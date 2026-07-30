package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// cluster-target: a tiny, silent monitoring agent for the Fleet Monitor system.
// - Exposes a local HTTP API (consumed by the Host over SSH port-forward / direct).
// - Pushes metrics to registered Host endpoints (hybrid model).
// - No Docker, no external deps; single static binary + one systemd unit.

const (
	apiVersion   = "/api/v1"
	listenAddr   = "0.0.0.0:59191"
	pushInterval = 1 * time.Second
)

var (
	serverID      string
	agentToken    string
	endpoints     []string
	endpointMu    sync.Mutex
	endpointsFile = defaultEndpointsFile()

	lastCPUTicks   = make(map[string]CPUTicks)
	lastCPUTicksMu sync.Mutex
)

// defaultEndpointsFile returns a user-writable path for the endpoints config.
func defaultEndpointsFile() string {
	return filepath.Join(configDir(), "endpoints")
}

type CPUTicks struct {
	Idle     float64
	Total    float64
	LastTime time.Time
	LastVal  float64
}

func main() {
	// --- Credentials: read from env (set by the systemd unit or the initial SSH run) ---
	serverID = os.Getenv("SERVER_ID")
	if serverID == "" {
		serverID = loadOrCreateServerID()
	}
	agentToken = os.Getenv("AGENT_TOKEN")

	// HOST_ENDPOINT can be supplied directly as an env var (e.g. on first run via SSH)
	// or loaded from the endpoints file written on previous runs.
	if ep := strings.TrimSpace(os.Getenv("HOST_ENDPOINT")); ep != "" {
		endpoints = []string{ep}
	} else {
		if envFile := os.Getenv("ENDPOINTS_FILE"); envFile != "" {
			endpointsFile = envFile
		}
		loadEndpoints()
	}

	// --- Self-install systemd service on first run (if not already running as one) ---
	go selfInstallService()

	log.Printf("[cluster-target] starting client agent (serverID=%s, endpoints=%d)", serverID, len(endpoints))
	go logMonitorLoop()
	go pushLoop()

	for _, ep := range endpoints {
		go startAgentWSLoop(ep)
	}

	select {}
}

func handleUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"uninstalling"}`))

	go func() {
		time.Sleep(500 * time.Millisecond)
		log.Println("[uninstall] Self-destruct teardown payload received. Cleaning up daemon...")
		cmd := exec.Command("sh", "-c", "sudo systemctl stop cluster-target.service 2>/dev/null; sudo systemctl disable cluster-target.service 2>/dev/null; sudo rm -f /etc/systemd/system/cluster-target.service; sudo systemctl daemon-reload 2>/dev/null; sudo rm -rf /etc/cluster-target; sudo pkill -9 -f cluster-target; sudo rm -f /usr/local/bin/cluster-target")
		_ = cmd.Run()
		os.Exit(0)
	}()
}

// ---- Stable Server ID ----

// loadOrCreateServerID reads the persisted server ID from disk, or generates and saves a new one.
func loadOrCreateServerID() string {
	cfgDir := configDir()
	idFile := filepath.Join(cfgDir, "server-id")
	if data, err := os.ReadFile(idFile); err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			return id
		}
	}
	id := uuid.New().String()
	if err := os.MkdirAll(cfgDir, 0755); err == nil {
		_ = os.WriteFile(idFile, []byte(id+"\n"), 0644)
	}
	return id
}

// configDir returns the writable config directory for this agent.
func configDir() string {
	// Only use system-wide /etc/cluster-target if running as root (UID "0" or user "root")
	currentUser, err := user.Current()
	if err == nil && (currentUser.Uid == "0" || currentUser.Username == "root") {
		if err := os.MkdirAll("/etc/cluster-target", 0755); err == nil {
			return "/etc/cluster-target"
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return filepath.Join(home, ".config", "cluster-target")
}

// selfInstallService installs and enables the systemd service for this agent
// automatically on the first run so it survives reboots without any manual steps.
// All credentials are embedded directly into the service unit's Environment= lines
// so NO external config files are required — the binary is the only installed artifact.
func selfInstallService() {
	// Already running as a systemd service — nothing to do.
	if os.Getenv("INVOCATION_ID") != "" {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	exe, _ = filepath.EvalSymlinks(exe)

	// Embed all three credentials in the unit so the service needs zero external files.
	hostEndpointLine := ""
	if ep := strings.TrimSpace(os.Getenv("HOST_ENDPOINT")); ep != "" {
		hostEndpointLine = fmt.Sprintf("Environment=HOST_ENDPOINT=%s", ep)
	} else if len(endpoints) > 0 {
		hostEndpointLine = fmt.Sprintf("Environment=HOST_ENDPOINT=%s", endpoints[0])
	}

	agentTokenLine := ""
	if agentToken != "" {
		agentTokenLine = fmt.Sprintf("Environment=AGENT_TOKEN=%s", agentToken)
	}

	serviceContent := fmt.Sprintf(`[Unit]
Description=Fleet Monitor Target Agent (cluster-target)
After=network.target

[Service]
Type=simple
Environment=SERVER_ID=%s
%s
%s
ExecStart=%s
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
`, serverID, agentTokenLine, hostEndpointLine, exe)

	// Try system-wide install (root) first
	systemUnit := "/etc/systemd/system/cluster-target.service"
	if os.Getuid() == 0 {
		if err := os.WriteFile(systemUnit, []byte(serviceContent), 0644); err == nil {
			exec.Command("systemctl", "daemon-reload").Run()
			exec.Command("systemctl", "enable", "--now", "cluster-target").Run()
			log.Printf("[cluster-target] auto-installed system service at %s", systemUnit)
			return
		}
	}

	// User-level install (non-root)
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		return
	}
	userUnit := filepath.Join(unitDir, "cluster-target.service")
	if err := os.WriteFile(userUnit, []byte(serviceContent), 0644); err != nil {
		log.Printf("[cluster-target] warning: could not write user service: %v", err)
		return
	}
	exec.Command("systemctl", "--user", "daemon-reload").Run()
	exec.Command("systemctl", "--user", "enable", "--now", "cluster-target").Run()
	log.Printf("[cluster-target] auto-installed user service at %s (id=%s)", userUnit, serverID)
}

// ---- Endpoint management ----

func loadEndpoints() {
	endpointMu.Lock()
	defer endpointMu.Unlock()
	endpoints = nil
	data, err := os.ReadFile(endpointsFile)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			endpoints = append(endpoints, line)
		}
	}
}

func saveEndpoints() error {
	endpointMu.Lock()
	defer endpointMu.Unlock()
	if len(endpoints) == 0 {
		_ = os.Remove(endpointsFile)
		return nil
	}
	dir := filepath.Dir(endpointsFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(endpointsFile, []byte(strings.Join(endpoints, "\n")+"\n"), 0644)
}

func selfDestruct() {
	log.Println("[cluster-target] No host endpoints remaining. Self-destructing target agent...")
	_ = os.Remove(endpointsFile)
	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(exe)
	}
	go func() {
		time.Sleep(500 * time.Millisecond)
		log.Println("[cluster-target] Self-destruction complete. Process terminating.")
		os.Exit(0)
	}()
}

func handleEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var p struct {
		Action string `json:"action"` // "add", "remove", "replace", "set"
		URL    string `json:"url"`
		OldURL string `json:"old_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.URL == "" {
		http.Error(w, "Invalid body (need action + url)", http.StatusBadRequest)
		return
	}
	endpointMu.Lock()
	switch p.Action {
	case "add":
		if !contains(endpoints, p.URL) {
			endpoints = append(endpoints, p.URL)
		}
	case "set":
		endpoints = []string{p.URL}
	case "replace":
		out := make([]string, 0, len(endpoints))
		for _, e := range endpoints {
			if e != p.OldURL && e != p.URL {
				out = append(out, e)
			}
		}
		out = append(out, p.URL)
		endpoints = out
	case "remove":
		out := make([]string, 0, len(endpoints))
		for _, e := range endpoints {
			if e != p.URL && !strings.Contains(e, p.URL) {
				out = append(out, e)
			}
		}
		endpoints = out
	default:
		endpointMu.Unlock()
		http.Error(w, "action must be add|remove|replace|set", http.StatusBadRequest)
		return
	}
	emptyEndpoints := len(endpoints) == 0
	endpointMu.Unlock()

	if err := saveEndpoints(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"endpoints":     endpoints,
		"self_destruct": emptyEndpoints,
	})

	if emptyEndpoints {
		selfDestruct()
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// ---- Push loop (Host-registered endpoints) ----

var agentPushClient = &http.Client{
	Timeout: 3 * time.Second,
}

func pushLoop() {
	ticker := time.NewTicker(pushInterval)
	for range ticker.C {
		m := collectMetrics()
		payload, _ := json.Marshal(m)
		endpointMu.Lock()
		eps := append([]string{}, endpoints...)
		endpointMu.Unlock()
		for _, base := range eps {
			url := strings.TrimRight(base, "/") + "/api/ingest/" + serverID + "/metrics"
			go func(u string) {
				req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(string(payload)))
				if err != nil {
					return
				}
				req.Header.Set("Content-Type", "application/json")
				resp, err := agentPushClient.Do(req)
				if err != nil {
					log.Printf("[cluster-target] push to %s failed: %v", u, err)
					return
				}
				resp.Body.Close()
			}(url)
		}
	}
}

// logMonitorLoop periodically scans system logs (journalctl) and Docker container logs for API failures & 5xx errors.
func logMonitorLoop() {
	ticker := time.NewTicker(10 * time.Second)
	var seenLogsMu sync.Mutex
	seenLogs := make(map[string]bool)

	isAPIFailureLine := func(line string) bool {
		l := strings.ToLower(line)
		return strings.Contains(l, " 500 ") || strings.Contains(l, " 502 ") || strings.Contains(l, " 503 ") || strings.Contains(l, " 504 ") ||
			strings.Contains(l, "http/1.1 5") || strings.Contains(l, "http/2 5") || strings.Contains(l, "\"status\":5") ||
			strings.Contains(l, "api error") || strings.Contains(l, "connection refused") || strings.Contains(l, "internal server error") ||
			strings.Contains(l, "bad gateway") || strings.Contains(l, "gateway timeout")
	}

	for range ticker.C {
		// 1. Scan System Logs (journalctl)
		out, err := exec.Command("bash", "-c", "journalctl -n 30 --since '12 seconds ago' --no-pager 2>/dev/null").CombinedOutput()
		if err == nil && len(out) > 0 {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if isAPIFailureLine(line) {
					seenLogsMu.Lock()
					alreadySeen := seenLogs[line]
					if !alreadySeen {
						seenLogs[line] = true
						if len(seenLogs) > 1000 {
							seenLogs = make(map[string]bool)
						}
					}
					seenLogsMu.Unlock()

					if !alreadySeen {
						logAPIFailure("systemlogs/journalctl", "systemd", 500, line)
					}
				}
			}
		}

		// 2. Scan Running Docker Containers Logs
		cOut, err := exec.Command("docker", "ps", "--format", "{{.ID}} {{.Names}}").CombinedOutput()
		if err == nil && len(cOut) > 0 {
			cLines := strings.Split(strings.TrimSpace(string(cOut)), "\n")
			for _, cLine := range cLines {
				parts := strings.Fields(cLine)
				if len(parts) < 2 {
					continue
				}
				cID, cName := parts[0], parts[1]

				lOut, lErr := exec.Command("docker", "logs", "--since", "12s", cID).CombinedOutput()
				if lErr == nil && len(lOut) > 0 {
					logLines := strings.Split(string(lOut), "\n")
					for _, lLine := range logLines {
						lLine = strings.TrimSpace(lLine)
						if lLine == "" {
							continue
						}
						if isAPIFailureLine(lLine) {
							seenLogsMu.Lock()
							alreadySeen := seenLogs[lLine]
							if !alreadySeen {
								seenLogs[lLine] = true
								if len(seenLogs) > 1000 {
									seenLogs = make(map[string]bool)
								}
							}
							seenLogsMu.Unlock()

							if !alreadySeen {
								logAPIFailure("container/"+cName, "docker_logs", 500, lLine)
							}
						}
					}
				}
			}
		}
	}
}

// ---- Local API handlers ----

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	m := collectMetrics()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m)
}

func handleProcesses(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("bash", "-c",
		"ps -eo pid,user,pcpu,pmem,comm:50,args --sort=-pcpu 2>/dev/null | head -n 25").CombinedOutput()
	if err != nil && len(out) == 0 {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(parsePS(string(out)))
}

type FailureLog struct {
	Timestamp  string `json:"timestamp"`
	Endpoint   string `json:"endpoint"`
	Action     string `json:"action,omitempty"`
	StatusCode int    `json:"status_code"`
	Error      string `json:"error"`
	ServerID   string `json:"server_id,omitempty"`
}

var (
	failureLogsMu sync.RWMutex
	failureLogs   []FailureLog
)

func logAPIFailure(endpoint, action string, statusCode int, errStr string) {
	entry := FailureLog{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Endpoint:   endpoint,
		Action:     action,
		StatusCode: statusCode,
		Error:      errStr,
		ServerID:   serverID,
	}
	failureLogsMu.Lock()
	failureLogs = append(failureLogs, entry)
	if len(failureLogs) > 200 {
		failureLogs = failureLogs[1:]
	}
	failureLogsMu.Unlock()

	log.Printf("[API-FAILURE] %s %s (status %d): %s", endpoint, action, statusCode, errStr)

	file := filepath.Join(configDir(), "api_failures.log")
	line := fmt.Sprintf("[%s] %s %s (status %d): %s\n", entry.Timestamp, endpoint, action, statusCode, errStr)
	f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err == nil {
		f.WriteString(line)
		f.Close()
	}

	go pushFailureLogToHost(entry)
}

func pushFailureLogToHost(entry FailureLog) {
	endpointMu.Lock()
	eps := append([]string{}, endpoints...)
	endpointMu.Unlock()

	payload, _ := json.Marshal(entry)
	for _, base := range eps {
		u := strings.TrimRight(base, "/") + "/api/ingest/" + serverID + "/logs"
		req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(string(payload)))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := agentPushClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var entry FailureLog
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		logAPIFailure(entry.Endpoint, entry.Action, entry.StatusCode, entry.Error)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}

	failureLogsMu.RLock()
	logsCopy := append([]FailureLog{}, failureLogs...)
	failureLogsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"count":    len(logsCopy),
		"failures": logsCopy,
	})
}

func handleSystemLogs(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("bash", "-c", "journalctl -n 100 --no-pager 2>/dev/null").CombinedOutput()
	if err != nil && len(out) == 0 {
		logAPIFailure("/systemlogs", "journalctl", http.StatusInternalServerError, err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(out)
}

func handleNetworks(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("bash", "-c",
		"ip -br link 2>/dev/null; echo '---ADDR---'; ip -br addr 2>/dev/null; echo '---PROC---'; cat /proc/net/dev 2>/dev/null").CombinedOutput()
	if err != nil && len(out) == 0 {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(parseNetworks(string(out)))
}

func handleContainers(w http.ResponseWriter, r *http.Request) {
	// Docker version & instance info
	verOut, _ := exec.Command("docker", "version", "--format", "Docker Engine v{{.Server.Version}} (API v{{.Server.APIVersion}})").Output()
	dockerVer := strings.TrimSpace(string(verOut))
	if dockerVer == "" {
		dockerVer = "Docker Engine (Not Available)"
	}

	infoOut, _ := exec.Command("docker", "info", "--format", "{{.Name}} | {{.OperatingSystem}} ({{.KernelVersion}}) | Driver: {{.Driver}}").Output()
	dockerInfo := strings.TrimSpace(string(infoOut))

	// Running + stopped containers (docker ps -a)
	psOut, _ := exec.Command("bash", "-c",
		`docker ps -a --format '{"id":"{{.ID}}","name":"{{.Names}}","image":"{{.Image}}","status":"{{.Status}}","state":"{{.State}}","created":"{{.CreatedAt}}","ports":"{{.Ports}}","size":"{{.Size}}"}' 2>/dev/null`).Output()
	var containers []map[string]interface{}
	for _, line := range strings.Split(strings.TrimSpace(string(psOut)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var c map[string]interface{}
		if json.Unmarshal([]byte(line), &c) == nil {
			containers = append(containers, c)
		}
	}

	// All local images (docker images)
	imgOut, _ := exec.Command("bash", "-c",
		`docker images --format '{"repo":"{{.Repository}}","tag":"{{.Tag}}","id":"{{.ID}}","created":"{{.CreatedAt}}","size":"{{.Size}}"}' 2>/dev/null`).Output()
	var images []map[string]interface{}
	for _, line := range strings.Split(strings.TrimSpace(string(imgOut)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var img map[string]interface{}
		if json.Unmarshal([]byte(line), &img) == nil {
			images = append(images, img)
		}
	}

	if containers == nil {
		containers = []map[string]interface{}{}
	}
	if images == nil {
		images = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"docker_version": dockerVer,
		"docker_info":    dockerInfo,
		"containers":     containers,
		"images":         images,
	})
}

func handleStorage(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("bash", "-c", "df -T -B1 2>/dev/null").CombinedOutput()
	if err != nil && len(out) == 0 {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(parseDFOutput(string(out)))
}
func handleDockerInfo(w http.ResponseWriter, r *http.Request) {
	verOut, _ := exec.Command("docker", "version", "--format", "{{json .}}").Output()
	var ver interface{}
	_ = json.Unmarshal(verOut, &ver)

	imgOut, _ := exec.Command("docker", "images", "--format", "{{json .}}").Output()
	images := []map[string]interface{}{}
	for _, line := range strings.Split(strings.TrimSpace(string(imgOut)), "\n") {
		var img map[string]interface{}
		if json.Unmarshal([]byte(line), &img) == nil {
			images = append(images, img)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"available": true,
		"version":   ver,
		"images":    images,
	})
}

func handleNetworkConnections(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("bash", "-c", "echo '---TCP---'; cat /proc/net/tcp /proc/net/tcp6 2>/dev/null; echo '---UDP---'; cat /proc/net/udp /proc/net/udp6 2>/dev/null").CombinedOutput()
	if err != nil && len(out) == 0 {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(out)
}


func parseDFOutput(out string) []map[string]interface{} {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var result []map[string]interface{}
	seenDevices := make(map[string]int)

	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		fsSource := fields[0]
		fsType := fields[1]
		if !strings.HasPrefix(fsSource, "/dev/") {
			continue
		}
		mount := fields[6]

		if existingIdx, ok := seenDevices[fsSource]; ok {
			if mount == "/" {
				result[existingIdx]["mountpoint"] = "/"
			}
			continue
		}

		sizeB, _ := strconv.ParseFloat(fields[2], 64)
		usedB, _ := strconv.ParseFloat(fields[3], 64)
		availB, _ := strconv.ParseFloat(fields[4], 64)
		pctStr := strings.TrimSuffix(fields[5], "%")
		pct, _ := strconv.Atoi(pctStr)

		sizeGB := fmt.Sprintf("%.1f GB", sizeB/(1024*1024*1024))
		usedGB := fmt.Sprintf("%.1f GB", usedB/(1024*1024*1024))
		availGB := fmt.Sprintf("%.1f GB", availB/(1024*1024*1024))
		if sizeB < 1024*1024*1024 {
			sizeGB = fmt.Sprintf("%.0f MB", sizeB/(1024*1024))
			usedGB = fmt.Sprintf("%.0f MB", usedB/(1024*1024))
			availGB = fmt.Sprintf("%.0f MB", availB/(1024*1024))
		}

		entry := map[string]interface{}{
			"name":       fsSource,
			"fstype":     fsType,
			"mountpoint": mount,
			"size":       sizeGB,
			"used":       usedGB,
			"available":  availGB,
			"pct":        pct,
			"used_pct":   pct,
			"size_bytes": sizeB,
			"used_bytes": usedB,
		}
		seenDevices[fsSource] = len(result)
		result = append(result, entry)
	}
	return result
}

// handleContainerAction handles start/stop/pause/unpause/restart/rebuild/logs for a container
func handleContainerAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Action string `json:"action"` // start | stop | pause | unpause | restart | remove | logs | compose-up | compose-down | compose-rebuild | compose-logs
		Target string `json:"target"` // container name or ID
		Image  string `json:"image"`  // for pull
		Dir    string `json:"dir"`    // directory containing docker-compose.yml
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch req.Action {
	case "start":
		out, err := exec.Command("docker", "start", req.Target).CombinedOutput()
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": err == nil, "output": string(out)})
	case "stop":
		out, err := exec.Command("docker", "stop", req.Target).CombinedOutput()
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": err == nil, "output": string(out)})
	case "pause":
		out, err := exec.Command("docker", "pause", req.Target).CombinedOutput()
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": err == nil, "output": string(out)})
	case "unpause":
		out, err := exec.Command("docker", "unpause", req.Target).CombinedOutput()
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": err == nil, "output": string(out)})
	case "restart":
		out, err := exec.Command("docker", "restart", req.Target).CombinedOutput()
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": err == nil, "output": string(out)})
	case "remove":
		out, err := exec.Command("docker", "rm", "-f", req.Target).CombinedOutput()
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": err == nil, "output": string(out)})
	case "logs":
		out, _ := exec.Command("docker", "logs", "--tail", "300", "--timestamps", req.Target).CombinedOutput()
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "output": string(out)})
	case "pull":
		out, err := exec.Command("docker", "pull", req.Image).CombinedOutput()
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": err == nil, "output": string(out)})
	case "compose-up":
		composeFile := composeFilePath(req.Dir)
		out, err := exec.Command("docker", "compose", "-f", composeFile, "up", "-d").CombinedOutput()
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": err == nil, "output": string(out)})
	case "compose-down":
		composeFile := composeFilePath(req.Dir)
		out, err := exec.Command("docker", "compose", "-f", composeFile, "down").CombinedOutput()
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": err == nil, "output": string(out)})
	case "compose-rebuild":
		composeFile := composeFilePath(req.Dir)
		out, err := exec.Command("docker", "compose", "-f", composeFile, "up", "-d", "--build").CombinedOutput()
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": err == nil, "output": string(out)})
	case "compose-logs":
		composeFile := composeFilePath(req.Dir)
		var args []string
		if req.Target != "" {
			args = []string{"compose", "-f", composeFile, "logs", "--tail", "200", "--timestamps", req.Target}
		} else {
			args = []string{"compose", "-f", composeFile, "logs", "--tail", "200", "--timestamps"}
		}
		out, _ := exec.Command("docker", args...).CombinedOutput()
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "output": string(out)})
	default:
		http.Error(w, "Unknown action: "+req.Action, http.StatusBadRequest)
	}
}

// composeFilePath returns the docker-compose.yml path for a given directory.
// If dir is empty it tries the user's home directory.
func composeFilePath(dir string) string {
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = home
	}
	for _, name := range []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} {
		p := dir + "/" + name
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return dir + "/docker-compose.yml"
}


// ---- Collectors ----

func collectMetrics() map[string]interface{} {
	out, err := exec.Command("bash", "-c", strings.Join([]string{
		"cat /proc/loadavg;",
		"grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree):' /proc/meminfo;",
		"echo -n 'UPTIME '; cat /proc/uptime;",
		"df -B1 / 2>/dev/null | tail -1;",
		"grep -E '^cpu[0-9]*' /proc/stat;",
	}, "\n")).CombinedOutput()
	if err != nil {
		return map[string]interface{}{"cpu": 0.0, "error": err.Error()}
	}
	return parseMetrics(string(out))
}

func parseMetrics(out string) map[string]interface{} {
	res := map[string]interface{}{
		"cpu": 0.0, "ram_used_pct": 0.0, "ram_used_gb": 0.0, "ram_total_gb": 0.0,
		"swap_used_pct": 0.0, "swap_used_gb": 0.0, "swap_total_gb": 0.0,
		"disk_used_pct": 0.0, "disk_used_gb": 0.0, "disk_total_gb": 0.0,
		"cores": []float64{},
	}
	sections := strings.Split(out, "\n")
	var memInfo = map[string]float64{}
	var cpuLines []string
	
	for _, line := range sections {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "UPTIME") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				if v, e := parseFloat(f[1]); e == nil {
					res["uptime_seconds"] = v
				}
			}
			continue
		}
		if strings.HasPrefix(upper, "MEM") || strings.HasPrefix(upper, "SWAP") || strings.HasPrefix(upper, "BUFFERS") || strings.HasPrefix(upper, "CACHED") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				if v, e := parseFloat(f[1]); e == nil {
					memInfo[strings.ToUpper(f[0])] = v
				}
			}
			continue
		}
		if strings.HasPrefix(line, "cpu") {
			cpuLines = append(cpuLines, line)
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 5 && f[len(f)-1] == "/" {
			if t, e := parseFloat(f[len(f)-5]); e == nil {
				if u, e2 := parseFloat(f[len(f)-4]); e2 == nil {
					res["disk_total_gb"] = t / 1024 / 1024 / 1024
					res["disk_used_gb"] = u / 1024 / 1024 / 1024
					if t > 0 {
						res["disk_used_pct"] = (u / t) * 100.0
					}
				}
			}
			continue
		}
	}

	memTotal := memInfo["MEMTOTAL:"]
	swapTotal := memInfo["SWAPTOTAL:"]
	var diskTotal float64
	if t, ok := res["disk_total_gb"].(float64); ok && t > 0 {
		diskTotal = t * 1024 * 1024 * 1024
	}

	// RAM
	memAvail := memInfo["MEMAVAILABLE:"]
	if memAvail == 0 {
		memAvail = memInfo["MEMFREE:"] + memInfo["BUFFERS:"] + memInfo["CACHED:"]
	}
	if memTotal > 0 {
		res["ram_total_gb"] = memTotal / 1024 / 1024
		used := memTotal - memAvail
		if used < 0 {
			used = 0
		}
		res["ram_used_gb"] = used / 1024 / 1024
		res["ram_used_pct"] = (used / memTotal) * 100.0
	}
	// Swap
	swapFree := memInfo["SWAPFREE:"]
	if swapTotal > 0 {
		res["swap_total_gb"] = swapTotal / 1024 / 1024
		used := swapTotal - swapFree
		if used < 0 {
			used = 0
		}
		res["swap_used_gb"] = used / 1024 / 1024
		res["swap_used_pct"] = (used / swapTotal) * 100.0
	}
	// Disk
	if diskTotal > 0 {
		res["disk_total_gb"] = diskTotal / 1024 / 1024 / 1024
		if uVal, ok := res["disk_used_gb"].(float64); ok {
			uBytes := uVal * 1024 * 1024 * 1024
			res["disk_used_pct"] = (uBytes / diskTotal) * 100.0
		}
	}

	// CPU
	if len(cpuLines) > 0 {
		numCores := 0
		for {
			coreName := fmt.Sprintf("cpu%d", numCores)
			found := false
			for _, cl := range cpuLines {
				if strings.HasPrefix(cl, coreName+" ") {
					found = true
					break
				}
			}
			if !found {
				break
			}
			numCores++
		}
		coreValues := make(map[string]float64)
		lastCPUTicksMu.Lock()
		for _, cl := range cpuLines {
			f := strings.Fields(cl)
			if len(f) < 5 {
				continue
			}
			name := f[0]
			var vals []float64
			for _, x := range f[1:] {
				if v, e := parseFloat(x); e == nil {
					vals = append(vals, v)
				}
			}
			if len(vals) < 4 {
				continue
			}
			idle := vals[3]
			total := 0.0
			for _, v := range vals {
				total += v
			}

			prev, exists := lastCPUTicks[name]
			percent := 0.0
			now := time.Now()
			if exists {
				if now.Sub(prev.LastTime) < 600*time.Millisecond && prev.LastVal >= 0 {
					percent = prev.LastVal
				} else {
					deltaIdle := idle - prev.Idle
					deltaTotal := total - prev.Total
					if deltaTotal > 0 {
						percent = (1.0 - deltaIdle/deltaTotal) * 100.0
					} else {
						percent = prev.LastVal
					}
					lastCPUTicks[name] = CPUTicks{Idle: idle, Total: total, LastTime: now, LastVal: percent}
				}
			} else {
				if total > 0 {
					percent = (1.0 - idle/total) * 100.0
				}
				lastCPUTicks[name] = CPUTicks{Idle: idle, Total: total, LastTime: now, LastVal: percent}
			}

			if percent < 0 {
				percent = 0
			}
			if percent > 100 {
				percent = 100
			}
			coreValues[name] = round1(percent)
		}
		lastCPUTicksMu.Unlock()

		res["cpu"] = coreValues["cpu"]
		var coresList []float64
		for i := 0; i < numCores; i++ {
			coreName := fmt.Sprintf("cpu%d", i)
			coresList = append(coresList, coreValues[coreName])
		}
		res["cores"] = coresList
	}
	res["active_tcp_connections"] = countConnections("/proc/net/tcp", "/proc/net/tcp6")
	res["active_udp_connections"] = countConnections("/proc/net/udp", "/proc/net/udp6")
	rxRate, txRate := getNetRates()
	res["net_rx_kb"] = round1(rxRate)
	res["net_tx_kb"] = round1(txRate)
	return res
}

func parsePS(out string) []map[string]interface{} {
	var procs []map[string]interface{}
	for i, line := range strings.Split(out, "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		pid := fields[0]
		user := fields[1]
		cpu := fields[2]
		mem := fields[3]

		// Find the start of the 5th field (comm) in the raw line
		idx := 0
		for f := 0; f < 4; f++ {
			// Skip spaces
			for idx < len(line) && (line[idx] == ' ' || line[idx] == '\t') {
				idx++
			}
			// Skip word
			for idx < len(line) && line[idx] != ' ' && line[idx] != '\t' {
				idx++
			}
		}
		// Skip spaces after 4th field
		for idx < len(line) && (line[idx] == ' ' || line[idx] == '\t') {
			idx++
		}

		if idx >= len(line) {
			continue
		}

		var commRaw, argsRaw string
		if idx+50 <= len(line) {
			commRaw = line[idx : idx+50]
			argsRaw = line[idx+50:]
		} else {
			commRaw = line[idx:]
			argsRaw = ""
		}

		name := strings.TrimSpace(commRaw)
		if name == "ps" || strings.Contains(name, "ssh") {
			continue
		}

		cmdline := strings.TrimSpace(argsRaw)
		if cmdline == "" {
			cmdline = name
		}

		procs = append(procs, map[string]interface{}{
			"pid": pid, "user": user, "cpu": cpu, "mem": mem, "name": name, "cmdline": cmdline,
		})
		if len(procs) >= 20 {
			break
		}
	}
	return procs
}

func formatBytes(bytesStr string) string {
	var b float64
	_, err := fmt.Sscanf(bytesStr, "%f", &b)
	if err != nil || b == 0 {
		return "0 B"
	}
	if b >= 1024*1024*1024 {
		return fmt.Sprintf("%.2f GB", b/(1024*1024*1024))
	}
	if b >= 1024*1024 {
		return fmt.Sprintf("%.1f MB", b/(1024*1024))
	}
	if b >= 1024 {
		return fmt.Sprintf("%.1f KB", b/1024)
	}
	return fmt.Sprintf("%.0f B", b)
}

func parseNetworks(out string) []map[string]interface{} {
	parts := strings.Split(out, "---PROC---")
	linkAddrParts := strings.Split(parts[0], "---ADDR---")

	linkLines := []string{}
	addrLines := []string{}
	procLines := []string{}

	if len(linkAddrParts) > 0 {
		linkLines = strings.Split(linkAddrParts[0], "\n")
	}
	if len(linkAddrParts) > 1 {
		addrLines = strings.Split(linkAddrParts[1], "\n")
	} else {
		addrLines = linkLines
	}
	if len(parts) > 1 {
		procLines = strings.Split(parts[1], "\n")
	}

	macMap := map[string]string{}
	for _, line := range linkLines {
		f := strings.Fields(line)
		if len(f) >= 3 {
			name := strings.TrimSuffix(f[0], ":")
			mac := f[2]
			if strings.Contains(mac, ":") {
				macMap[name] = mac
			}
		}
	}

	ipMap := map[string]string{}
	for _, line := range addrLines {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		name := strings.TrimSuffix(f[0], ":")
		ip := "N/A"
		for _, x := range f[2:] {
			if strings.Contains(x, ".") && !strings.HasPrefix(x, "127.") {
				ip = strings.Split(x, "/")[0]
				break
			}
			if strings.Contains(x, ":") && x != "::1" && !strings.HasPrefix(x, "fe80") {
				ip = strings.Split(x, "/")[0]
				break
			}
		}
		ipMap[name] = ip
	}

	var result []map[string]interface{}
	for i, line := range procLines {
		if i < 2 {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 11 {
			continue
		}
		name := strings.TrimSuffix(f[0], ":")
		if name == "lo" || strings.HasPrefix(name, "lo") {
			continue
		}
		ip := "N/A"
		if v, ok := ipMap[name]; ok {
			ip = v
		}
		mac := "N/A"
		if v, ok := macMap[name]; ok {
			mac = v
		}

		result = append(result, map[string]interface{}{
			"name":    name,
			"ip":      ip,
			"mac":     mac,
			"rxSpeed": "Active",
			"txSpeed": "Active",
			"rxTotal": formatBytes(f[1]),
			"txTotal": formatBytes(f[9]),
		})
	}
	return result
}

func countConnections(files ...string) int {
	total := 0
	for _, file := range files {
		out, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		lines := strings.Split(string(out), "\n")
		for i, line := range lines {
			if i == 0 || strings.TrimSpace(line) == "" {
				continue
			}
			total++
		}
	}
	return total
}

func parseFloat(s string) (float64, error) {
	var v float64
	_, err := fmt.Sscanf(s, "%f", &v)
	return v, err
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10.0
}

// authOptional: the local API is bound to localhost/loopback in practice; for the
// hybrid SSH model the Host reaches it via an SSH port-forward, so we keep it open
// on the loopback interface. This stub allows future token auth without changing signatures.
func authOptional(h http.HandlerFunc) http.HandlerFunc {
	return h
}

var (
	netRateMu  sync.Mutex
	lastRx     float64
	lastTx     float64
	lastTime   time.Time
	currRxRate float64
	currTxRate float64
)

func readNetDev() (float64, float64) {
	out, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	var totalRx, totalTx float64
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		if strings.TrimSpace(parts[0]) == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) >= 9 {
			rx, _ := strconv.ParseFloat(fields[0], 64)
			tx, _ := strconv.ParseFloat(fields[8], 64)
			totalRx += rx
			totalTx += tx
		}
	}
	return totalRx, totalTx
}

func getNetRates() (float64, float64) {
	netRateMu.Lock()
	defer netRateMu.Unlock()

	now := time.Now()
	rx, tx := readNetDev()

	if !lastTime.IsZero() {
		dur := now.Sub(lastTime).Seconds()
		if dur > 0.1 {
			currRxRate = (rx - lastRx) / dur / 1024.0
			currTxRate = (tx - lastTx) / dur / 1024.0
			if currRxRate < 0 {
				currRxRate = 0
			}
			if currTxRate < 0 {
				currTxRate = 0
			}
		}
	}
	lastRx = rx
	lastTx = tx
	lastTime = now

	return currRxRate, currTxRate
}

// ---- WebSocket Communication Logic ----

type WSMessage struct {
	Type      string          `json:"type"`       // "metrics", "command_request", "command_response", "heartbeat"
	RequestID string          `json:"request_id"`
	ServerID  string          `json:"server_id"`
	Payload   json.RawMessage `json:"payload"`
}

type WSRequestPayload struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   []byte `json:"body"`
}

type WSResponsePayload struct {
	StatusCode int    `json:"status_code"`
	Body       []byte `json:"body"`
}

type mockResponseWriter struct {
	header     http.Header
	body       bytes.Buffer
	statusCode int
}

func newMockResponseWriter() *mockResponseWriter {
	return &mockResponseWriter{
		header:     make(http.Header),
		statusCode: http.StatusOK,
	}
}

func (w *mockResponseWriter) Header() http.Header {
	return w.header
}

func (w *mockResponseWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}

func (w *mockResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

func startAgentWSLoop(ep string) {
	wsURL := ep
	if strings.HasPrefix(wsURL, "http://") {
		wsURL = "ws://" + strings.TrimPrefix(wsURL, "http://")
	} else if strings.HasPrefix(wsURL, "https://") {
		wsURL = "wss://" + strings.TrimPrefix(wsURL, "https://")
	}
	wsURL = strings.TrimRight(wsURL, "/") + "/api/ws?server_id=" + url.QueryEscape(serverID) + "&token=" + url.QueryEscape(agentToken)

	backoff := 1 * time.Second
	for {
		log.Printf("[ws-client] Connecting to Host WebSocket: %s", ep)
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			log.Printf("[ws-client] Connection failed: %v. Retrying in %v...", err, backoff)
			time.Sleep(backoff)
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			continue
		}
		backoff = 1 * time.Second
		log.Printf("[ws-client] Successfully connected to Host: %s", ep)

		stopPush := make(chan struct{})
		go runMetricsPushLoop(conn, stopPush)

		err = runCommandReadLoop(conn)
		close(stopPush)
		conn.Close()
		log.Printf("[ws-client] Connection closed: %v. Reconnecting in 2s...", err)
		time.Sleep(2 * time.Second)
	}
}

func runMetricsPushLoop(conn *websocket.Conn, stop chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m := collectMetrics()
			rawPayload, err := json.Marshal(m)
			if err != nil {
				continue
			}
			msg := WSMessage{
				Type:      "metrics",
				ServerID:  serverID,
				Payload:   rawPayload,
			}
			rawMsg, _ := json.Marshal(msg)
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, rawMsg); err != nil {
				return
			}
		case <-stop:
			return
		}
	}
}

func runCommandReadLoop(conn *websocket.Conn) error {
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return err
		}

		var msg WSMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}

		if msg.Type == "command_request" {
			go processHostCommand(conn, msg)
		}
	}
}

func processHostCommand(conn *websocket.Conn, msg WSMessage) {
	var req WSRequestPayload
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		return
	}

	var handler http.HandlerFunc
	switch req.Path {
	case "processes":
		handler = handleProcesses
	case "containers":
		handler = handleContainers
	case "systemlogs":
		handler = handleSystemLogs
	case "storage":
		handler = handleStorage
	case "networks":
		handler = handleNetworks
	case "metrics":
		handler = handleMetrics
	case "uninstall":
		handler = handleUninstall
	case "container-action":
		handler = handleContainerAction
	case "endpoint":
		handler = handleEndpoint
	case "docker-info":
		handler = handleDockerInfo
	case "network-connections":
		handler = handleNetworkConnections
	case "exec-command":
		handler = handleExecCommand
	default:
		respondWithStatus(conn, msg.RequestID, http.StatusNotFound, []byte("Endpoint not found"))
		return
	}

	httpReq, err := http.NewRequest(req.Method, "/api/v1/"+req.Path, bytes.NewReader(req.Body))
	if err != nil {
		respondWithStatus(conn, msg.RequestID, http.StatusInternalServerError, []byte(err.Error()))
		return
	}
	if req.Method == "POST" {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	w := newMockResponseWriter()
	handler(w, httpReq)

	resPayload := WSResponsePayload{
		StatusCode: w.statusCode,
		Body:       w.body.Bytes(),
	}
	rawPayload, _ := json.Marshal(resPayload)

	resMsg := WSMessage{
		Type:      "command_response",
		RequestID: msg.RequestID,
		ServerID:  serverID,
		Payload:   rawPayload,
	}
	rawMsg, _ := json.Marshal(resMsg)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = conn.WriteMessage(websocket.TextMessage, rawMsg)
}

func respondWithStatus(conn *websocket.Conn, reqID string, status int, body []byte) {
	resPayload := WSResponsePayload{
		StatusCode: status,
		Body:       body,
	}
	rawPayload, _ := json.Marshal(resPayload)
	resMsg := WSMessage{
		Type:      "command_response",
		RequestID: reqID,
		ServerID:  serverID,
		Payload:   rawPayload,
	}
	rawMsg, _ := json.Marshal(resMsg)
	_ = conn.WriteMessage(websocket.TextMessage, rawMsg)
}

func handleExecCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Command string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	// Limit command execution to 7 seconds so it doesn't block the WebSocket connection indefinitely
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "powershell.exe", "-Command", req.Command)
	} else {
		cmd = exec.CommandContext(ctx, "bash", "-c", req.Command)
	}

	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":     false,
			"output": string(out) + "\nCommand execution timed out (exceeded 7 second limit)",
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":     err == nil,
		"output": string(out),
	})
}

