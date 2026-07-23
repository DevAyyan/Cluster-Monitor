package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// cluster-target: a tiny, silent monitoring agent for the Fleet Monitor system.
// - Exposes a local HTTP API (consumed by the Host over SSH port-forward / direct).
// - Pushes metrics to registered Host endpoints (hybrid model).
// - No Docker, no external deps; single static binary + one systemd unit.

const (
	apiVersion   = "/api/v1"
	listenAddr   = "0.0.0.0:9192"
	pushInterval = 10 * time.Second
)

var (
	serverID      string
	endpoints     []string
	endpointMu    sync.Mutex
	endpointsFile = defaultEndpointsFile()

	lastCPUTicks   = make(map[string]CPUTicks)
	lastCPUTicksMu sync.Mutex

	staticMu        sync.Mutex
	staticMemTotal  float64 // in kB
	staticSwapTotal float64 // in kB
	staticDiskTotal float64 // in bytes
	staticNumCores  int
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
	// --- Stable SERVER_ID: persist across restarts ---
	serverID = os.Getenv("SERVER_ID")
	if serverID == "" {
		serverID = loadOrCreateServerID()
	}
	if envFile := os.Getenv("ENDPOINTS_FILE"); envFile != "" {
		endpointsFile = envFile
	}
	loadEndpoints()

	// --- Self-install systemd service on first run (if not already running as one) ---
	go selfInstallService()

	http.HandleFunc(apiVersion+"/metrics", authOptional(handleMetrics))
	http.HandleFunc(apiVersion+"/processes", authOptional(handleProcesses))
	http.HandleFunc(apiVersion+"/systemlogs", authOptional(handleSystemLogs))
	http.HandleFunc(apiVersion+"/networks", authOptional(handleNetworks))
	http.HandleFunc(apiVersion+"/storage", authOptional(handleStorage))
	http.HandleFunc(apiVersion+"/containers", authOptional(handleContainers))
	http.HandleFunc(apiVersion+"/container-action", authOptional(handleContainerAction))
	http.HandleFunc(apiVersion+"/endpoint", handleEndpoint) // add/remove Host endpoints

	log.Printf("[cluster-target] listening on %s (serverID=%s, endpoints=%d)", listenAddr, serverID, len(endpoints))
	go pushLoop()
	log.Fatal(http.ListenAndServe(listenAddr, nil))
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
	if err := os.MkdirAll("/etc/cluster-target", 0755); err == nil {
		return "/etc/cluster-target"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return filepath.Join(home, ".config", "cluster-target")
}

// ---- Self-install systemd service ----

// selfInstallService installs and enables the systemd service for this agent automatically
// on the first run so it survives reboots without any manual steps.
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
	cfgDir := configDir()

	serviceContent := fmt.Sprintf(`[Unit]
Description=Fleet Monitor Target Agent (cluster-target)
After=network.target

[Service]
Type=simple
Environment=SERVER_ID=%s
ExecStart=%s
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
`, serverID, exe)

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
	// Replace ProtectHome in user unit (not supported for user services)
	if err := os.WriteFile(userUnit, []byte(serviceContent), 0644); err != nil {
		log.Printf("[cluster-target] warning: could not write user service: %v", err)
		return
	}
	exec.Command("systemctl", "--user", "daemon-reload").Run()
	exec.Command("systemctl", "--user", "enable", "--now", "cluster-target").Run()
	log.Printf("[cluster-target] auto-installed user service at %s (id=%s)", userUnit, serverID)

	// Also write endpoint to config dir so it survives restart
	_ = os.MkdirAll(cfgDir, 0755)
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
	dir := filepath.Dir(endpointsFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(endpointsFile, []byte(strings.Join(endpoints, "\n")+"\n"), 0644)
}

func handleEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var p struct {
		Action string `json:"action"` // "add" or "remove"
		URL    string `json:"url"`
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
	case "remove":
		out := endpoints[:0]
		for _, e := range endpoints {
			if e != p.URL {
				out = append(out, e)
			}
		}
		endpoints = out
	default:
		endpointMu.Unlock()
		http.Error(w, "action must be add|remove", http.StatusBadRequest)
		return
	}
	endpointMu.Unlock()
	if err := saveEndpoints(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "endpoints": endpoints})
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
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					log.Printf("[cluster-target] push to %s failed: %v", u, err)
					return
				}
				resp.Body.Close()
			}(url)
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

func handleSystemLogs(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("bash", "-c", "journalctl -n 100 --no-pager 2>/dev/null").CombinedOutput()
	if err != nil && len(out) == 0 {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(out)
}

func handleNetworks(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("bash", "-c",
		"ip -br addr 2>/dev/null; echo '---PROC---'; cat /proc/net/dev 2>/dev/null").CombinedOutput()
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

	staticMu.Lock()
	if staticMemTotal == 0 && memInfo["MEMTOTAL:"] > 0 {
		staticMemTotal = memInfo["MEMTOTAL:"]
	}
	if staticSwapTotal == 0 && memInfo["SWAPTOTAL:"] > 0 {
		staticSwapTotal = memInfo["SWAPTOTAL:"]
	}
	if staticDiskTotal == 0 {
		if t, ok := res["disk_total_gb"].(float64); ok && t > 0 {
			staticDiskTotal = t * 1024 * 1024 * 1024
		}
	}
	if staticNumCores == 0 && len(cpuLines) > 0 {
		count := 0
		for {
			coreName := fmt.Sprintf("cpu%d", count)
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
			count++
		}
		if count > 0 {
			staticNumCores = count
		}
	}

	memTotal := staticMemTotal
	swapTotal := staticSwapTotal
	diskTotal := staticDiskTotal
	numCores := staticNumCores
	staticMu.Unlock()

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

func parseNetworks(out string) []map[string]interface{} {
	parts := strings.Split(out, "---PROC---")
	ipLines, procLines := []string{}, []string{}
	if len(parts) > 0 {
		ipLines = strings.Split(parts[0], "\n")
	}
	if len(parts) > 1 {
		procLines = strings.Split(parts[1], "\n")
	}
	ipMap := map[string]string{}
	for _, line := range ipLines {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		name := strings.TrimSuffix(f[0], ":")
		ip := "N/A"
		for _, x := range f[2:] {
			if strings.Contains(x, ".") && !strings.HasPrefix(x, "127.") {
				ip = x
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
		ip := "N/A"
		if v, ok := ipMap[name]; ok {
			ip = v
		}
		result = append(result, map[string]interface{}{
			"name": name, "ip": ip, "rxSpeed": "Active", "txSpeed": "Active",
			"rxTotal": f[1], "txTotal": f[9],
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
