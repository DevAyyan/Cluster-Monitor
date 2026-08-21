package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// hostEndpoint is the base URL the target agents should push metrics to.
// Set via HOST_ENDPOINT env (e.g. http://10.0.0.5:8080). Empty = push disabled.
var hostEndpoint string

// previousHostEndpoint stores the host's most recent IP/endpoint before an IP change.
var previousHostEndpoint string

// sshError writes a JSON {error: msg} so the dashboard can surface the real
// SSH failure reason instead of a generic "agent offline" message.
func sshError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// doAgentRequest performs an HTTP request to the target agent.
// It first attempts direct HTTP to the agent's port 9192.
// If direct HTTP fails or is bypassed for localhost, it falls back to a localhost request.
// If both fail, it falls back to running a curl command to localhost:9192 locally on the remote server over SSH.
var (
	directReachMu     sync.RWMutex
	directReachCache  = make(map[string]bool)
	directReachExpiry = make(map[string]time.Time)
)

func checkDirectReachable(host string) (bool, bool) {
	directReachMu.RLock()
	defer directReachMu.RUnlock()
	exp, ok := directReachExpiry[host]
	if !ok || time.Now().After(exp) {
		return false, false
	}
	return directReachCache[host], true
}

func setDirectReachable(host string, reachable bool) {
	directReachMu.Lock()
	defer directReachMu.Unlock()
	directReachCache[host] = reachable
	directReachExpiry[host] = time.Now().Add(30 * time.Second)
}

// isLocalHost returns true if the given host address refers to this machine
// (the Docker host), meaning the cluster-target agent on 172.17.0.1:9192 is the same as info.Host:9192.
func isLocalHost(info serverSSHInfo) bool {
	if info.ServerID == "00000000-0000-0000-0000-000000000001" {
		return true
	}
	switch info.Host {
	case "localhost", "127.0.0.1", "0.0.0.0":
		return true
	case "":
		return false
	}
	// Resolve local non-loopback interfaces to check if this IP belongs to us
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.String() == info.Host {
				return true
			}
		}
	}
	return false
}

var agentHTTPClient = &http.Client{
	Transport: &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 800 * time.Millisecond}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	},
	Timeout: 2000 * time.Millisecond,
}

func doAgentRequest(info serverSSHInfo, path string) ([]byte, error) {
	return wsManager.SendCommand(info.ServerID, "GET", path, nil)
}

// doAgentPostRequest sends a POST with a JSON body to the agent.
func doAgentPostRequest(info serverSSHInfo, path string, body []byte) ([]byte, error) {
	return wsManager.SendCommand(info.ServerID, "POST", path, body)
}

// hostBindAddr is the interface the Host listener binds to (default "" => all).
var hostBindAddr string

// scpFile copies a local file to a remote path using the SCP protocol over an
// existing SSH connection. mode is the remote file mode (e.g. 0755).
func scpFile(info serverSSHInfo, localPath, remotePath string, mode os.FileMode) error {
	client, err := dialSSHClient(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port)
	if err != nil {
		return err
	}
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	// SCP source mode: we send a "C" control message then the file contents.
	go func() {
		w, _ := session.StdinPipe()
		defer w.Close()
		fmt.Fprintf(w, "C%04o %d %s\n", mode.Perm(), st.Size(), baseName(remotePath))
		io.Copy(w, f)
		fmt.Fprint(w, "\x00")
	}()

	if err := session.Run(fmt.Sprintf("scp -t %s", quotePath(dirOf(remotePath)))); err != nil {
		return err
	}
	return nil
}

func baseName(p string) string {
	p = strings.TrimRight(p, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func dirOf(p string) string {
	p = strings.TrimRight(p, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return "."
}

func quotePath(p string) string {
	return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'"
}

// sshClientConfig builds an SSH client config from the per-server stored credentials.
// Authentication is key-based: sshKey is the private key PEM contents.
func sshClientConfig(user, password, key string) (*ssh.ClientConfig, error) {
	var authMethods []ssh.AuthMethod
	// Password auth takes precedence (password-only mode).
	if strings.TrimSpace(password) != "" {
		authMethods = append(authMethods, ssh.Password(strings.TrimSpace(password)))
	}
	if strings.TrimSpace(key) != "" {
		keyBytes := []byte(key)
		// The stored key may be raw PEM, base64-encoded PEM, or a bare
		// OpenSSH key blob (no PEM armor). Normalize to PEM.
		if !strings.Contains(key, "PRIVATE KEY") {
			if decoded, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(key)); derr == nil && len(decoded) > 0 {
				keyBytes = decoded
			}
		}
		// If still no PEM armor but looks like an OpenSSH key blob, wrap it.
		if !strings.Contains(string(keyBytes), "-----BEGIN") {
			if bytes.Contains(keyBytes, []byte("openssh-key-v1")) {
				keyBytes = []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
					base64.StdEncoding.EncodeToString(keyBytes) +
					"\n-----END OPENSSH PRIVATE KEY-----\n")
			}
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SSH private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no SSH authentication method available (missing password or private key)")
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // lab/internal use; auto-accepts unknown hosts
		Timeout:         10 * time.Second,
	}
	return cfg, nil
}

type cachedSSHClient struct {
	client   *ssh.Client
	lastUsed time.Time
	mu       sync.Mutex
}

var (
	sshClientPoolMu sync.Mutex
	sshClientPool   = make(map[string]*cachedSSHClient)
)

// dialSSHClient establishes a fresh SSH connection to the target.
func dialSSHClient(serverID, user, password, key, host string, port int) (*ssh.Client, error) {
	cfg, err := sshClientConfig(user, password, key)
	if err != nil {
		return nil, err
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	if port == 0 {
		addr = fmt.Sprintf("%s:22", host)
	}
	return ssh.Dial("tcp", addr, cfg)
}

func getOrCreateSSHClient(serverID, user, password, key, host string, port int) (*ssh.Client, error) {
	sshClientPoolMu.Lock()
	cached, ok := sshClientPool[serverID]
	if ok && cached != nil {
		cached.mu.Lock()
		if cached.client != nil {
			// Fast check if connection is still healthy
			_, _, err := cached.client.SendRequest("keepalive@openssh.com", true, nil)
			if err == nil {
				cached.lastUsed = time.Now()
				client := cached.client
				cached.mu.Unlock()
				sshClientPoolMu.Unlock()
				return client, nil
			}
			// Connection dropped or failed keepalive
			_ = cached.client.Close()
			cached.client = nil
		}
		cached.mu.Unlock()
	}
	sshClientPoolMu.Unlock()

	client, err := dialSSHClient(serverID, user, password, key, host, port)
	if err != nil {
		return nil, err
	}

	sshClientPoolMu.Lock()
	sshClientPool[serverID] = &cachedSSHClient{
		client:   client,
		lastUsed: time.Now(),
	}
	sshClientPoolMu.Unlock()

	return client, nil
}

// runSSHCommand reuses active SSH connections and opens a new session per command.
// Retries once automatically on transient session errors.
func runSSHCommand(serverID, user, password, key, host string, port int, command string) (string, error) {
	// If the server has an active WebSocket connection, route it directly over the WebSocket!
	if serverID != "" && serverID != "test" {
		if _, online := wsManager.Get(serverID); online {
			log.Printf("[ws-proxy-exec] Routing command over WebSocket to server %s: %s", serverID, command)
			reqBody, err := json.Marshal(map[string]string{"command": command})
			if err != nil {
				return "", fmt.Errorf("failed to marshal request payload: %w", err)
			}
			respBytes, err := wsManager.SendCommand(serverID, "POST", "exec-command", reqBody)
			if err != nil {
				return "", err
			}
			var resp struct {
				Ok     bool   `json:"ok"`
				Output string `json:"output"`
			}
			if err := json.Unmarshal(respBytes, &resp); err != nil {
				return string(respBytes), nil // Return raw response if parsing fails
			}
			// When the command ran but returned a non-zero exit code, return the
			// output as the error so the caller can display the real failure reason.
			if !resp.Ok {
				return resp.Output, fmt.Errorf("%s", strings.TrimSpace(resp.Output))
			}
			return resp.Output, nil
		}
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		client, err := getOrCreateSSHClient(serverID, user, password, key, host, port)
		if err != nil {
			lastErr = err
			continue
		}
		session, err := client.NewSession()
		if err != nil {
			// Evict cached client on session failure
			sshClientPoolMu.Lock()
			if cached, ok := sshClientPool[serverID]; ok && cached.client == client {
				_ = client.Close()
				delete(sshClientPool, serverID)
			}
			sshClientPoolMu.Unlock()
			lastErr = err
			continue
		}
		cmdBash := "export PATH=$PATH:/usr/bin:/usr/local/bin:/usr/sbin:/sbin; " + command
		fullCmd := fmt.Sprintf("exec /bin/bash -c %s 2>/dev/null || exec bash -c %s 2>/dev/null || exec /bin/sh -c %s || exec sh -c %s",
			shellQuote(cmdBash), shellQuote(cmdBash), shellQuote(cmdBash), shellQuote(cmdBash))
		output, err := session.CombinedOutput(fullCmd)
		session.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return string(output), nil
	}
	return "", lastErr
}

// serverSSHInfo holds the resolved SSH credentials for a server.
type serverSSHInfo struct {
	ServerID string
	User     string
	Key      string
	Password string
	Host     string
	Port     int
	OSFamily string
}

// loadServerSSHInfo fetches SSH connection details for a server from the DB.
func loadServerSSHInfo(serverID string) (serverSSHInfo, error) {
	var user, key, password, host, osFamily string
	var port int
	err := db.QueryRow(
		"SELECT COALESCE(ssh_user,''), COALESCE(ssh_key,''), COALESCE(ssh_password,''), ip_address, COALESCE(ssh_port,22), os_family FROM servers WHERE id=$1",
		serverID,
	).Scan(&user, &key, &password, &host, &port, &osFamily)
	if err != nil {
		return serverSSHInfo{}, err
	}
	return serverSSHInfo{ServerID: serverID, User: user, Key: key, Password: password, Host: host, Port: port, OSFamily: osFamily}, nil
}

// isDemoServer returns true if the server should return mock data (no SSH used).
func isDemoServer(info serverSSHInfo, serverID string) bool {
	return serverID == "11111111-1111-1111-1111-111111111111"
}

// sshGetProcesses runs `ps` over SSH and returns the same ProcessInfo shape the agent produced.
func sshGetProcesses(info serverSSHInfo) ([]map[string]interface{}, error) {
	// Try direct HTTP or SSH-tunnel curl first
	data, err := doAgentRequest(info, "processes")
	if err == nil {
		var procs []map[string]interface{}
		if errUnmarshal := json.Unmarshal(data, &procs); errUnmarshal == nil {
			return procs, nil
		}
	}

	// Fallback to raw SSH execution if agent fails
	var cmd string
	switch info.OSFamily {
	case "darwin":
		cmd = "ps -eo pid,user,pcpu,pmem,comm,args -r 2>/dev/null"
	default: // linux
		// pmem is a % of RAM; convert to MB using MemTotal so the UI shows real memory.
		cmd = "ps -eo pid,user,pcpu,pmem,rss,comm,args --sort=-pcpu 2>/dev/null | awk 'NR==1{print; next}{rss_mb=$5/1024; printf \"%s %s %s %s %.1f %s %s\\n\",$1,$2,$3,$4,rss_mb,$6,substr($0,index($0,$7))}'"
	}
	out, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, cmd)
	if err != nil {
		return nil, err
	}
	return parsePSOutput(out), nil
}

func parsePSOutput(out string) []map[string]interface{} {
	lines := strings.Split(out, "\n")
	var procs []map[string]interface{}
	for i, line := range lines {
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
		pmem := fields[3]
		memMB := fields[4]
		name := fields[5]
		cmdline := strings.Join(fields[6:], " ")
		// ignore our own ssh/ps invocations
		if name == "ps" || strings.Contains(name, "ssh") {
			continue
		}
		procs = append(procs, map[string]interface{}{
			"pid":     pid,
			"user":    user,
			"cpu":     cpu,
			"pmem":    pmem,
			"mem":     memMB,
			"name":    name,
			"cmdline": cmdline,
		})
	}
	return procs
}

// sshGetContainers runs `docker ps -a` over SSH with JSON formatting and includes images list.
func sshGetContainers(info serverSSHInfo) (map[string]interface{}, error) {
	data, err := doAgentRequest(info, "containers")
	if err == nil {
		var payload map[string]interface{}
		if errUnmarshal := json.Unmarshal(data, &payload); errUnmarshal == nil {
			return payload, nil
		}
		var containers []map[string]interface{}
		if errUnmarshal := json.Unmarshal(data, &containers); errUnmarshal == nil {
			return map[string]interface{}{"containers": containers, "images": []map[string]interface{}{}}, nil
		}
	}

	// Fallback to raw SSH execution if agent fails
	cmd := `export PATH=$PATH:/usr/bin:/usr/local/bin:/usr/sbin:/sbin; docker version --format 'Docker Engine v{{.Server.Version}} (API v{{.Server.APIVersion}})' 2>/dev/null; echo "---INFO---"; docker info --format '{{.Name}} | {{.OperatingSystem}} ({{.KernelVersion}})' 2>/dev/null; echo "---CONTAINERS---"; docker ps -a --format '{"id":"{{.ID}}","name":"{{.Names}}","status":"{{.Status}}","state":"{{.State}}","image":"{{.Image}}","ports":"{{.Ports}}","created":"{{.CreatedAt}}"}' 2>/dev/null; echo "---IMAGES---"; docker images --format '{"repo":"{{.Repository}}","tag":"{{.Tag}}","id":"{{.ID}}","created":"{{.CreatedAt}}","size":"{{.Size}}"}' 2>/dev/null`
	out, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, cmd)
	if err != nil {
		return map[string]interface{}{"containers": []map[string]interface{}{}, "images": []map[string]interface{}{}}, nil
	}

	dockerVer := "Docker Engine"
	dockerInfo := ""
	var containers []map[string]interface{}
	var images []map[string]interface{}

	partsInfo := strings.Split(out, "---INFO---")
	if len(partsInfo) > 0 {
		dockerVer = strings.TrimSpace(partsInfo[0])
	}
	rem := out
	if len(partsInfo) > 1 {
		rem = partsInfo[1]
	}

	partsCont := strings.Split(rem, "---CONTAINERS---")
	if len(partsCont) > 0 {
		dockerInfo = strings.TrimSpace(partsCont[0])
	}
	rem2 := rem
	if len(partsCont) > 1 {
		rem2 = partsCont[1]
	}

	parts := strings.Split(rem2, "---IMAGES---")
	if len(parts) > 0 {
		for _, l := range strings.Split(strings.TrimSpace(parts[0]), "\n") {
			var c map[string]interface{}
			if json.Unmarshal([]byte(l), &c) == nil {
				containers = append(containers, c)
			}
		}
	}
	if len(parts) > 1 {
		for _, l := range strings.Split(strings.TrimSpace(parts[1]), "\n") {
			var img map[string]interface{}
			if json.Unmarshal([]byte(l), &img) == nil {
				images = append(images, img)
			}
		}
	}
	return map[string]interface{}{
		"docker_version": dockerVer,
		"docker_info":    dockerInfo,
		"containers":     containers,
		"images":         images,
	}, nil
}

// sshGetSystemLogs runs journalctl over SSH.
func sshGetSystemLogs(info serverSSHInfo) (string, error) {
	data, err := doAgentRequest(info, "systemlogs")
	if err == nil {
		return string(data), nil
	}

	// Fallback to raw SSH execution if agent fails
	var cmd string
	switch info.OSFamily {
	case "darwin":
		cmd = "log show --last 10m 2>/dev/null | tail -n 100"
	default:
		cmd = "journalctl -n 100 --no-pager 2>/dev/null"
	}
	out, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, cmd)
	if err != nil {
		return "", err
	}
	return out, nil
}

// sshGetStorage collects disk/partition info via lsblk + df.
func sshGetStorage(info serverSSHInfo) ([]map[string]interface{}, error) {
	data, err := doAgentRequest(info, "storage")
	if err == nil {
		var parts []map[string]interface{}
		if e := json.Unmarshal(data, &parts); e == nil {
			return parts, nil
		}
	}
	cmd := `df -T -B1 2>/dev/null || df -T 2>/dev/null`
	out, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, cmd)
	if err != nil {
		return nil, err
	}
	return parseStorageOutput(out)
}

func parseStorageOutput(out string) ([]map[string]interface{}, error) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var parts []map[string]interface{}
	seenDevices := make(map[string]int)

	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" || strings.HasPrefix(line, "Filesystem") || strings.HasPrefix(line, "NAME") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		name := fields[0]
		fstype := fields[1]
		if !strings.HasPrefix(name, "/dev/") {
			continue
		}
		mountpoint := fields[len(fields)-1]

		if existingIdx, ok := seenDevices[name]; ok {
			if mountpoint == "/" {
				parts[existingIdx]["mountpoint"] = "/"
			}
			continue
		}

		sizeB, err1 := strconv.ParseFloat(fields[2], 64)
		usedB, err2 := strconv.ParseFloat(fields[3], 64)
		availB, err3 := strconv.ParseFloat(fields[4], 64)
		pct := 0
		if len(fields) >= 7 {
			pctStr := strings.TrimSuffix(fields[5], "%")
			pct, _ = strconv.Atoi(pctStr)
		}

		sizeStr := fields[2]
		usedStr := fields[3]
		availStr := fields[4]

		if err1 == nil && err2 == nil && err3 == nil {
			if sizeB > 0 {
				pct = int((usedB / sizeB) * 100.0)
			}
			sizeStr = fmt.Sprintf("%.1f GB", sizeB/(1024*1024*1024))
			usedStr = fmt.Sprintf("%.1f GB", usedB/(1024*1024*1024))
			availStr = fmt.Sprintf("%.1f GB", availB/(1024*1024*1024))
			if sizeB < 1024*1024*1024 {
				sizeStr = fmt.Sprintf("%.0f MB", sizeB/(1024*1024))
				usedStr = fmt.Sprintf("%.0f MB", usedB/(1024*1024))
				availStr = fmt.Sprintf("%.0f MB", availB/(1024*1024))
			}
		}

		entry := map[string]interface{}{
			"name":       name,
			"fstype":     fstype,
			"size":       sizeStr,
			"used":       usedStr,
			"available":  availStr,
			"mountpoint": mountpoint,
			"pct":        pct,
		}
		seenDevices[name] = len(parts)
		parts = append(parts, entry)
	}
	return parts, nil
}

// sshGetDockerInfo returns Docker version + images list.
func sshGetDockerInfo(info serverSSHInfo) (map[string]interface{}, error) {
	data, err := doAgentRequest(info, "docker-info")
	if err == nil {
		var res map[string]interface{}
		if errUnmarshal := json.Unmarshal(data, &res); errUnmarshal == nil {
			return res, nil
		}
	}

	verCmd := `docker version --format '{{json .}}' 2>/dev/null || echo '{"error":"no docker"}'`
	imgCmd := `docker images --format '{{json .}}' 2>/dev/null`
	outVer, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, verCmd)
	if err != nil {
		return map[string]interface{}{"available": false, "error": err.Error()}, nil
	}
	outImg, _ := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, imgCmd)
	var ver interface{}
	json.Unmarshal([]byte(outVer), &ver)
	images := []map[string]interface{}{}
	for _, line := range strings.Split(strings.TrimSpace(outImg), "\n") {
		var img map[string]interface{}
		if json.Unmarshal([]byte(line), &img) == nil {
			images = append(images, img)
		}
	}
	return map[string]interface{}{
		"available": true,
		"version":   ver,
		"images":    images,
	}, nil
}

func sshGetNetworkConnections(info serverSSHInfo) (map[string]interface{}, error) {
	data, err := doAgentRequest(info, "network-connections")
	if err == nil {
		return parseNetworkConnections(string(data)), nil
	}

	cmd := `echo '---TCP---'; cat /proc/net/tcp /proc/net/tcp6 2>/dev/null; echo '---UDP---'; cat /proc/net/udp /proc/net/udp6 2>/dev/null`
	out, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, cmd)
	if err != nil {
		return nil, err
	}
	return parseNetworkConnections(out), nil
}

func parseNetworkConnections(out string) map[string]interface{} {
	res := map[string]interface{}{"tcp": []map[string]string{}, "udp": []map[string]string{}}
	var current string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "---TCP---" {
			current = "tcp"
			continue
		}
		if line == "---UDP---" {
			current = "udp"
			continue
		}
		if line == "" || strings.HasPrefix(line, "  sl") || current == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		localAddr := decodeHexIP(fields[1])
		remAddr := decodeHexIP(fields[2])
		state := decodeTCPState(fields[3])
		conns, _ := res[current].([]map[string]string)
		conns = append(conns, map[string]string{"local": localAddr, "remote": remAddr, "state": state})
		res[current] = conns
	}
	return res
}

func decodeHexIP(h string) string {
	parts := strings.Split(h, ":")
	if len(parts) != 2 {
		return h
	}
	ipHex := parts[0]
	portHex := parts[1]
	port, _ := strconv.ParseInt(portHex, 16, 64)
	// Try IPv4 (8 hex chars = 4 bytes)
	if len(ipHex) == 8 {
		b, _ := hex.DecodeString(ipHex)
		if len(b) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d:%d", b[3], b[2], b[1], b[0], port)
		}
	}
	// IPv6 (32 hex chars = 16 bytes)
	if len(ipHex) == 32 {
		// Return as-is with port (simplified)
		return fmt.Sprintf("[%s]:%d", ipHex, port)
	}
	return fmt.Sprintf("%s:%d", ipHex, port)
}

func decodeTCPState(state string) string {
	states := map[string]string{
		"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
		"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
		"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
		"0A": "LISTEN", "0B": "CLOSING",
	}
	if s, ok := states[state]; ok {
		return s
	}
	return "UNKNOWN"
}

// sshDockerRun runs a docker command on the target (start/stop/restart/logs/compose).
func sshDockerRun(info serverSSHInfo, cmdStr string) (string, error) {
	escaped := strings.ReplaceAll(cmdStr, "'", "'\\''")
	sshCmd := fmt.Sprintf("export PATH=$PATH:/usr/bin:/usr/local/bin:/usr/sbin:/sbin; docker %s 2>&1", escaped)
	out, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, sshCmd)
	if err != nil {
		return out, err
	}
	return out, nil
}

// sshGetNetworks derives interface info over SSH by combining `ip -br addr` with /proc/net/dev.
func sshGetNetworks(info serverSSHInfo) ([]map[string]interface{}, error) {
	data, err := doAgentRequest(info, "networks")
	if err == nil {
		var nets []map[string]interface{}
		if errUnmarshal := json.Unmarshal(data, &nets); errUnmarshal == nil {
			return nets, nil
		}
	}

	// Fallback to raw SSH execution if agent fails
	cmd := "ip -br link 2>/dev/null; echo '---ADDR---'; ip -br addr 2>/dev/null; echo '---PROC---'; cat /proc/net/dev 2>/dev/null"
	out, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, cmd)
	if err != nil {
		return nil, err
	}
	return parseNetworks(out), nil
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
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			name := strings.TrimSuffix(fields[0], ":")
			mac := fields[2]
			if strings.Contains(mac, ":") {
				macMap[name] = mac
			}
		}
	}

	ipMap := map[string]string{}
	for _, line := range addrLines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ":")
		ip := "N/A"
		for _, f := range fields[2:] {
			if strings.Contains(f, ".") && !strings.HasPrefix(f, "127.") {
				ip = strings.Split(f, "/")[0]
				break
			}
			if strings.Contains(f, ":") && f != "::1" && !strings.HasPrefix(f, "fe80") {
				ip = strings.Split(f, "/")[0]
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
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ":")
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
			"rxTotal": formatBytes(fields[1]),
			"txTotal": formatBytes(fields[9]),
		})
	}
	return result
}

var (
	metricsCacheMu    sync.RWMutex
	hostMetricsCache  = make(map[string]map[string]interface{})
	hostMetricsExpiry = make(map[string]time.Time)
)

// sshGetMetrics collects accurate system metrics directly from the remote kernel
// via reading /proc and standard utilities. No Prometheus/agent required.
func sshGetMetrics(info serverSSHInfo) (map[string]interface{}, error) {
	cacheKey := info.ServerID // Use ServerID not Host — different servers can have the same IP via NAT
	metricsCacheMu.RLock()
	if exp, ok := hostMetricsExpiry[cacheKey]; ok && time.Now().Before(exp) {
		m := hostMetricsCache[cacheKey]
		metricsCacheMu.RUnlock()
		return m, nil
	}
	metricsCacheMu.RUnlock()

	data, err := doAgentRequest(info, "metrics")
	if err == nil {
		var metrics map[string]interface{}
		if errUnmarshal := json.Unmarshal(data, &metrics); errUnmarshal == nil {
			metricsCacheMu.Lock()
			hostMetricsCache[cacheKey] = metrics
			hostMetricsExpiry[cacheKey] = time.Now().Add(1000 * time.Millisecond)
			metricsCacheMu.Unlock()
			return metrics, nil
		}
	}

	// Fallback to raw SSH execution if agent fails
	cmd := `
load=$(awk '{print $1}' /proc/loadavg)
memtotal=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
memfree=$(awk '/^MemFree:/{print $2}' /proc/meminfo)
memavail=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
buffers=$(awk '/^Buffers:/{print $2}' /proc/meminfo)
cached=$(awk '/^Cached:/{print $2}' /proc/meminfo)
swaptotal=$(awk '/^SwapTotal:/{print $2}' /proc/meminfo)
swapfree=$(awk '/^SwapFree:/{print $2}' /proc/meminfo)
nproc=$(nproc)
uptime=$(awk '{print int($1)}' /proc/uptime)
disk=$(df -B1 / 2>/dev/null | awk 'NR==2{print $2" "$3}')
# Network delta over ~1s (sum of all interfaces' rx/tx bytes from /proc/net/dev)
netstat() { awk 'NR>2{ rx+=$2; tx+=$10 } END{ print rx" "tx }' /proc/net/dev; }
read nr1 nt1 < <(netstat)
# Per-core CPU initial snapshot
declare -a c1_total c1_idle; i=0
while read -r label rest; do
  case "$label" in cpu[0-9]|cpu[0-9][0-9])
    set -- $rest; t=$(( $1+$2+$3+$4 )); id=$4
    c1_total[i]=$t; c1_idle[i]=$id; ((i++))
  esac
done < /proc/stat
# CPU delta over ~1s
read -r _ a1 b1 c1 d1 rest < /proc/stat
t1=$((a1+b1+c1+d1)); i1=$((d1))
sleep 1
read -r _ a2 b2 c2 d2 rest < /proc/stat
t2=$((a2+b2+c2+d2)); i2=$((d2))
dt=$((t2-t1)); di=$((i2-i1))
if [ "$dt" -gt 0 ]; then cpu=$(( (100*(dt-di))/dt )); else cpu=0; fi
# Per-core CPU delta
i=0
while read -r label rest; do
  case "$label" in cpu[0-9]|cpu[0-9][0-9])
    set -- $rest; t2=$(( $1+$2+$3+$4 )); i2=$4
    t1=${c1_total[i]}; i1=${c1_idle[i]}
    dt=$((t2-t1)); di=$((i2-i1))
    if [ "$dt" -gt 0 ]; then echo "CORE$i $(( (100*(dt-di))/dt ))"; else echo "CORE$i 0"; fi
    ((i++))
  esac
done < /proc/stat
read nr2 nt2 < <(netstat)
dnr=$((nr2-nr1)); dnt=$((nt2-nt1))
if [ "$dnr" -lt 0 ]; then dnr=0; fi
if [ "$dnt" -lt 0 ]; then dnt=0; fi
# bytes/sec -> KB/s
rxkb=$((dnr/1024)); txkb=$((dnt/1024))
printf "LOAD %s\nMEMTOTAL %s\nMEMFREE %s\nMEMAVAILABLE %s\nBUFFERS %s\nCACHED %s\nSWAPTOTAL %s\nSWAPFREE %s\nNPROC %s\nUPTIME %s\nDISK %s\nCPU %s\nNETRX %s\nNETTX %s\n" \
  "$load" "$memtotal" "$memfree" "$memavail" "$buffers" "$cached" "$swaptotal" "$swapfree" \
  "$nproc" "$uptime" "$disk" "$cpu" "$rxkb" "$txkb"
tcp=$(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | grep -c -v 'local_address' || echo 0)
udp=$(cat /proc/net/udp /proc/net/udp6 2>/dev/null | grep -c -v 'local_address' || echo 0)
echo "TCP $tcp"
echo "UDP $udp"
`
	out, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, cmd)
	if err != nil {
		return nil, err
	}
	return parseMetrics(out), nil
}

func parseMetrics(out string) map[string]interface{} {
	res := map[string]interface{}{
		"cpu":           0.0,
		"ram_used_pct":  0.0,
		"ram_used_gb":   0.0,
		"ram_total_gb":  0.0,
		"swap_used_pct": 0.0,
		"swap_used_gb":  0.0,
		"swap_total_gb": 0.0,
		"disk_used_pct": 0.0,
		"disk_used_gb":  0.0,
		"disk_total_gb": 0.0,
		"net_rx_kb":     0.0,
		"net_tx_kb":     0.0,
		"cores":         []float64{},
	}

	memInfo := map[string]float64{}
	diskTotal := 0.0
	diskUsed := 0.0
	uptime := 0.0
	nproc := 0
	cpuPct := 0.0
	var corePcts []float64

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToUpper(fields[0])
		val := fields[1]
		switch key {
		case "LOAD":
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				res["load_1"] = v
			}
		case "MEMTOTAL", "MEMFREE", "MEMAVAILABLE", "BUFFERS", "CACHED", "SWAPTOTAL", "SWAPFREE":
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				memInfo[key] = v // value in kB
			}
		case "NPROC":
			if n, err := strconv.Atoi(val); err == nil {
				nproc = n
			}
		case "UPTIME":
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				uptime = v
			}
		case "DISK":
			// "total used" in bytes
			if len(fields) >= 3 {
				if t, err := strconv.ParseFloat(fields[1], 64); err == nil {
					if u, err2 := strconv.ParseFloat(fields[2], 64); err2 == nil {
						diskTotal = t
						diskUsed = u
					}
				}
			}
		case "CPU":
			if v, err := strconv.Atoi(val); err == nil {
				cpuPct = float64(v)
			}
		case "NETRX":
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				res["net_rx_kb"] = v
			}
		case "NETTX":
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				res["net_tx_kb"] = v
			}
		case "TCP":
			if v, err := strconv.Atoi(val); err == nil {
				res["active_tcp_connections"] = v
			}
		case "UDP":
			if v, err := strconv.Atoi(val); err == nil {
				res["active_udp_connections"] = v
			}
		default:
			if strings.HasPrefix(key, "CORE") {
				if idx, err := strconv.Atoi(strings.TrimPrefix(key, "CORE")); err == nil {
					if v, e := strconv.ParseFloat(val, 64); e == nil {
						for len(corePcts) <= idx {
							corePcts = append(corePcts, 0)
						}
						corePcts[idx] = v
					}
				}
			}
		}
	}

	// RAM
	memTotal := memInfo["MEMTOTAL"]
	memAvail := memInfo["MEMAVAILABLE"]
	if memAvail == 0 {
		memAvail = memInfo["MEMFREE"] + memInfo["BUFFERS"] + memInfo["CACHED"]
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
	swapTotal := memInfo["SWAPTOTAL"]
	swapFree := memInfo["SWAPFREE"]
	if swapTotal > 0 {
		res["swap_total_gb"] = swapTotal / 1024 / 1024
		used := swapTotal - swapFree
		if used < 0 {
			used = 0
		}
		res["swap_used_gb"] = used / 1024 / 1024
		res["swap_used_pct"] = (used / swapTotal) * 100.0
	}

	// Disk (bytes)
	if diskTotal > 0 {
		res["disk_total_gb"] = diskTotal / 1024 / 1024 / 1024
		res["disk_used_gb"] = diskUsed / 1024 / 1024 / 1024
		res["disk_used_pct"] = (diskUsed / diskTotal) * 100.0
	}

	// CPU (already a delta computed on the target)
	// CPU (already a delta computed on the target)
	res["cpu"] = round1(cpuPct)
	cores := corePcts
	if len(cores) == 0 && nproc > 0 {
		res["cpu_cores"] = nproc
		for i := 0; i < nproc; i++ {
			cores = append(cores, round1(cpuPct))
		}
	} else if len(cores) == 0 {
		cores = append(cores, round1(cpuPct))
	}
	res["cores"] = cores
	if len(cores) > 0 && res["cpu_cores"] == nil {
		res["cpu_cores"] = len(cores)
	}

	if uptime > 0 {
		res["uptime_seconds"] = uptime
	}

	return res
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10.0
}

// sshServiceControl runs a systemctl action over SSH (with sudo).
func sshServiceControl(info serverSSHInfo, service, action string) (map[string]interface{}, error) {
	var cmd string
	switch info.OSFamily {
	case "darwin":
		switch action {
		case "start":
			cmd = fmt.Sprintf("sudo launchctl start %s 2>&1 || launchctl start %s 2>&1", service, service)
		case "stop":
			cmd = fmt.Sprintf("sudo launchctl stop %s 2>&1 || launchctl stop %s 2>&1", service, service)
		case "restart":
			cmd = fmt.Sprintf("sudo launchctl kickstart -k %s 2>&1 || launchctl kickstart -k %s 2>&1", service, service)
		default:
			cmd = fmt.Sprintf("launchctl list | grep %s 2>&1", service)
		}
	case "windows":
		switch action {
		case "start":
			cmd = fmt.Sprintf("powershell.exe -Command \"Start-Service -Name %s\" 2>&1", service)
		case "stop":
			cmd = fmt.Sprintf("powershell.exe -Command \"Stop-Service -Name %s\" 2>&1", service)
		case "restart":
			cmd = fmt.Sprintf("powershell.exe -Command \"Restart-Service -Name %s\" 2>&1", service)
		default:
			cmd = fmt.Sprintf("powershell.exe -Command \"Get-Service -Name %s | Select-Object Status\" 2>&1", service)
		}
	default:
		cmd = fmt.Sprintf("sudo systemctl %s %s 2>&1 || systemctl %s %s 2>&1", action, service, action, service)
	}
	out, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, cmd)
	if err != nil {
		return map[string]interface{}{
			"status": "error",
			"output": strings.TrimSpace(out) + " | " + err.Error(),
		}, nil
	}
	return map[string]interface{}{
		"status": "success",
		"output": strings.TrimSpace(out),
	}, nil
}

// sshKillProcess sends a signal to a PID over SSH (with sudo).
// signalToArg maps a friendly signal name to the `kill` flag.
func signalToArg(signal string) (string, bool) {
	switch strings.ToLower(signal) {
	case "suspend", "sigstop", "stop":
		return "-STOP", true
	case "continue", "sigcont", "cont":
		return "-CONT", true
	case "hangup", "sighup", "hup":
		return "-HUP", true
	case "interrupt", "sigint", "int":
		return "-INT", true
	case "terminate", "sigterm", "term":
		return "-TERM", true
	case "kill", "sigkill", "9":
		return "-9", true
	default:
		return "", false
	}
}

func sshKillProcess(info serverSSHInfo, pid, signal string) (map[string]interface{}, error) {
	signalArg, ok := signalToArg(signal)
	if !ok {
		return map[string]interface{}{"status": "error", "error": "Invalid signal value"}, nil
	}
	cmd := fmt.Sprintf("sudo kill %s %s 2>&1 || kill %s %s 2>&1", signalArg, pid, signalArg, pid)
	out, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, cmd)
	if err != nil {
		errMsg := strings.TrimSpace(out)
		if errMsg == "" {
			errMsg = err.Error()
		}
		if strings.Contains(strings.ToLower(errMsg), "operation not permitted") || strings.Contains(strings.ToLower(errMsg), "permission denied") {
			errMsg = "Permission Denied: SSH user does not have permission to send this signal. Configure passwordless sudo for the SSH user."
		}
		return map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("Failed to send signal: %s", errMsg),
		}, nil
	}
	return map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Signal %s sent to process successfully.", signal),
	}, nil
}

// sshKillProcessByName sends a signal to every process whose comm/name matches
// the given application name. Used for application-level actions from the Host.
func sshKillProcessByName(info serverSSHInfo, name, signal string) (map[string]interface{}, error) {
	signalArg, ok := signalToArg(signal)
	if !ok {
		return map[string]interface{}{"status": "error", "error": "Invalid signal value"}, nil
	}
	// Match by comm (process name, exact-ish) and args; prefer pkill, fall back to pgrep+kill.
	cmd := fmt.Sprintf("for p in $(pgrep -x %s 2>/dev/null); do sudo kill %s $p 2>/dev/null || kill %s $p 2>/dev/null; done; echo done", shellQuote(name), signalArg, signalArg)
	out, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, cmd)
	if err != nil {
		errMsg := strings.TrimSpace(out)
		if errMsg == "" {
			errMsg = err.Error()
		}
		return map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("Failed to signal application: %s", errMsg),
		}, nil
	}
	return map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Signal %s sent to application '%s'.", signal, name),
	}, nil
}

// shellQuote wraps a value in single quotes for safe shell usage.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// bufioScanner helper is intentionally unused; kept reference removed.

// agentAssetsDir is where the backend keeps the prebuilt agent binary + unit file
// to ship to external servers. Override with AGENT_ASSETS_DIR env if needed.
var agentAssetsDir = "agent_assets"

// sshInstallAgent cross-deploys the correct pre-built agent binary to the
// target server. It:
//  1. Detects the target's OS/arch via SSH
//  2. SCPs ONLY the matching binary (nothing else)
//  3. Runs the binary once with SERVER_ID, AGENT_TOKEN, HOST_ENDPOINT as env vars
//
// The binary's selfInstallService() then writes its own systemd unit with all
// three credentials embedded and starts itself — no external config files needed.
func sshInstallAgent(info serverSSHInfo, serverID string, endpoint string) error {
	// --- Step 1: Detect target OS and CPU architecture ---
	osOut, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, "uname -s 2>/dev/null || echo Linux")
	if err != nil {
		return fmt.Errorf("detect OS: %w", err)
	}
	archOut, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, "uname -m 2>/dev/null || echo x86_64")
	if err != nil {
		return fmt.Errorf("detect arch: %w", err)
	}

	osName := strings.ToLower(strings.TrimSpace(osOut))
	archRaw := strings.ToLower(strings.TrimSpace(archOut))

	goos := "linux"
	switch {
	case strings.Contains(osName, "darwin"):
		goos = "darwin"
	case strings.Contains(osName, "windows"), strings.Contains(osName, "mingw"):
		goos = "windows"
	}

	goarch := "amd64"
	if archRaw == "aarch64" || archRaw == "arm64" || strings.HasPrefix(archRaw, "arm") {
		goarch = "arm64"
	}

	// --- Step 2: Pick the correct pre-built binary ---
	binName := fmt.Sprintf("cluster-target-%s-%s", goos, goarch)
	if goos == "windows" {
		binName += ".exe"
	}
	binLocal := filepath.Join(agentAssetsDir, binName)
	if _, err := os.Stat(binLocal); err != nil {
		return fmt.Errorf("no pre-built binary for %s/%s at %s: %w", goos, goarch, binLocal, err)
	}
	log.Printf("[agent-bootstrap] deploying %s to %s (%s/%s)", binName, info.Host, goos, goarch)

	// --- Step 3: SCP ONLY the binary to ~/.local/bin/ ---
	remoteBin := "~/.local/bin/cluster-target"
	setupDir := "mkdir -p ~/.local/bin"
	if _, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, setupDir); err != nil {
		return fmt.Errorf("mkdir ~/.local/bin: %w", err)
	}
	if err := scpFile(info, binLocal, "/tmp/cluster-target-new", 0755); err != nil {
		return fmt.Errorf("scp binary: %w", err)
	}
	if _, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port,
		fmt.Sprintf("mv /tmp/cluster-target-new %s && chmod +x %s", remoteBin, remoteBin)); err != nil {
		return fmt.Errorf("install binary: %w", err)
	}

	// --- Step 4: Look up the agent token ---
	var agentToken string
	_ = db.QueryRow("SELECT agent_token FROM servers WHERE id=$1", serverID).Scan(&agentToken)

	// --- Step 5: Run the binary ONCE with env vars ---
	// selfInstallService() inside the binary writes its own systemd unit with all
	// credentials embedded and starts the persistent service. Nothing else is needed.
	runCmd := fmt.Sprintf(
		"SERVER_ID=%s AGENT_TOKEN=%s HOST_ENDPOINT=%s nohup %s > /tmp/cluster-target-install.log 2>&1 &",
		shellQuote(serverID), shellQuote(agentToken), shellQuote(endpoint), remoteBin,
	)
	if _, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, runCmd); err != nil {
		return fmt.Errorf("launch agent: %w", err)
	}

	log.Printf("[agent-bootstrap] agent binary installed and launched on %s — self-install will start the service", info.Host)
	return nil
}

// sshAgentAddEndpoint tells the target agent to start pushing to the Host endpoint.
// It writes the host URL directly into the agent's `~/.config/cluster-target/endpoints` file
// then restarts the service so it picks it up immediately.
func sshAgentAddEndpoint(info serverSSHInfo, endpoint string) error {
	if endpoint == "" {
		return nil
	}
	cmds := []string{
		fmt.Sprintf(`mkdir -p ~/.config/cluster-target && echo %s > ~/.config/cluster-target/endpoints`, quotePath(endpoint)),
		`systemctl --user restart cluster-target.service 2>&1 || true`,
	}
	for _, c := range cmds {
		if _, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, c); err != nil {
			return fmt.Errorf("add endpoint: %w", err)
		}
	}
	return nil
}

// sshAgentRemoveEndpoint removes the Host endpoint from the target agent.
func sshAgentRemoveEndpoint(info serverSSHInfo, endpoint string) error {
	if endpoint == "" {
		return nil
	}
	cmd := `rm -f ~/.config/cluster-target/endpoints`
	if _, err := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, cmd); err != nil {
		return fmt.Errorf("remove endpoint: %w", err)
	}
	return nil
}
