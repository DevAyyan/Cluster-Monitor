package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

var (
	db          *sql.DB
	uuidRegex   = regexp.MustCompile(`^[a-fA-F0-9\-]{36}$`)
	actionRegex = regexp.MustCompile(`^(start|stop|restart|status)$`)
	serviceRegex = regexp.MustCompile(`^[a-zA-Z0-9\.\-_]+$`)
)

// Structs representing database entities
type Server struct {
	ID         string    `json:"id"`
	Hostname   string    `json:"hostname"`
	IPAddress  string    `json:"ip_address"`
	OSFamily   string    `json:"os_family"`
	AgentToken string    `json:"agent_token,omitempty"`
	SSHUser     string    `json:"ssh_user,omitempty"`
	SSHKey      string    `json:"ssh_key,omitempty"`
	SSHPassword string    `json:"ssh_password,omitempty"`
	SSHPort     int       `json:"ssh_port,omitempty"`
	Status     string    `json:"status"`
	LastSeen   time.Time `json:"last_seen"`
	CreatedAt  time.Time `json:"created_at"`
}

type MonitoredService struct {
	ID          int    `json:"id"`
	ServerID    string `json:"server_id"`
	ServiceName string `json:"service_name"`
	IsTracked   bool   `json:"is_tracked"`
}

type AlertRule struct {
	ID              int          `json:"id"`
	ServerID        string       `json:"server_id"`
	MetricType      string       `json:"metric_type"`      // "cpu", "ram", "disk"
	Operator        string       `json:"operator"`         // ">", "<"
	Threshold       float64      `json:"threshold"`        // e.g. 90.0
	DurationMinutes int          `json:"duration_minutes"` // e.g. 5
	RecipientEmail  string       `json:"recipient_email"`
	IsActive        bool         `json:"is_active"`
	LastTriggered   sql.NullTime `json:"last_triggered"`
}

type MonitoredProcess struct {
	ID          int    `json:"id"`
	ServerID    string `json:"server_id"`
	ProcessName string `json:"process_name"`
	ProcessPID  int    `json:"process_pid"`
	CommandLine string `json:"command_line"`
}

type MonitoredApplication struct {
	ID              int    `json:"id"`
	ServerID        string `json:"server_id"`
	ApplicationName string `json:"application_name"`
}

func initDatabase() {
	dbHost := os.Getenv("DB_HOST")
	if dbHost == "" {
		dbHost = "localhost"
	}
	dbPort := os.Getenv("DB_PORT")
	if dbPort == "" {
		dbPort = "5432"
	}
	dbUser := os.Getenv("POSTGRES_USER")
	dbPassword := os.Getenv("POSTGRES_PASSWORD")
	dbName := os.Getenv("POSTGRES_DB")

	if dbUser == "" {
		dbUser = "postgres"
	}
	if dbPassword == "" {
		dbPassword = "postgrespassword"
	}
	if dbName == "" {
		dbName = "cluster_monitor"
	}

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	var err error
	for i := 0; i < 15; i++ {
		log.Printf("Connecting to PostgreSQL (attempt %d/15)...", i+1)
		db, err = sql.Open("postgres", connStr)
		if err == nil {
			err = db.Ping()
			if err == nil {
				log.Println("Successfully connected to PostgreSQL database!")
				break
			}
		}
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		log.Fatalf("Could not connect to database: %v", err)
	}

	// Create tables according to implementation_plan.md
	createTablesQueries := []string{
		`CREATE TABLE IF NOT EXISTS servers (
			id UUID PRIMARY KEY,
			hostname VARCHAR(255) NOT NULL,
			ip_address VARCHAR(45) NOT NULL,
			os_family VARCHAR(50) NOT NULL,
			agent_token VARCHAR(255) NOT NULL,
			ssh_user VARCHAR(255),
			ssh_key TEXT,
			ssh_port INTEGER DEFAULT 22,
			status VARCHAR(50) DEFAULT 'unknown',
			last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS monitored_services (
			id SERIAL PRIMARY KEY,
			server_id UUID NOT NULL,
			service_name VARCHAR(255) NOT NULL,
			is_tracked BOOLEAN DEFAULT TRUE,
			FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE,
			CONSTRAINT unique_server_service UNIQUE(server_id, service_name)
		);`,
		`CREATE TABLE IF NOT EXISTS alert_rules (
			id SERIAL PRIMARY KEY,
			server_id UUID NOT NULL,
			metric_type VARCHAR(50) NOT NULL,
			operator VARCHAR(5) DEFAULT '>',
			threshold REAL NOT NULL,
			duration_minutes INTEGER DEFAULT 5,
			recipient_email VARCHAR(255) NOT NULL,
			is_active BOOLEAN DEFAULT TRUE,
			last_triggered TIMESTAMP,
			FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS recently_viewed (
			id SERIAL PRIMARY KEY,
			server_id UUID NOT NULL,
			viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS monitored_processes (
			id SERIAL PRIMARY KEY,
			server_id UUID NOT NULL,
			process_name VARCHAR(255) NOT NULL,
			process_pid INTEGER,
			command_line TEXT,
			FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE,
			CONSTRAINT unique_server_process UNIQUE(server_id, process_name, process_pid)
		);`,
		`CREATE TABLE IF NOT EXISTS monitored_applications (
			id SERIAL PRIMARY KEY,
			server_id UUID NOT NULL,
			application_name VARCHAR(255) NOT NULL,
			FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE,
			CONSTRAINT unique_server_application UNIQUE(server_id, application_name)
		);`,
	}

	for _, query := range createTablesQueries {
		_, err := db.Exec(query)
		if err != nil {
			log.Fatalf("Error executing table creation query: %v", err)
		}
	}

	// Migration: add SSH columns to existing servers tables (idempotent).
	migrationQueries := []string{
		`ALTER TABLE servers ADD COLUMN IF NOT EXISTS ssh_user VARCHAR(255);`,
		`ALTER TABLE servers ADD COLUMN IF NOT EXISTS ssh_key TEXT;`,
		`ALTER TABLE servers ADD COLUMN IF NOT EXISTS ssh_password TEXT;`,
		`ALTER TABLE servers ADD COLUMN IF NOT EXISTS ssh_port INTEGER DEFAULT 22;`,
		`CREATE TABLE IF NOT EXISTS metrics_history (
			id SERIAL PRIMARY KEY,
			server_id UUID NOT NULL,
			sampled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			cpu REAL,
			ram_used_pct REAL,
			ram_used_gb REAL,
			ram_total_gb REAL,
			swap_used_pct REAL,
			swap_used_gb REAL,
			swap_total_gb REAL,
			disk_used_pct REAL,
			disk_used_gb REAL,
			disk_total_gb REAL,
			net_rx_kb REAL,
			net_tx_kb REAL,
			FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_metrics_history_server_time ON metrics_history(server_id, sampled_at);`,
		`CREATE INDEX IF NOT EXISTS idx_monitored_services_server_id ON monitored_services(server_id);`,
		`CREATE INDEX IF NOT EXISTS idx_alert_rules_server_id ON alert_rules(server_id);`,
		`CREATE INDEX IF NOT EXISTS idx_servers_status ON servers(status);`,
	}
	for _, q := range migrationQueries {
		if _, err := db.Exec(q); err != nil {
			log.Printf("Migration notice (servers ssh columns & indexes): %v", err)
		}
	}

	log.Println("Database schema successfully initialized.")

	// Purge old demo server if present
	_, _ = db.Exec("DELETE FROM monitored_processes WHERE server_id = '11111111-1111-1111-1111-111111111111'")
	_, _ = db.Exec("DELETE FROM monitored_applications WHERE server_id = '11111111-1111-1111-1111-111111111111'")
	_, _ = db.Exec("DELETE FROM alert_rules WHERE server_id = '11111111-1111-1111-1111-111111111111'")
	_, _ = db.Exec("DELETE FROM recently_viewed WHERE server_id = '11111111-1111-1111-1111-111111111111'")
	_, _ = db.Exec("DELETE FROM servers WHERE id = '11111111-1111-1111-1111-111111111111'")

	// Always ensure permanent Localhost server node exists
	localhostID := "00000000-0000-0000-0000-000000000001"
	var exists int
	err = db.QueryRow("SELECT COUNT(*) FROM servers WHERE id = $1", localhostID).Scan(&exists)
	if err == nil && exists == 0 {
		hostName := "Localhost Node"
		if hn, hnErr := os.Hostname(); hnErr == nil && hn != "" {
			hostName = fmt.Sprintf("Localhost (%s)", hn)
		}
		_, err = db.Exec("INSERT INTO servers (id, hostname, ip_address, os_family, agent_token, status, last_seen) VALUES ($1, $2, '127.0.0.1', 'linux', 'localhost_token', 'online', NOW())",
			localhostID, hostName)
		if err == nil {
			log.Println("Initialized permanent Localhost server node.")
		}
	} else {
		// Keep status online and update last_seen for Localhost node
		_, _ = db.Exec("UPDATE servers SET status = 'online', last_seen = NOW() WHERE id = $1", localhostID)
	}
}

// 1. Server Registration API
func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Hostname    string `json:"hostname"`
		IPAddress   string `json:"ip_address"`
		OSFamily    string `json:"os_family"`
		AgentToken  string `json:"agent_token"`
		SSHUser     string `json:"ssh_user"`
		SSHKey      string `json:"ssh_key"`
		SSHPassword string `json:"ssh_password"`
		SSHPort     int    `json:"ssh_port"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid Request JSON", http.StatusBadRequest)
		return
	}

	if payload.Hostname == "" || payload.IPAddress == "" || payload.OSFamily == "" {
		http.Error(w, "Missing required fields (hostname, ip_address, os_family)", http.StatusBadRequest)
		return
	}

	// SSH credentials are mandatory: the Host must be able to reach the target
	// over SSH to install the agent and manage its endpoint. Password OR key is accepted.
	if payload.SSHUser == "" || (strings.TrimSpace(payload.SSHKey) == "" && strings.TrimSpace(payload.SSHPassword) == "") {
		http.Error(w, "SSH credentials required: ssh_user and (ssh_key or ssh_password) must be provided to register a server", http.StatusBadRequest)
		return
	}

	// Clean inputs
	payload.Hostname = strings.TrimSpace(payload.Hostname)
	payload.IPAddress = strings.TrimSpace(payload.IPAddress)
	payload.OSFamily = strings.ToLower(strings.TrimSpace(payload.OSFamily))
	payload.AgentToken = strings.TrimSpace(payload.AgentToken)
	payload.SSHUser = strings.TrimSpace(payload.SSHUser)
	payload.SSHKey = strings.TrimSpace(payload.SSHKey)
	payload.SSHPassword = strings.TrimSpace(payload.SSHPassword)
	if payload.SSHPort == 0 {
		payload.SSHPort = 22
	}

	// Check if already registered
	var existingID string
	err := db.QueryRow("SELECT id FROM servers WHERE hostname = $1", payload.Hostname).Scan(&existingID)
	if err == nil {
		// Update existing server details
		_, err = db.Exec("UPDATE servers SET ip_address = $1, os_family = $2, agent_token = COALESCE(NULLIF($3,''), agent_token), ssh_user = $4, ssh_key = $5, ssh_password = $6, ssh_port = $7, last_seen = NOW(), status = 'online' WHERE id = $8",
			payload.IPAddress, payload.OSFamily, payload.AgentToken, payload.SSHUser, payload.SSHKey, payload.SSHPassword, payload.SSHPort, existingID)
		if err != nil {
			http.Error(w, "Failed to update server info", http.StatusInternalServerError)
			return
		}

	// Hybrid: (re)install agent + register Host endpoint over SSH (best-effort,
	// run async so registration never blocks on a slow/failing SSH handshake).
	go bootstrapAgentOverSSH(existingID, payload.IPAddress, payload.OSFamily, payload.SSHUser, payload.SSHPassword, payload.SSHKey, payload.SSHPort)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "updated",
		"id":      existingID,
		"message": "Server metrics, configurations, and SSH credentials updated.",
	})
	return
}

	// Generate UUID
	serverID := uuid.New().String()

	_, err = db.Exec("INSERT INTO servers (id, hostname, ip_address, os_family, agent_token, ssh_user, ssh_key, ssh_password, ssh_port, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'online')",
		serverID, payload.Hostname, payload.IPAddress, payload.OSFamily, payload.AgentToken, payload.SSHUser, payload.SSHKey, payload.SSHPassword, payload.SSHPort)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to register server: %v", err), http.StatusInternalServerError)
		return
	}

	// Hybrid: install agent + register Host endpoint over SSH (best-effort,
	// run async so registration never blocks on a slow/failing SSH handshake).
	go bootstrapAgentOverSSH(serverID, payload.IPAddress, payload.OSFamily, payload.SSHUser, payload.SSHPassword, payload.SSHKey, payload.SSHPort)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":      "registered",
		"id":          serverID,
		"agent_token": payload.AgentToken,
	})
}

// bootstrapAgentOverSSH installs the tiny target agent (1-2 files) over SSH and
// registers the Host as a push endpoint. Best-effort: failures are logged, not fatal,
// since the SSH-pull path continues to work regardless.
func bootstrapAgentOverSSH(serverID, host, osFamily, user, password, key string, port int) {
	if host == "127.0.0.1" || host == "localhost" || serverID == "11111111-1111-1111-1111-111111111111" {
		return // demo server: no agent install
	}
	info := serverSSHInfo{ServerID: serverID, User: user, Password: password, Key: key, Host: host, Port: port, OSFamily: osFamily}
	if err := sshInstallAgent(info, serverID); err != nil {
		log.Printf("[agent-bootstrap] install failed for %s: %v (SSH-pull still available)", host, err)
		return
	}
	if err := sshAgentAddEndpoint(info, hostEndpoint); err != nil {
		log.Printf("[agent-bootstrap] add-endpoint failed for %s: %v", host, err)
	}
}

// Unregister Server API
func handleUnregisterServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	serverID := strings.TrimSpace(r.URL.Query().Get("id"))
	if serverID == "" {
		http.Error(w, "Missing 'id' query parameter", http.StatusBadRequest)
		return
	}

	// Capture SSH info before deletion so we can tell the agent to drop the Host endpoint.
	sshInfo, sshErr := loadServerSSHInfo(serverID)

	// Delete associated records first to prevent foreign key constraint violations
	_, _ = db.Exec("DELETE FROM monitored_processes WHERE server_id = $1", serverID)
	_, _ = db.Exec("DELETE FROM monitored_applications WHERE server_id = $1", serverID)
	_, _ = db.Exec("DELETE FROM alert_rules WHERE server_id = $1", serverID)
	_, _ = db.Exec("DELETE FROM recently_viewed WHERE server_id = $1", serverID)
	_, _ = db.Exec("DELETE FROM server_history WHERE server_id = $1", serverID)

	// Delete from servers catalog
	res, err := db.Exec("DELETE FROM servers WHERE id = $1", serverID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete server: %v", err), http.StatusInternalServerError)
		return
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if rowsAffected == 0 {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Hybrid: remove Host endpoint from the target agent asynchronously so SSH timeout never blocks HTTP response
	if sshErr == nil && sshInfo.Host != "127.0.0.1" && sshInfo.Host != "localhost" {
		go func(info serverSSHInfo, ep string) {
			if err := sshAgentRemoveEndpoint(info, ep); err != nil {
				log.Printf("[agent-bootstrap] remove-endpoint failed for %s: %v", info.Host, err)
			}
		}(sshInfo, hostEndpoint)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "unregistered",
		"id":      serverID,
		"message": "Server successfully unregistered. Agent endpoint removed (agent left running).",
	})
}

// 2. Server List API (Sidebar & Main Page Overview)
func handleGetServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	rows, err := db.Query("SELECT id, hostname, ip_address, os_family, status, last_seen, created_at FROM servers ORDER BY hostname ASC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	servers := []Server{}
	for rows.Next() {
		var s Server
		if err := rows.Scan(&s.ID, &s.Hostname, &s.IPAddress, &s.OSFamily, &s.Status, &s.LastSeen, &s.CreatedAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Evaluate online/offline state dynamically based on last seen heartbeat (threshold: 90 seconds)
		if time.Since(s.LastSeen) > 90*time.Second {
			s.Status = "offline"
			_, _ = db.Exec("UPDATE servers SET status = 'offline' WHERE id = $1 AND status != 'offline'", s.ID)
		}
		servers = append(servers, s)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(servers)
}

// 3. Recently Viewed / Active Servers List
func handleGetActiveServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	query := `
		SELECT s.id, s.hostname, s.ip_address, s.os_family, s.status, s.last_seen, s.created_at
		FROM servers s
		LEFT JOIN (
			SELECT server_id, MAX(viewed_at) as last_viewed
			FROM recently_viewed
			GROUP BY server_id
		) r ON s.id = r.server_id
		WHERE s.status = 'online' AND s.last_seen >= NOW() - INTERVAL '90 seconds'
		ORDER BY COALESCE(r.last_viewed, '1970-01-01'::timestamp) DESC, s.last_seen DESC
		LIMIT 6`

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	servers := []Server{}
	for rows.Next() {
		var s Server
		if err := rows.Scan(&s.ID, &s.Hostname, &s.IPAddress, &s.OSFamily, &s.Status, &s.LastSeen, &s.CreatedAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if time.Since(s.LastSeen) > 90*time.Second {
			s.Status = "offline"
			continue // Exclude inactive servers
		}
		servers = append(servers, s)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(servers)
}

// 4. Server Details Proxy API (Queries metrics from Prometheus & logs from Loki)
func handleServerDetail(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/servers/detail/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 1 || parts[0] == "" {
		http.Error(w, "Invalid URL path", http.StatusBadRequest)
		return
	}
	serverID := parts[0]
	if !uuidRegex.MatchString(serverID) {
		http.Error(w, "Invalid UUID format", http.StatusBadRequest)
		return
	}

	var subPath string
	if len(parts) >= 2 {
		subPath = parts[1]
		if idx := strings.Index(subPath, "?"); idx != -1 {
			subPath = subPath[:idx]
		}
		subPath = strings.TrimSuffix(subPath, "/")
	}

	// Route POST handlers before GET check
	if subPath == "docker-run" || subPath == "container-action" {
		if subPath == "docker-run" {
			handleDockerRun(w, r, serverID)
		} else {
			handleContainerActionProxy(w, r, serverID)
		}
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Route processes request: /api/servers/detail/:id/processes
	if subPath == "processes" {
		handleGetProcessesProxy(w, r, serverID)
		return
	}

	// Route metrics request: /api/servers/detail/:id/metrics
	if subPath == "metrics" {
		handleGetMetrics(w, r, serverID)
		return
	}

	// Route containers request: /api/servers/detail/:id/containers
	if subPath == "containers" {
		handleGetContainersProxy(w, r, serverID)
		return
	}

	// Route systemlogs request: /api/servers/detail/:id/systemlogs
	if subPath == "systemlogs" {
		handleGetSystemLogsProxy(w, r, serverID)
		return
	}

	// Route networks request: /api/servers/detail/:id/networks
	if subPath == "networks" {
		handleGetNetworksProxy(w, r, serverID)
		return
	}

	// Route history request: /api/servers/detail/:id/history
	if subPath == "history" {
		handleGetHistory(w, r, serverID)
		return
	}

	// Route storage request: /api/servers/detail/:id/storage
	if subPath == "storage" {
		handleGetStorage(w, r, serverID)
		return
	}

	// Route docker-info request: /api/servers/detail/:id/docker-info
	if subPath == "docker-info" {
		handleGetDockerInfo(w, r, serverID)
		return
	}

	// Route network-connections request: /api/servers/detail/:id/network-connections
	if subPath == "network-connections" {
		handleGetNetworkConnections(w, r, serverID)
		return
	}

	// Fetch server info
	var s Server
	err := db.QueryRow("SELECT id, hostname, ip_address, os_family, status, last_seen FROM servers WHERE id = $1", serverID).Scan(
		&s.ID, &s.Hostname, &s.IPAddress, &s.OSFamily, &s.Status, &s.LastSeen)
	if err == sql.ErrNoRows {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update recently viewed log
	db.Exec("INSERT INTO recently_viewed (server_id) VALUES ($1)", s.ID)

	// Fetch tracked services list
	rows, err := db.Query("SELECT service_name, is_tracked FROM monitored_services WHERE server_id = $1", s.ID)
	services := make(map[string]bool)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name string
			var tracked bool
			if errScan := rows.Scan(&name, &tracked); errScan == nil {
				services[name] = tracked
			}
		}
	}

	// Return server specs + configuration states
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"server":             s,
		"monitored_services": services,
	})
}

// Helper to perform HTTP requests to Go Agent with localhost fallback
// Proxy function to query active processes list from remote server over SSH



func handleGetProcessesProxy(w http.ResponseWriter, r *http.Request, serverID string) {
	info, err := loadServerSSHInfo(serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cacheKey := "processes:" + serverID
	if val, ok := getCachedJSON(cacheKey); ok {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(val))
		return
	}

	if isDemoServer(info, serverID) {
		mockProcs := []map[string]interface{}{
			{"pid": "1", "name": "systemd", "user": "root", "cpu": "0.1", "mem": "12.4"},
			{"pid": "824", "name": "alloy", "user": "alloy", "cpu": "1.2", "mem": "64.8"},
			{"pid": "912", "name": "cluster-agent", "user": "root", "cpu": "0.5", "mem": "18.2"},
			{"pid": "1042", "name": "postgres", "user": "postgres", "cpu": "0.8", "mem": "142.1"},
			{"pid": "1205", "name": "nginx", "user": "nginx", "cpu": "0.2", "mem": "8.5"},
			{"pid": "1530", "name": "go-backend", "user": "root", "cpu": "2.4", "mem": "32.0"},
			{"pid": "2054", "name": "node_exporter", "user": "prometheus", "cpu": "0.4", "mem": "14.1"},
			{"pid": "2100", "name": "loki", "user": "loki", "cpu": "1.5", "mem": "98.3"},
		}
		setCachedJSON(cacheKey, mockProcs, 60)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockProcs)
		return
	}

	procs, err := sshGetProcesses(info)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-SSH-Unavailable", "1")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "SSH collection unavailable", "detail": err.Error()})
		return
	}
	setCachedJSON(cacheKey, procs, 60)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(procs)
}

func handleGetContainersProxy(w http.ResponseWriter, r *http.Request, serverID string) {
	info, err := loadServerSSHInfo(serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cacheKey := "containers:" + serverID
	if val, ok := getCachedJSON(cacheKey); ok {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(val))
		return
	}

	payload, err := sshGetContainers(info)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-SSH-Unavailable", "1")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "Docker query failed", "detail": err.Error()})
		return
	}
	setCachedJSON(cacheKey, payload, 60)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(payload)
}

func handleContainerActionProxy(w http.ResponseWriter, r *http.Request, serverID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	info, err := loadServerSSHInfo(serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// 1. Try direct HTTP to the target agent (/api/v1/container-action)
	if agentResp, dErr := doAgentPostRequest(info, "container-action", body); dErr == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write(agentResp)
		return
	}

	// 2. SSH fallback — parse action/target and run docker directly on the remote host
	var req struct {
		Action string `json:"action"`
		Target string `json:"target"`
		Dir    string `json:"dir"`
		Image  string `json:"image"`
	}
	if jErr := json.Unmarshal(body, &req); jErr != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	var dockerCmd string
	switch req.Action {
	case "start":
		dockerCmd = fmt.Sprintf("start %s", shellQuote(req.Target))
	case "stop":
		dockerCmd = fmt.Sprintf("stop %s", shellQuote(req.Target))
	case "pause":
		dockerCmd = fmt.Sprintf("pause %s", shellQuote(req.Target))
	case "unpause":
		dockerCmd = fmt.Sprintf("unpause %s", shellQuote(req.Target))
	case "restart":
		dockerCmd = fmt.Sprintf("restart %s", shellQuote(req.Target))
	case "remove":
		dockerCmd = fmt.Sprintf("rm -f %s", shellQuote(req.Target))
	case "logs":
		dockerCmd = fmt.Sprintf("logs --tail 300 --timestamps %s", shellQuote(req.Target))
	case "pull":
		dockerCmd = fmt.Sprintf("pull %s", shellQuote(req.Image))
	case "compose-up":
		dockerCmd = fmt.Sprintf("compose -f %s up -d", shellQuote(req.Dir+"/docker-compose.yml"))
	case "compose-down":
		dockerCmd = fmt.Sprintf("compose -f %s down", shellQuote(req.Dir+"/docker-compose.yml"))
	case "compose-rebuild":
		dockerCmd = fmt.Sprintf("compose -f %s up -d --build", shellQuote(req.Dir+"/docker-compose.yml"))
	case "compose-logs":
		if req.Target != "" {
			dockerCmd = fmt.Sprintf("compose -f %s logs --tail 200 --timestamps %s", shellQuote(req.Dir+"/docker-compose.yml"), shellQuote(req.Target))
		} else {
			dockerCmd = fmt.Sprintf("compose -f %s logs --tail 200 --timestamps", shellQuote(req.Dir+"/docker-compose.yml"))
		}
	default:
		http.Error(w, "Unknown action: "+req.Action, http.StatusBadRequest)
		return
	}

	out, sshErr := sshDockerRun(info, dockerCmd)
	w.Header().Set("Content-Type", "application/json")
	if sshErr != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": sshErr.Error(), "output": out})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "output": out})
}

// handleGetStorage returns disk/partition info via SSH.
func handleGetStorage(w http.ResponseWriter, r *http.Request, serverID string) {
	info, err := loadServerSSHInfo(serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cacheKey := "storage:" + serverID
	if val, ok := getCachedJSON(cacheKey); ok {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(val))
		return
	}

	if isDemoServer(info, serverID) {
		mockStorage := []map[string]interface{}{
			{"name": "sda1", "size": "80G", "type": "part", "fstype": "ext4", "mountpoint": "/", "model": "Demo Disk"},
			{"name": "sdb1", "size": "200G", "type": "part", "fstype": "ext4", "mountpoint": "/home", "model": ""},
		}
		setCachedJSON(cacheKey, mockStorage, 60)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockStorage)
		return
	}
	parts, err := sshGetStorage(info)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "SSH collection unavailable", "detail": err.Error()})
		return
	}
	setCachedJSON(cacheKey, parts, 60)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(parts)
}

// handleGetDockerInfo returns Docker version and images.
func handleGetDockerInfo(w http.ResponseWriter, r *http.Request, serverID string) {
	info, err := loadServerSSHInfo(serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if isDemoServer(info, serverID) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"available": true,
			"version":   map[string]string{"Server": "24.0.5"},
			"images": []map[string]interface{}{
				{"Repository": "postgres", "Tag": "15-alpine", "Size": "87.2MB"},
				{"Repository": "nginx", "Tag": "latest", "Size": "45.3MB"},
			},
		})
		return
	}
	dinfo, err := sshGetDockerInfo(info)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "SSH collection unavailable", "detail": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dinfo)
}

// handleDockerRun runs a docker command (start/stop/restart/logs/compose up/compose down).
func handleDockerRun(w http.ResponseWriter, r *http.Request, serverID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Action    string `json:"action"`
		Container string `json:"container"`
		Service   string `json:"service"`
		Dir       string `json:"dir"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	info, err := loadServerSSHInfo(serverID)
	if err != nil {
		http.Error(w, "Server not registered", http.StatusNotFound)
		return
	}
	if isDemoServer(info, serverID) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "output": "Demo: no real action taken"})
		return
	}
	var dockerCmd string
	switch req.Action {
	case "logs":
		dockerCmd = fmt.Sprintf("logs --tail 200 %s", shellQuote(req.Container))
	case "start":
		dockerCmd = fmt.Sprintf("start %s", shellQuote(req.Container))
	case "stop":
		dockerCmd = fmt.Sprintf("stop %s", shellQuote(req.Container))
	case "restart":
		dockerCmd = fmt.Sprintf("restart %s", shellQuote(req.Container))
	case "compose-up":
		dockerCmd = fmt.Sprintf("compose -f %s up -d", shellQuote(req.Dir+"/docker-compose.yml"))
	case "compose-down":
		dockerCmd = fmt.Sprintf("compose -f %s down", shellQuote(req.Dir+"/docker-compose.yml"))
	case "compose-rebuild":
		dockerCmd = fmt.Sprintf("compose -f %s up -d --build", shellQuote(req.Dir+"/docker-compose.yml"))
	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
		return
	}
	out, err := sshDockerRun(info, dockerCmd)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error(), "output": out})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "output": out})
}

// handleGetNetworkConnections returns active TCP/UDP connections.
func handleGetNetworkConnections(w http.ResponseWriter, r *http.Request, serverID string) {
	info, err := loadServerSSHInfo(serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if isDemoServer(info, serverID) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tcp": []map[string]string{{"local": "0.0.0.0:22", "remote": "0.0.0.0:0", "state": "LISTEN"}, {"local": "192.168.21.206:443", "remote": "10.0.0.1:54321", "state": "ESTABLISHED"}},
			"udp": []map[string]string{},
		})
		return
	}
	conns, err := sshGetNetworkConnections(info)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "SSH collection unavailable", "detail": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(conns)
}

func handleGetSystemLogsProxy(w http.ResponseWriter, r *http.Request, serverID string) {
	info, err := loadServerSSHInfo(serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if isDemoServer(info, serverID) {
		mockLogs := "Jul 20 09:40:01 local-agent systemd[1]: Starting systemd-tmpfiles-clean.service...\n" +
			"Jul 20 09:40:02 local-agent systemd[1]: Finished cleanup of Temporary Directories.\n" +
			"Jul 20 09:41:15 local-agent alloy[824]: TSDB remote-write: metrics successfully sent to Prometheus.\n" +
			"Jul 20 09:42:04 local-agent docker-daemon[1050]: Container fleet-backend status changed to UP.\n" +
			"Jul 20 09:43:52 local-agent sshd[4201]: Accepted publickey for user admin from 192.168.21.100 port 54890 ssh2\n" +
			"Jul 20 09:45:00 local-agent kernel: ext4: mounted filesystem with ordered data mode. Opts: (null)\n" +
			"Jul 20 09:46:12 local-agent systemd[1]: Starting Periodic Command Scheduler..."
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(mockLogs))
		return
	}

	logs, err := sshGetSystemLogs(info)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-SSH-Unavailable", "1")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "SSH collection unavailable", "detail": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(logs))
}

func handleGetNetworksProxy(w http.ResponseWriter, r *http.Request, serverID string) {
	info, err := loadServerSSHInfo(serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if isDemoServer(info, serverID) {
		mockNets := []map[string]interface{}{
			{"name": "lo", "ip": "127.0.0.1", "rxSpeed": "12 KB/s", "txSpeed": "12 KB/s", "rxTotal": "2.5 GB", "txTotal": "2.5 GB"},
			{"name": "eth0", "ip": "192.168.21.206", "rxSpeed": "1.2 MB/s", "txSpeed": "240 KB/s", "rxTotal": "142.6 GB", "txTotal": "38.4 GB"},
			{"name": "docker0", "ip": "172.17.0.1", "rxSpeed": "0 KB/s", "txSpeed": "0 KB/s", "rxTotal": "12.4 GB", "txTotal": "8.1 GB"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockNets)
		return
	}

	nets, err := sshGetNetworks(info)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-SSH-Unavailable", "1")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "SSH collection unavailable", "detail": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(nets)
}

func getLatestDBMetrics(serverID string) (map[string]interface{}, error) {
	var cpu, ramPct, ramUsed, ramTotal, swapPct, swapUsed, swapTotal, diskPct, diskUsed, diskTotal, rx, tx float64
	query := `
		SELECT cpu, ram_used_pct, ram_used_gb, ram_total_gb, swap_used_pct, swap_used_gb, swap_total_gb, disk_used_pct, disk_used_gb, disk_total_gb, net_rx_kb, net_tx_kb
		FROM metrics_history
		WHERE server_id = $1
		ORDER BY sampled_at DESC
		LIMIT 1`
	err := db.QueryRow(query, serverID).Scan(&cpu, &ramPct, &ramUsed, &ramTotal, &swapPct, &swapUsed, &swapTotal, &diskPct, &diskUsed, &diskTotal, &rx, &tx)
	if err != nil {
		return nil, err
	}
	
	// Reconstruct the metrics map structure expected by the frontend
	return map[string]interface{}{
		"cpu":           cpu,
		"ram_used_pct":  ramPct,
		"ram_used_gb":   ramUsed,
		"ram_total_gb":  ramTotal,
		"swap_used_pct": swapPct,
		"swap_used_gb":  swapUsed,
		"swap_total_gb": swapTotal,
		"disk_used_pct": diskPct,
		"disk_used_gb":  diskUsed,
		"disk_total_gb": diskTotal,
		"net_rx_kb":     rx,
		"net_tx_kb":     tx,
		"cores":         []float64{cpu}, // Fallback cores list
	}, nil
}

func handleGetMetrics(w http.ResponseWriter, r *http.Request, serverID string) {
	info, err := loadServerSSHInfo(serverID)
	if err != nil {
		http.Error(w, "Server not found", http.StatusNotFound)
		return
	}

	// Return cached metrics from Redis if present to keep Dashboard and Overview in sync
	if cached, ok := getCachedMetrics(serverID); ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cached)
		return
	}

	if isDemoServer(info, serverID) {
		// Mock metrics for the local demo server
		randVal := func(min, max float64) float64 {
			return min + float64(time.Now().UnixNano()%int64(max-min))
		}
		metrics := map[string]interface{}{
			"cpu":           randVal(15, 65),
			"ram_used_pct":  randVal(30, 70),
			"ram_used_gb":   8.0 * (randVal(30, 70) / 100.0),
			"ram_total_gb":  8.0,
			"swap_used_pct": randVal(5, 15),
			"swap_used_gb":  2.0 * (randVal(5, 15) / 100.0),
			"swap_total_gb": 2.0,
			"disk_used_pct": 48.0,
			"disk_used_gb":  250.0 * 0.48,
			"disk_total_gb": 250.0,
			"net_rx_kb":     randVal(10, 250),
			"net_tx_kb":     randVal(5, 80),
			"cores":         []float64{randVal(10, 80), randVal(10, 80), randVal(10, 80), randVal(10, 80)},
		}
		setCachedMetrics(serverID, metrics, 60)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metrics)
		return
	}

	metrics, err := sshGetMetrics(info)
	if err != nil {
		// Fallback: get the latest sample from PostgreSQL database (metrics_history table)
		log.Printf("[metrics-fallback] SSH/HTTP direct failed for %s, falling back to DB: %v", serverID, err)
		metrics, dbErr := getLatestDBMetrics(serverID)
		if dbErr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-SSH-Unavailable", "1")
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": "Metrics unavailable", "detail": fmt.Sprintf("Agent offline and no database history: %v (DB err: %v)", err, dbErr)})
			return
		}
		
		setCachedMetrics(serverID, metrics, 60)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metrics)
		return
	}

	// Update last_seen and status in the servers table since we successfully queried the agent
	_, _ = db.Exec("UPDATE servers SET status = 'online', last_seen = NOW() WHERE id = $1", serverID)

	// Persist a sample so the History tab has stored trends even without an agent push.
	if !isDemoServer(info, serverID) {
		persistMetricSample(serverID, metrics)
	}

	setCachedMetrics(serverID, metrics, 60)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// persistMetricSample writes a metrics snapshot into metrics_history.
func persistMetricSample(serverID string, m map[string]interface{}) {
	getF := func(k string) float64 {
		if v, ok := m[k].(float64); ok {
			return v
		}
		return 0
	}
	_, err := db.Exec(`INSERT INTO metrics_history
		(server_id, cpu, ram_used_pct, ram_used_gb, ram_total_gb, swap_used_pct, swap_used_gb, swap_total_gb, disk_used_pct, disk_used_gb, disk_total_gb, net_rx_kb, net_tx_kb)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		serverID, getF("cpu"), getF("ram_used_pct"), getF("ram_used_gb"), getF("ram_total_gb"),
		getF("swap_used_pct"), getF("swap_used_gb"), getF("swap_total_gb"),
		getF("disk_used_pct"), getF("disk_used_gb"), getF("disk_total_gb"),
		getF("net_rx_kb"), getF("net_tx_kb"))
	if err != nil {
		log.Printf("[history] persist sample failed for %s: %v", serverID, err)
	}
}

// handleTestSSH verifies SSH connectivity to a target using supplied credentials.
// POST { ip_address, ssh_user, ssh_key, ssh_port } -> { ok, error }
func handleTestSSH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var p struct {
		IPAddress  string `json:"ip_address"`
		SSHUser    string `json:"ssh_user"`
		SSHKey     string `json:"ssh_key"`
		SSHPassword string `json:"ssh_password"`
		SSHPort    int    `json:"ssh_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if p.IPAddress == "" || p.SSHUser == "" || (strings.TrimSpace(p.SSHKey) == "" && strings.TrimSpace(p.SSHPassword) == "") {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "ip_address, ssh_user and (ssh_key or ssh_password) are required"})
		return
	}
	if p.SSHPort == 0 {
		p.SSHPort = 22
	}

	info := serverSSHInfo{User: p.SSHUser, Password: p.SSHPassword, Key: p.SSHKey, Host: p.IPAddress, Port: p.SSHPort, OSFamily: "linux"}
	// Attempt to run a trivial command to prove auth + connectivity.
	out, err := runSSHCommand("test", info.User, info.Password, info.Key, info.Host, info.Port, "echo ok")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "output": strings.TrimSpace(out)})
}

// handleGetHistory returns stored time-series from metrics_history (fed by agent
// pushes and/or any stats collection). Supports ?limit= (default 200) and ?hours=.
func handleGetHistory(w http.ResponseWriter, r *http.Request, serverID string) {
	limit := 200
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 5000 {
			limit = v
		}
	}
	hours := r.URL.Query().Get("hours")
	var rows *sql.Rows
	var err error
	if hours != "" {
		rows, err = db.Query(
			`SELECT sampled_at, cpu, ram_used_pct, swap_used_pct, disk_used_pct, net_rx_kb, net_tx_kb
			 FROM metrics_history WHERE server_id=$1 AND sampled_at > NOW() - ($2 || ' hours')::interval
			 ORDER BY sampled_at ASC LIMIT $3`,
			serverID, hours, limit)
	} else {
		rows, err = db.Query(
			`SELECT sampled_at, cpu, ram_used_pct, swap_used_pct, disk_used_pct, net_rx_kb, net_tx_kb
			 FROM (SELECT sampled_at, cpu, ram_used_pct, swap_used_pct, disk_used_pct, net_rx_kb, net_tx_kb,
			              ROW_NUMBER() OVER (ORDER BY sampled_at DESC) rn
			       FROM metrics_history WHERE server_id=$1) t
			 WHERE rn <= $2 ORDER BY sampled_at ASC`,
			serverID, limit)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type point struct {
		Time         string  `json:"time"`
		CPU          float64 `json:"cpu"`
		RAMUsedPct   float64 `json:"ram_used_pct"`
		SwapUsedPct  float64 `json:"swap_used_pct"`
		DiskUsedPct  float64 `json:"disk_used_pct"`
		NetRxKB      float64 `json:"net_rx_kb"`
		NetTxKB      float64 `json:"net_tx_kb"`
	}
	var data []point
	for rows.Next() {
		var p point
		var t time.Time
		if err := rows.Scan(&t, &p.CPU, &p.RAMUsedPct, &p.SwapUsedPct, &p.DiskUsedPct, &p.NetRxKB, &p.NetTxKB); err != nil {
			continue
		}
		p.Time = t.Format(time.RFC3339)
		data = append(data, p)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"server_id": serverID, "points": data})
}

// 5. Monitored Services Toggle (Track/Ignore specific services)
func handleToggleService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	serverID := parts[4]
	if !uuidRegex.MatchString(serverID) {
		http.Error(w, "Invalid UUID", http.StatusBadRequest)
		return
	}

	var payload struct {
		Service   string `json:"service"`
		IsTracked bool   `json:"is_tracked"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if !serviceRegex.MatchString(payload.Service) {
		http.Error(w, "Invalid service name syntax", http.StatusBadRequest)
		return
	}

	query := `
		INSERT INTO monitored_services (server_id, service_name, is_tracked)
		VALUES ($1, $2, $3)
		ON CONFLICT (server_id, service_name)
		DO UPDATE SET is_tracked = EXCLUDED.is_tracked`

	_, err := db.Exec(query, serverID, payload.Service, payload.IsTracked)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}

// 6. Proxy Service Commands to Go Agent (Start, Stop, Restart)
func handleServiceControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	serverID := parts[4]
	if !uuidRegex.MatchString(serverID) {
		http.Error(w, "Invalid UUID", http.StatusBadRequest)
		return
	}

	var payload struct {
		Service string `json:"service"`
		Action  string `json:"action"` // start, stop, restart, status
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if !serviceRegex.MatchString(payload.Service) || !actionRegex.MatchString(payload.Action) {
		http.Error(w, "Invalid Service or Action parameters", http.StatusBadRequest)
		return
	}

	// Fetch server SSH credentials
	info, err := loadServerSSHInfo(serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if isDemoServer(info, serverID) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "success",
			"output": fmt.Sprintf("Service '%s' has successfully completed action '%s' on demo-server-01.", payload.Service, payload.Action),
		})
		return
	}

	result, err := sshServiceControl(info, payload.Service, payload.Action)
	if err != nil {
		sshError(w, fmt.Sprintf("Failed to control service over SSH at %s: %v", info.Host, err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// Proxy Kill Process Command to Go Agent
func handleKillProcessControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 6 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	serverID := parts[5]
	if !uuidRegex.MatchString(serverID) {
		http.Error(w, "Invalid UUID", http.StatusBadRequest)
		return
	}

	var payload struct {
		PID    string `json:"pid"`
		Signal string `json:"signal"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Validate PID
	pidClean := strings.TrimSpace(payload.PID)
	if pidClean == "" {
		http.Error(w, "PID is required", http.StatusBadRequest)
		return
	}
	for _, char := range pidClean {
		if char < '0' || char > '9' {
			http.Error(w, "Invalid PID format", http.StatusBadRequest)
			return
		}
	}

	signalClean := strings.ToLower(strings.TrimSpace(payload.Signal))
	if signalClean == "" {
		signalClean = "kill"
	}

	// Fetch server SSH credentials
	info, err := loadServerSSHInfo(serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if isDemoServer(info, serverID) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": fmt.Sprintf("Signal %s sent to PID %s on demo-server-01.", signalClean, pidClean),
		})
		return
	}

	result, err := sshKillProcess(info, pidClean, signalClean)
	if err != nil {
		sshError(w, fmt.Sprintf("Failed to kill process over SSH at %s: %v", info.Host, err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// Proxy Kill Application Command to Go Agent (by process name, all instances)
func handleKillApplicationControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 6 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	serverID := parts[5]
	if !uuidRegex.MatchString(serverID) {
		http.Error(w, "Invalid UUID", http.StatusBadRequest)
		return
	}

	var payload struct {
		Name   string `json:"name"`
		Signal string `json:"signal"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(payload.Name) == "" {
		http.Error(w, "Application name is required", http.StatusBadRequest)
		return
	}
	signalClean := strings.ToLower(strings.TrimSpace(payload.Signal))
	if signalClean == "" {
		signalClean = "kill"
	}

	info, err := loadServerSSHInfo(serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if isDemoServer(info, serverID) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": fmt.Sprintf("Signal %s sent to application '%s' on demo-server-01.", signalClean, payload.Name),
		})
		return
	}

	result, err := sshKillProcessByName(info, payload.Name, signalClean)
	if err != nil {
		sshError(w, fmt.Sprintf("Failed to signal application over SSH at %s: %v", info.Host, err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// 7. Alert Rules Configuration API
func handleAlertRules(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// List active alert rules
		rows, err := db.Query("SELECT id, server_id, metric_type, operator, threshold, duration_minutes, recipient_email, is_active FROM alert_rules")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		rules := []AlertRule{}
		for rows.Next() {
			var rule AlertRule
			if err := rows.Scan(&rule.ID, &rule.ServerID, &rule.MetricType, &rule.Operator, &rule.Threshold, &rule.DurationMinutes, &rule.RecipientEmail, &rule.IsActive); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			rules = append(rules, rule)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rules)
		return
	}

	if r.Method == http.MethodPost {
		// Create new alert rule
		var rule AlertRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		if !uuidRegex.MatchString(rule.ServerID) || rule.MetricType == "" || rule.RecipientEmail == "" {
			http.Error(w, "Invalid parameters", http.StatusBadRequest)
			return
		}

		query := `
			INSERT INTO alert_rules (server_id, metric_type, operator, threshold, duration_minutes, recipient_email, is_active)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`
		_, err := db.Exec(query, rule.ServerID, rule.MetricType, rule.Operator, rule.Threshold, rule.DurationMinutes, rule.RecipientEmail, rule.IsActive)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"status":"created"}`))
		return
	}

	if r.Method == http.MethodDelete {
		ruleID := r.URL.Query().Get("id")
		if ruleID == "" {
			http.Error(w, "Missing rule id", http.StatusBadRequest)
			return
		}
		_, err := db.Exec("DELETE FROM alert_rules WHERE id = $1", ruleID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"deleted"}`))
		return
	}

	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

// 8. Alerting engine loop
// Periodically evaluates user alert thresholds
func startAlertingLoop() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			rows, err := db.Query("SELECT id, server_id, metric_type, operator, threshold, duration_minutes, recipient_email, last_triggered FROM alert_rules WHERE is_active = TRUE")
			if err != nil {
				log.Printf("[AlertEngine] Error querying rules: %v", err)
				continue
			}

			var rules []AlertRule
			for rows.Next() {
				var rule AlertRule
				if scanErr := rows.Scan(&rule.ID, &rule.ServerID, &rule.MetricType, &rule.Operator, &rule.Threshold, &rule.DurationMinutes, &rule.RecipientEmail, &rule.LastTriggered); scanErr == nil {
					rules = append(rules, rule)
				}
			}
			rows.Close()

			var wg sync.WaitGroup
			for _, rule := range rules {
				// Don't alert more than once every 15 minutes to avoid spamming
				if rule.LastTriggered.Valid && time.Since(rule.LastTriggered.Time) < 15*time.Minute {
					continue
				}

				wg.Add(1)
				go func(r AlertRule) {
					defer wg.Done()
					evaluateAlertRule(r)
				}(rule)
			}
			wg.Wait()
		}
	}()
}

func evaluateAlertRule(rule AlertRule) {
	// Fetch target server SSH credentials
	info, err := loadServerSSHInfo(rule.ServerID)
	if err != nil {
		return
	}
	hostname := info.Host
	ipAddress := info.Host

	var val float64
	if isDemoServer(info, rule.ServerID) {
		// Demo server: synthesize a value near threshold occasionally
		val = rule.Threshold - 5.0
		_ = hostname
		_ = ipAddress
		// Force a benign value (no trigger) for the mock server
		val = rule.Threshold * 0.5
	} else {
		metrics, mErr := sshGetMetrics(info)
		if mErr != nil {
			log.Printf("[AlertEngine] Error gathering metrics over SSH for %s: %v", info.Host, mErr)
			return
		}
		switch rule.MetricType {
		case "cpu":
			if v, ok := metrics["cpu"].(float64); ok {
				val = v
			}
		case "ram":
			if v, ok := metrics["ram_used_pct"].(float64); ok {
				val = v
			}
		case "disk":
			if v, ok := metrics["disk_used_pct"].(float64); ok {
				val = v
			}
		default:
			return
		}
	}

	// Check threshold condition
	triggered := false
	if rule.Operator == ">" && val > rule.Threshold {
		triggered = true
	} else if rule.Operator == "<" && val < rule.Threshold {
		triggered = true
	}

	if triggered {
		log.Printf("[ALERT TRIGGERED] Server %s (%s) crossed %s threshold: current=%.2f%%, limit=%.2f%%",
			hostname, ipAddress, rule.MetricType, val, rule.Threshold)

		sendAlertEmail(rule, hostname, ipAddress, val)

		// Update last_triggered time
		db.Exec("UPDATE alert_rules SET last_triggered = NOW() WHERE id = $1", rule.ID)
	}
}

func sendAlertEmail(rule AlertRule, hostname, ipAddress string, currentValue float64) {
	recipient := strings.TrimSpace(rule.RecipientEmail)
	if recipient == "" {
		log.Printf("[AlertEngine] No recipient email configured for rule %s", rule.ID)
		return
	}

	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	if smtpPort == "" {
		smtpPort = "587"
	}
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASSWORD")
	if smtpPass == "" {
		smtpPass = os.Getenv("SMTP_PASS")
	}
	fromEmail := os.Getenv("SMTP_FROM")
	if fromEmail == "" {
		fromEmail = smtpUser
	}
	if fromEmail == "" {
		fromEmail = "fleet-monitor@localhost"
	}

	subject := fmt.Sprintf("CRITICAL ALERT: %s on %s (%s)", strings.ToUpper(rule.MetricType), hostname, ipAddress)
	body := fmt.Sprintf(
		"From: Fleet Monitor <%s>\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: text/html; charset=UTF-8\r\n\r\n"+
			"<h2>🚨 Fleet Monitor Alert Triggered</h2>"+
			"<p><strong>Server:</strong> %s (%s)</p>"+
			"<p><strong>Metric:</strong> %s</p>"+
			"<p><strong>Condition:</strong> Current value <strong>%.2f%%</strong> crossed threshold of <strong>%s %.2f%%</strong></p>"+
			"<p><strong>Triggered At:</strong> %s</p>"+
			"<hr><p style='font-size:12px; color:#888;'>This is an automated alert from Fleet Monitor.</p>",
		fromEmail, recipient, subject, hostname, ipAddress, strings.ToUpper(rule.MetricType), currentValue, rule.Operator, rule.Threshold, time.Now().Format(time.RFC1123),
	)

	log.Printf("[ALERT EMAIL] Preparing alert email for %s (%s crossed %.2f%%)", recipient, hostname, rule.MetricType, currentValue)

	if smtpHost == "" {
		log.Printf("[EMAIL SIMULATOR] (Configure SMTP_HOST, SMTP_USER, SMTP_PASSWORD to send live emails) -> TO: %s | SUBJECT: %s", recipient, subject)
		return
	}

	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
	addr := net.JoinHostPort(smtpHost, smtpPort)

	err := smtp.SendMail(addr, auth, fromEmail, []string{recipient}, []byte(body))
	if err != nil {
		log.Printf("[AlertEngine] Failed to send email to %s via %s: %v", recipient, addr, err)
	} else {
		log.Printf("[AlertEngine] Successfully sent alert email to %s via SMTP (%s)", recipient, smtpHost)
	}
}

// Handle monitored processes - GET and POST
func handleMonitoredProcesses(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		serverID := r.URL.Query().Get("server_id")
		if serverID == "" {
			http.Error(w, "server_id parameter required", http.StatusBadRequest)
			return
		}

		rows, err := db.Query("SELECT id, server_id, process_name, process_pid, command_line FROM monitored_processes WHERE server_id = $1", serverID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		processes := []MonitoredProcess{}
		for rows.Next() {
			var p MonitoredProcess
			err := rows.Scan(&p.ID, &p.ServerID, &p.ProcessName, &p.ProcessPID, &p.CommandLine)
			if err != nil {
				continue
			}
			processes = append(processes, p)
		}

		json.NewEncoder(w).Encode(processes)
	} else if r.Method == http.MethodPost {
		var payload struct {
			ServerID  string `json:"server_id"`
			Processes []struct {
				ProcessName string `json:"process_name"`
				ProcessPID  int    `json:"process_pid"`
				CommandLine string `json:"command_line"`
			} `json:"processes"`
		}

		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Clear existing monitored processes for this server
		_, err := db.Exec("DELETE FROM monitored_processes WHERE server_id = $1", payload.ServerID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Insert new monitored processes
		for _, proc := range payload.Processes {
			_, err := db.Exec("INSERT INTO monitored_processes (server_id, process_name, process_pid, command_line) VALUES ($1, $2, $3, $4) ON CONFLICT (server_id, process_name, process_pid) DO UPDATE SET command_line = EXCLUDED.command_line",
				payload.ServerID, proc.ProcessName, proc.ProcessPID, proc.CommandLine)
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to save monitored process '%s': %v", proc.ProcessName, err), http.StatusInternalServerError)
				return
			}
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// Handle monitored applications - GET and POST
func handleMonitoredApplications(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		serverID := r.URL.Query().Get("server_id")
		if serverID == "" {
			http.Error(w, "server_id parameter required", http.StatusBadRequest)
			return
		}

		rows, err := db.Query("SELECT id, server_id, application_name FROM monitored_applications WHERE server_id = $1", serverID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		applications := []MonitoredApplication{}
		for rows.Next() {
			var app MonitoredApplication
			err := rows.Scan(&app.ID, &app.ServerID, &app.ApplicationName)
			if err != nil {
				continue
			}
			applications = append(applications, app)
		}

		json.NewEncoder(w).Encode(applications)
	} else if r.Method == http.MethodPost {
		var payload struct {
			ServerID     string   `json:"server_id"`
			Applications []string `json:"applications"`
		}

		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Clear existing monitored applications for this server
		_, err := db.Exec("DELETE FROM monitored_applications WHERE server_id = $1", payload.ServerID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Insert new monitored applications
		for _, appName := range payload.Applications {
			_, err := db.Exec("INSERT INTO monitored_applications (server_id, application_name) VALUES ($1, $2) ON CONFLICT (server_id, application_name) DO NOTHING",
				payload.ServerID, appName)
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to save monitored application '%s': %v", appName, err), http.StatusInternalServerError)
				return
			}
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/index.html")
}

// handleAgentIngest receives metrics pushed by a target agent (hybrid push path).
// Route: POST /api/ingest/{serverID}/metrics
func handleAgentIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	// Path: /api/ingest/{serverID}/metrics
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid ingest path", http.StatusBadRequest)
		return
	}
	serverID := parts[2]
	if _, err := uuid.Parse(serverID); err != nil {
		http.Error(w, "Invalid server ID", http.StatusBadRequest)
		return
	}

	var m struct {
		CPU         float64 `json:"cpu"`
		RAMUsedPct  float64 `json:"ram_used_pct"`
		RAMUsedGB   float64 `json:"ram_used_gb"`
		RAMTotalGB  float64 `json:"ram_total_gb"`
		SwapUsedPct float64 `json:"swap_used_pct"`
		SwapUsedGB  float64 `json:"swap_used_gb"`
		SwapTotalGB float64 `json:"swap_total_gb"`
		DiskUsedPct float64 `json:"disk_used_pct"`
		DiskUsedGB  float64 `json:"disk_used_gb"`
		DiskTotalGB float64 `json:"disk_total_gb"`
		NetRxKB     float64 `json:"net_rx_kb"`
		NetTxKB     float64 `json:"net_tx_kb"`
	}
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Verify the server exists.
	var exists bool
	if err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM servers WHERE id=$1)", serverID).Scan(&exists); err != nil || !exists {
		http.Error(w, "Unknown server", http.StatusNotFound)
		return
	}

	_, err := db.Exec(`INSERT INTO metrics_history
		(server_id, cpu, ram_used_pct, ram_used_gb, ram_total_gb, swap_used_pct, swap_used_gb, swap_total_gb, disk_used_pct, disk_used_gb, disk_total_gb, net_rx_kb, net_tx_kb)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		serverID, m.CPU, m.RAMUsedPct, m.RAMUsedGB, m.RAMTotalGB, m.SwapUsedPct, m.SwapUsedGB, m.SwapTotalGB,
		m.DiskUsedPct, m.DiskUsedGB, m.DiskTotalGB, m.NetRxKB, m.NetTxKB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update last_seen and status in the servers table
	_, _ = db.Exec("UPDATE servers SET status = 'online', last_seen = NOW() WHERE id = $1", serverID)

	setCachedMetrics(serverID, map[string]interface{}{
		"cpu":           m.CPU,
		"ram_used_pct":  m.RAMUsedPct,
		"ram_used_gb":   m.RAMUsedGB,
		"ram_total_gb":  m.RAMTotalGB,
		"swap_used_pct": m.SwapUsedPct,
		"swap_used_gb":  m.SwapUsedGB,
		"swap_total_gb": m.SwapTotalGB,
		"disk_used_pct": m.DiskUsedPct,
		"disk_used_gb":  m.DiskUsedGB,
		"disk_total_gb": m.DiskTotalGB,
		"net_rx_kb":     m.NetRxKB,
		"net_tx_kb":     m.NetTxKB,
	}, 3)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"stored"}`))
}

// detectHostIP picks the best address for agents to push metrics to.
// Inside Docker, host.docker.internal resolves to the host but that's only
// reachable from within Docker containers, not from remote LAN servers.
// We prefer actual LAN IPs (192.168.x.x, 10.x.x.x) so remote targets can reach us.
func detectHostIP() string {
	// Check host.docker.internal first — gives us the docker host IP.
	// But prefer the result only if it's a routable LAN address, not a docker bridge.
	if addrs, err := net.LookupHost("host.docker.internal"); err == nil {
		for _, addr := range addrs {
			if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil && !isDockerBridgeIP(ip) {
				return ip.String()
			}
		}
	}
	// Scan interface addresses for the best routable LAN IP.
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				if ipnet, ok := addr.(*net.IPNet); ok {
					ip = ipnet.IP
				}
				if ip == nil || ip.IsLoopback() || ip.To4() == nil {
					continue
				}
				if isDockerBridgeIP(ip) {
					continue // skip docker bridge IPs
				}
				return ip.String()
			}
		}
	}
	// Last resort: any non-loopback IPv4
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "0.0.0.0"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return "0.0.0.0"
}

// isDockerBridgeIP returns true for IPs in docker's default bridge ranges
// (172.16.0.0/12) which are only reachable within the docker host.
func isDockerBridgeIP(ip net.IP) bool {
	_, docker0, _ := net.ParseCIDR("172.16.0.0/12")
	return docker0 != nil && docker0.Contains(ip)
}

// writeHostEndpointToEnv writes HOST_ENDPOINT into the nearest .env file so
// docker-compose doesn't warn about the variable being blank on next start.
func writeHostEndpointToEnv(endpoint string) {
	// Search for .env relative to cwd or parent directories (typical compose layout)
	envPaths := []string{".env", "../.env", "../../.env"}
	for _, p := range envPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		found := false
		for i, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "HOST_ENDPOINT=") ||
				strings.HasPrefix(strings.TrimSpace(line), "# HOST_ENDPOINT") {
				lines[i] = "HOST_ENDPOINT=" + endpoint
				found = true
			}
		}
		if !found {
			lines = append(lines, "HOST_ENDPOINT="+endpoint)
		}
		_ = os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0644)
		log.Printf("[env] wrote HOST_ENDPOINT=%s to %s", endpoint, p)
		return
	}
}

// endpointBroadcastLoop periodically registers the host endpoint with every
// registered target agent so they all know where to push metrics even when host IP changes.
func endpointBroadcastLoop() {
	register := func() {
		rows, err := db.Query(`
			SELECT id, ip_address, COALESCE(ssh_user,''), COALESCE(ssh_key,''), COALESCE(ssh_password,''), COALESCE(ssh_port,22)
			FROM servers`)
		if err != nil {
			log.Printf("[endpoint-broadcast] query error: %v", err)
			return
		}
		defer rows.Close()
		client := &http.Client{Timeout: 3 * time.Second}
		payload := fmt.Sprintf(`{"action":"add","url":%q}`, hostEndpoint)
		for rows.Next() {
			var info serverSSHInfo
			if err := rows.Scan(&info.ServerID, &info.Host, &info.User, &info.Key, &info.Password, &info.Port); err != nil {
				log.Printf("[endpoint-broadcast] scan error for server: %v", err)
				continue
			}
			// Try agent HTTP directly
			hostsToTry := []string{info.Host}
			if isLocalHost(info) {
				hostsToTry = append(hostsToTry, "172.17.0.1", "host.docker.internal")
			}
			registered := false
			for _, h := range hostsToTry {
				url := fmt.Sprintf("http://%s:9192/api/v1/endpoint", h)
				resp, err := client.Post(url, "application/json", strings.NewReader(payload))
				if err == nil && resp.StatusCode == http.StatusOK {
					resp.Body.Close()
					registered = true
					log.Printf("[endpoint-broadcast] registered %s with %s via HTTP", hostEndpoint, h)
					break
				}
				if resp != nil {
					resp.Body.Close()
				}
			}
			if !registered && info.User != "" {
				// SSH fallback
				sshCmd := fmt.Sprintf(
					`curl -s -X POST -H 'Content-Type: application/json' -d '%s' http://localhost:9192/api/v1/endpoint`,
					strings.ReplaceAll(payload, "'", `'\''`),
				)
				_, errSSH := runSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, sshCmd)
				if errSSH == nil {
					log.Printf("[endpoint-broadcast] registered %s with %s via SSH fallback", hostEndpoint, info.Host)
				}
			}
		}
	}

	// Run immediately on startup then every 15 seconds
	register()
	ticker := time.NewTicker(15 * time.Second)
	for range ticker.C {
		register()
	}
}

func main() {
	initDatabase()
	defer db.Close()

	initRedis()
	startBackgroundWorkerPool()

	// Hybrid mode: the Host advertises its own endpoint URL so target agents
	// (installed over SSH on register) know where to push metrics.
	if ep := os.Getenv("HOST_ENDPOINT"); ep != "" {
		hostEndpoint = strings.TrimRight(ep, "/")
	} else {
		hostIP := detectHostIP()
		port := os.Getenv("PORT")
		if port == "" {
			port = "8081"
		}
		hostEndpoint = fmt.Sprintf("http://%s:%s", hostIP, port)
	}
	log.Printf("Hybrid mode: agents will push to %s", hostEndpoint)

	// Write detected endpoint back into .env so docker-compose doesn't warn on next run.
	writeHostEndpointToEnv(hostEndpoint)

	// Periodically re-register our endpoint with all online targets so they push metrics here.
	go endpointBroadcastLoop()

	if d := os.Getenv("AGENT_ASSETS_DIR"); d != "" {
		agentAssetsDir = d
	}
	// Bind address for the Host listener. Default :8080 (all interfaces).
	// For bare-metal, set HOST_BIND_ADDR to a specific LAN IP to avoid exposing
	// the ingest/push endpoint on public interfaces.
	if b := os.Getenv("HOST_BIND_ADDR"); b != "" {
		hostBindAddr = b
		if !strings.HasPrefix(hostBindAddr, ":") && !strings.Contains(hostBindAddr, ":") {
			hostBindAddr = ":" + hostBindAddr
		}
	}

	startAlertingLoop()

	// Static & API Routing
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/api/register", handleRegister)
	http.HandleFunc("/api/servers", handleGetServers)
	http.HandleFunc("/api/servers/active", handleGetActiveServers)
	http.HandleFunc("/api/servers/unregister", handleUnregisterServer)
	http.HandleFunc("/api/servers/detail/", handleServerDetail)
	http.HandleFunc("/api/servers/toggle/", handleToggleService)
	http.HandleFunc("/api/servers/control/", handleServiceControl)
	http.HandleFunc("/api/servers/control/kill/", handleKillProcessControl)
	http.HandleFunc("/api/servers/control/kill-by-name/", handleKillApplicationControl)
	http.HandleFunc("/api/alerts/rules", handleAlertRules)
	http.HandleFunc("/api/monitored/processes", handleMonitoredProcesses)
	http.HandleFunc("/api/monitored/applications", handleMonitoredApplications)
	http.HandleFunc("/api/ingest/", handleAgentIngest)
	http.HandleFunc("/api/servers/test-ssh", handleTestSSH)

	port := os.Getenv("PORT")
	if port == "" {
		port = ":8080"
	} else if !strings.HasPrefix(port, ":") {
		port = ":" + port
	}
	log.Printf("Starting Host Backend on %s%s...", hostBindAddr, port)
	if err := http.ListenAndServe(hostBindAddr+port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
