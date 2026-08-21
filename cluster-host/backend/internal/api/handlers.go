package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"cluster-backend/internal/config"
	"cluster-backend/internal/domain"
	"cluster-backend/internal/repository"
	"cluster-backend/internal/ssh"
	wsPkg "cluster-backend/internal/websocket"
)

var (
	uuidRegex    = regexp.MustCompile(`^[a-fA-F0-9\\-]{36}$`)
	actionRegex  = regexp.MustCompile(`^(start|stop|restart|status)$`)
	serviceRegex = regexp.MustCompile(`^[a-zA-Z0-9\\.\\-_]+$`)
)

type APIHandler struct {
	db     *sql.DB
	redis  *repository.RedisClient
	cfg    *config.Config
	encKey string
}

func NewAPIHandler(db *sql.DB, redis *repository.RedisClient, cfg *config.Config) *APIHandler {
	return &APIHandler{
		db:     db,
		redis:  redis,
		cfg:    cfg,
		encKey: cfg.EncryptionKey,
	}
}

func (h *APIHandler) HandleAgentSelfRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Hostname   string `json:"hostname"`
		IPAddress  string `json:"ip_address"`
		OSFamily   string `json:"os_family"`
		AgentToken string `json:"agent_token"` // optional: reuse existing token
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	payload.Hostname = strings.TrimSpace(payload.Hostname)
	payload.IPAddress = strings.TrimSpace(payload.IPAddress)
	payload.OSFamily = strings.ToLower(strings.TrimSpace(payload.OSFamily))
	if payload.Hostname == "" || payload.IPAddress == "" {
		http.Error(w, "hostname and ip_address are required", http.StatusBadRequest)
		return
	}
	if payload.OSFamily == "" {
		payload.OSFamily = "linux"
	}

	// Reuse existing server record if hostname matches
	var existingID, existingToken string
	err := h.db.QueryRow("SELECT id, COALESCE(agent_token,'') FROM servers WHERE hostname = $1", payload.Hostname).Scan(&existingID, &existingToken)
	if err == nil && existingID != "" {
		// Update IP / OS family, keep existing token
		token := existingToken
		if token == "" {
			token = uuid.New().String()
			_, _ = h.db.Exec("UPDATE servers SET agent_token = $1 WHERE id = $2", token, existingID)
		}
		_, _ = h.db.Exec("UPDATE servers SET ip_address = $1, os_family = $2, last_seen = NOW() WHERE id = $3",
			payload.IPAddress, payload.OSFamily, existingID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":      "updated",
			"id":          existingID,
			"agent_token": token,
		})
		return
	}

	// New server — generate credentials
	newID := uuid.New().String()
	token := payload.AgentToken
	if token == "" {
		token = uuid.New().String()
	}
	_, err = h.db.Exec("INSERT INTO servers (id, hostname, ip_address, os_family, agent_token, status) VALUES ($1, $2, $3, $4, $5, 'online')",
		newID, payload.Hostname, payload.IPAddress, payload.OSFamily, token)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to register: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":      "registered",
		"id":          newID,
		"agent_token": token,
	})
}

// 1. domain.Server Registration API
func (h *APIHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
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

	if payload.AgentToken == "" {
		var existingToken sql.NullString
		_ = h.db.QueryRow("SELECT agent_token FROM servers WHERE hostname = $1", payload.Hostname).Scan(&existingToken)
		if existingToken.Valid && existingToken.String != "" {
			payload.AgentToken = existingToken.String
		} else {
			payload.AgentToken = uuid.New().String()
		}
	}

	session, _ := h.getSession(r)
	var username string
	if session != nil {
		username = session.Username
	}

	// Check if already registered
	var existingID string
	err := h.db.QueryRow("SELECT id FROM servers WHERE hostname = $1", payload.Hostname).Scan(&existingID)
	if err == nil {
		// Update existing server details
		_, err = h.db.Exec("UPDATE servers SET ip_address = $1, os_family = $2, agent_token = COALESCE(NULLIF($3,''), agent_token), ssh_user = $4, ssh_key = $5, ssh_password = $6, ssh_port = $7, last_seen = NOW(), status = 'online' WHERE id = $8",
			payload.IPAddress, payload.OSFamily, payload.AgentToken, payload.SSHUser, payload.SSHKey, payload.SSHPassword, payload.SSHPort, existingID)
		if err != nil {
			http.Error(w, "Failed to update server info", http.StatusInternalServerError)
			return
		}

		if username != "" {
			_, _ = h.db.Exec("UPDATE servers SET owner_id = $1 WHERE id = $2 AND owner_id IS NULL", strings.ToLower(username), existingID)
			_, _ = h.db.Exec("INSERT INTO server_members (server_id, username, role) VALUES ($1, $2, 'admin') ON CONFLICT (server_id, username) DO UPDATE SET role = 'admin'", existingID, strings.ToLower(username))
		}

		// Hybrid: (re)install agent + register Host endpoint over SSH (best-effort,
		// run async so registration never blocks on a slow/failing SSH handshake).
		go h.bootstrapAgentOverSSH(existingID, payload.IPAddress, payload.OSFamily, payload.SSHUser, payload.SSHPassword, payload.SSHKey, payload.SSHPort)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "updated",
			"id":      existingID,
			"message": "domain.Server metrics, configurations, and SSH credentials updated.",
		})
		return
	}

	// Generate UUID
	serverID := uuid.New().String()

	var ownerParam interface{}
	if username != "" {
		ownerParam = username
	} else {
		ownerParam = nil
	}

	_, err = h.db.Exec("INSERT INTO servers (id, hostname, ip_address, os_family, agent_token, ssh_user, ssh_key, ssh_password, ssh_port, status, owner_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'online', $10)",
		serverID, payload.Hostname, payload.IPAddress, payload.OSFamily, payload.AgentToken, payload.SSHUser, payload.SSHKey, payload.SSHPassword, payload.SSHPort, ownerParam)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to register server: %v", err), http.StatusInternalServerError)
		return
	}

	if username != "" {
		_, _ = h.db.Exec("INSERT INTO server_members (server_id, username, role) VALUES ($1, $2, 'admin') ON CONFLICT (server_id, username) DO UPDATE SET role = 'admin'", serverID, strings.ToLower(username))
	}

	// Hybrid: install agent + register Host endpoint over SSH (best-effort,
	// run async so registration never blocks on a slow/failing SSH handshake).
	go h.bootstrapAgentOverSSH(serverID, payload.IPAddress, payload.OSFamily, payload.SSHUser, payload.SSHPassword, payload.SSHKey, payload.SSHPort)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":      "registered",
		"id":          serverID,
		"agent_token": payload.AgentToken,
	})
}

// h.bootstrapAgentOverSSH installs the tiny target agent (1-2 files) over SSH and
// registers the Host as a push endpoint. Best-effort: failures are logged, not fatal,
// since the SSH-pull path continues to work regardless.
func (h *APIHandler) bootstrapAgentOverSSH(serverID, host, osFamily, user, password, key string, port int) {
	if host == "127.0.0.1" || host == "localhost" || serverID == "11111111-1111-1111-1111-111111111111" {
		return // demo server: no agent install
	}
	info := ssh.ServerSSHInfo{ServerID: serverID, User: user, Password: password, Key: key, Host: host, Port: port, OSFamily: osFamily}
	// ssh.SSHInstallAgent now writes the endpoints file during install so the agent
	// starts with endpoints=1 and immediately connects to the Host WebSocket.
	if err := ssh.SSHInstallAgent(h.db, info, serverID, ssh.HostEndpoint); err != nil {
		log.Printf("[agent-bootstrap] install failed for %s: %v (SSH-pull still available)", host, err)
		return
	}
	log.Printf("[agent-bootstrap] agent installed on %s with endpoint %s", host, ssh.HostEndpoint)
}

// Unregister domain.Server API with Admin Safety & Self-Destruction
func (h *APIHandler) HandleUnregisterServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	serverID := strings.TrimSpace(r.URL.Query().Get("id"))
	if serverID == "" {
		http.Error(w, "Missing 'id' query parameter", http.StatusBadRequest)
		return
	}

	session, errSession := h.getSession(r)
	username := ""
	if errSession == nil && session != nil {
		username = session.Username
	}

	// 1. Must be admin to trigger unregister/leave flow
	allowed, _ := h.checkServerPermission(serverID, username, "admin")
	if !allowed {
		http.Error(w, "Forbidden: Only server admins can unregister or leave a server.", http.StatusForbidden)
		return
	}

	// Count other members
	var otherMembersCount int
	_ = h.db.QueryRow("SELECT COUNT(*) FROM server_members WHERE server_id = $1 AND username != $2", serverID, username).Scan(&otherMembersCount)

	// Count other admins to determine if the user is the sole admin
	var otherAdminsCount int
	_ = h.db.QueryRow("SELECT COUNT(*) FROM server_members WHERE server_id = $1 AND role = 'admin' AND username != $2", serverID, username).Scan(&otherAdminsCount)
	isSoleAdmin := otherAdminsCount == 0

	// If leave=true is passed, the user wants to leave the server (revoke their admin access)
	isLeave := r.URL.Query().Get("leave") == "true"
	// If force=true is passed, they want to completely delete it even if others are on it
	isForce := r.URL.Query().Get("force") == "true"

	if isLeave {
		if otherAdminsCount == 0 && otherMembersCount > 0 {
			http.Error(w, "Conflict: You are the last remaining admin. You must promote another member to admin before leaving, or delete the server completely.", http.StatusConflict)
			return
		}

		_, err := h.db.Exec("DELETE FROM server_members WHERE server_id = $1 AND username = $2", serverID, username)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to remove membership: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "membership_revoked",
			"message": "You have left the server. It remains active for other members.",
		})
		return
	}

	// If other members exist and force is not specified, warn the admin (unless they are the sole admin)
	if otherMembersCount > 0 && !isForce && !isSoleAdmin {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":       "warning_other_members",
			"message":      fmt.Sprintf("There are %d other members monitoring this server. Unregistering will completely delete it for everyone and uninstall the target agent.", otherMembersCount),
			"member_count": otherMembersCount,
		})
		return
	}

	// Proceed with full deletion & agent teardown
	sshInfo, err := ssh.LoadServerSSHInfo(h.db, h.encKey, serverID)

	// Delete associated records
	_, _ = h.db.Exec("DELETE FROM monitored_processes WHERE server_id = $1", serverID)
	_, _ = h.db.Exec("DELETE FROM monitored_applications WHERE server_id = $1", serverID)
	_, _ = h.db.Exec("DELETE FROM alert_rules WHERE server_id = $1", serverID)
	_, _ = h.db.Exec("DELETE FROM recently_viewed WHERE server_id = $1", serverID)
	_, _ = h.db.Exec("DELETE FROM server_members WHERE server_id = $1", serverID)
	_, _ = h.db.Exec("DELETE FROM server_access_tokens WHERE server_id = $1", serverID)

	res, err := h.db.Exec("DELETE FROM servers WHERE id = $1", serverID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete server: %v", err), http.StatusInternalServerError)
		return
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil || rowsAffected == 0 {
		http.Error(w, "domain.Server not found", http.StatusNotFound)
		return
	}

	// Issue self-destruct teardown payload to target agent daemon
	if err == nil {
		go func(info ssh.ServerSSHInfo) {
			log.Printf("[agent-teardown] Sending self-destruct signal to target agent on %s", info.Host)
			// 1. Try websocket uninstall first
			_, errWS := ssh.DoAgentPostRequest(info, "uninstall", nil)
			if errWS != nil {
				log.Printf("[agent-teardown] WebSocket uninstall failed for %s: %v. Retrying via SSH...", info.Host, errWS)
			}
			// 2. Fallback to SSH command execution if SSH credentials are configured
			if info.User != "" {
				uninstallCmd := "sudo systemctl stop cluster-target.service 2>/dev/null; sudo systemctl disable cluster-target.service 2>/dev/null; sudo rm -f /etc/systemd/system/cluster-target.service; sudo rm -rf /etc/cluster-target; sudo rm -f /usr/local/bin/cluster-target; systemctl --user stop cluster-target.service 2>/dev/null; systemctl --user disable cluster-target.service 2>/dev/null; rm -f ~/.config/systemd/user/cluster-target.service; rm -rf ~/.config/cluster-target; rm -f ~/.local/bin/cluster-target; sudo systemctl daemon-reload 2>/dev/null; systemctl --user daemon-reload 2>/dev/null; sudo pkill -9 -f cluster-target; pkill -9 -f cluster-target"
				_, errSSH := ssh.RunSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, uninstallCmd)
				if errSSH != nil {
					log.Printf("[agent-teardown] SSH uninstall failed for %s: %v", info.Host, errSSH)
				} else {
					log.Printf("[agent-teardown] SSH uninstall completed successfully for %s", info.Host)
				}
			}
		}(sshInfo)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "purged",
		"message": "domain.Server permanently unregistered and target agent uninstalled.",
	})
}

func getEffectivePermissions(role string, permissionsBytes []byte) domain.UserPermissions {
	var perm domain.UserPermissions
	if len(permissionsBytes) > 0 && string(permissionsBytes) != "null" {
		if err := json.Unmarshal(permissionsBytes, &perm); err == nil {
			if len(perm.Containers) == 0 {
				perm.Containers = []string{"*"}
			}
			return perm
		}
	}

	if role == "admin" {
		return domain.UserPermissions{
			Tabs:                  []string{"*"},
			Applications:          []string{"*"},
			Processes:             []string{"*"},
			Containers:            []string{"*"},
			AllowProcessKill:      true,
			AllowContainerOperate: true,
			CustomCommandGroups:   []string{"*"},
			AllowedCommandActions: map[string][]string{"*": {"*"}},
		}
	}

	if role == "operator" || role == "member" {
		return domain.UserPermissions{
			Tabs:                  []string{"overview", "metrics", "processes", "applications", "containers", "commands"},
			Applications:          []string{"*"},
			Processes:             []string{"*"},
			Containers:            []string{"*"},
			AllowProcessKill:      true,
			AllowContainerOperate: true,
			CustomCommandGroups:   []string{"*"},
			AllowedCommandActions: map[string][]string{"*": {"*"}},
		}
	}

	return domain.UserPermissions{
		Tabs:                  []string{"overview", "metrics", "processes", "applications", "containers", "commands"},
		Applications:          []string{"*"},
		Processes:             []string{"*"},
		Containers:            []string{"*"},
		AllowProcessKill:      false,
		AllowContainerOperate: false,
		CustomCommandGroups:   []string{"*"},
		AllowedCommandActions: map[string][]string{},
	}
}


func (h *APIHandler) getUserServerPermissions(serverID string, username string) (domain.UserPermissions, string) {
	username = strings.ToLower(strings.TrimSpace(username))
	var role string
	var permissionsBytes []byte
	err := h.db.QueryRow("SELECT role, permissions FROM server_members WHERE server_id = $1 AND LOWER(username) = $2", serverID, username).Scan(&role, &permissionsBytes)
	if err != nil {
		return getEffectivePermissions("viewer", nil), ""
	}
	return getEffectivePermissions(role, permissionsBytes), role
}

type MemberInfo struct {
	Username    string           `json:"username"`
	Role        string           `json:"role"`
	Email       string           `json:"email"`
	CreatedAt   time.Time        `json:"created_at"`
	Permissions *domain.UserPermissions `json:"permissions,omitempty"`
}

func (h *APIHandler) HandleServerMembers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	serverID := r.URL.Query().Get("id")
	if serverID == "" {
		http.Error(w, "Missing server id", http.StatusBadRequest)
		return
	}

	session, err := h.getSession(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Requester must have at least "viewer" access
	allowed, currentUserRole := h.checkServerPermission(serverID, session.Username, "viewer")
	if !allowed {
		http.Error(w, "Forbidden: You do not have access to view this server's team members.", http.StatusForbidden)
		return
	}

	// Use DISTINCT ON to deduplicate by lowercase username — guards against any case-mismatch rows
	rows, err := h.db.Query(`
		SELECT DISTINCT ON (LOWER(username)) username, role, COALESCE(email, ''), created_at, permissions
		FROM server_members
		WHERE server_id = $1
		ORDER BY LOWER(username), CASE role WHEN 'admin' THEN 1 WHEN 'operator' THEN 2 WHEN 'member' THEN 3 ELSE 4 END ASC, created_at ASC
	`, serverID)
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	members := []MemberInfo{}
	for rows.Next() {
		var m MemberInfo
		var permissionsBytes []byte
		if err := rows.Scan(&m.Username, &m.Role, &m.Email, &m.CreatedAt, &permissionsBytes); err == nil {
			effPerms := getEffectivePermissions(m.Role, permissionsBytes)
			m.Permissions = &effPerms
			members = append(members, m)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"members":           members,
		"current_user_role": currentUserRole,
	})
}

func (h *APIHandler) HandleServerInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	session, err := h.getSession(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ServerID    string           `json:"server_id"`
		Username    string           `json:"username"`
		Usernames   []string         `json:"usernames"`
		Role        string           `json:"role"`
		Permissions *domain.UserPermissions `json:"permissions"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Role = strings.ToLower(strings.TrimSpace(req.Role))

	if req.ServerID == "" || req.Role == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Wrap single username in array for compatibility
	if req.Username != "" && len(req.Usernames) == 0 {
		req.Usernames = []string{req.Username}
	}

	if len(req.Usernames) == 0 {
		http.Error(w, "At least one username must be specified", http.StatusBadRequest)
		return
	}

	if req.Role != "admin" && req.Role != "operator" && req.Role != "viewer" {
		http.Error(w, "Invalid role. Must be 'admin', 'operator', or 'viewer'", http.StatusBadRequest)
		return
	}

	// Requester must have "admin" access
	allowed, _ := h.checkServerPermission(req.ServerID, session.Username, "admin")
	if !allowed {
		http.Error(w, "Forbidden: Only server admins can invite new members.", http.StatusForbidden)
		return
	}

	var permissionsBytes []byte
	if req.Permissions != nil {
		permissionsBytes, _ = json.Marshal(req.Permissions)
	}

	for _, uname := range req.Usernames {
		uname = strings.ToLower(strings.TrimSpace(uname))
		if uname == "" {
			continue
		}
		_, err = h.db.Exec(`
			INSERT INTO server_members (server_id, username, role, permissions) 
			VALUES ($1, $2, $3, $4) 
			ON CONFLICT (server_id, username) 
			DO UPDATE SET role = $3, permissions = $4
		`, req.ServerID, uname, req.Role, permissionsBytes)
		if err != nil {
			http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "User(s) successfully invited."})
}

func (h *APIHandler) HandleServerRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	session, err := h.getSession(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	serverID := r.URL.Query().Get("server_id")
	targetUser := strings.ToLower(r.URL.Query().Get("username"))

	if serverID == "" || targetUser == "" {
		http.Error(w, "Missing parameters", http.StatusBadRequest)
		return
	}

	// If a member is removing themselves, we allow it (leave server), otherwise caller must be admin
	if session.Username != targetUser {
		allowed, _ := h.checkServerPermission(serverID, session.Username, "admin")
		if !allowed {
			http.Error(w, "Forbidden: Only server admins can remove other members.", http.StatusForbidden)
			return
		}
	}

	// Check if this is the last admin
	var role string
	err = h.db.QueryRow("SELECT role FROM server_members WHERE server_id = $1 AND username = $2", serverID, targetUser).Scan(&role)
	if err == nil && role == "admin" {
		var adminCount int
		_ = h.db.QueryRow("SELECT COUNT(*) FROM server_members WHERE server_id = $1 AND role = 'admin'", serverID).Scan(&adminCount)
		if adminCount <= 1 {
			http.Error(w, "Conflict: Cannot remove the last remaining admin. Please transfer ownership or delete the server.", http.StatusConflict)
			return
		}
	}

	_, err = h.db.Exec("DELETE FROM server_members WHERE server_id = $1 AND username = $2", serverID, targetUser)
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "User successfully removed."})
}

func (h *APIHandler) HandleServerRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	session, err := h.getSession(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ServerID    string           `json:"server_id"`
		Username    string           `json:"username"`
		Role        string           `json:"role"`
		Permissions *domain.UserPermissions `json:"permissions"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	req.Role = strings.ToLower(strings.TrimSpace(req.Role))

	if req.ServerID == "" || req.Username == "" || req.Role == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	if req.Role != "admin" && req.Role != "operator" && req.Role != "viewer" {
		http.Error(w, "Invalid role. Must be 'admin', 'operator', or 'viewer'", http.StatusBadRequest)
		return
	}

	// Requester must have "admin" access
	allowed, _ := h.checkServerPermission(req.ServerID, session.Username, "admin")
	if !allowed {
		http.Error(w, "Forbidden: Only server admins can change roles.", http.StatusForbidden)
		return
	}

	// If demoting an admin, make sure they are not the last remaining admin
	var oldRole string
	err = h.db.QueryRow("SELECT role FROM server_members WHERE server_id = $1 AND username = $2", req.ServerID, req.Username).Scan(&oldRole)
	if err == nil && oldRole == "admin" && req.Role != "admin" {
		var adminCount int
		_ = h.db.QueryRow("SELECT COUNT(*) FROM server_members WHERE server_id = $1 AND role = 'admin'", req.ServerID).Scan(&adminCount)
		if adminCount <= 1 {
			http.Error(w, "Conflict: Cannot demote the last remaining admin. Please promote another user to admin first.", http.StatusConflict)
			return
		}
	}

	var permissionsBytes []byte
	var dbErr error
	if req.Permissions != nil {
		permissionsBytes, _ = json.Marshal(req.Permissions)
		_, dbErr = h.db.Exec("UPDATE server_members SET role = $1, permissions = $2 WHERE server_id = $3 AND LOWER(username) = $4", req.Role, permissionsBytes, req.ServerID, req.Username)
	} else {
		_, dbErr = h.db.Exec("UPDATE server_members SET role = $1 WHERE server_id = $2 AND LOWER(username) = $3", req.Role, req.ServerID, req.Username)
	}
	if dbErr != nil {
		http.Error(w, "Database error: "+dbErr.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Role successfully updated."})
}

// 2. domain.Server List API (Sidebar & Main Page Overview)
func (h *APIHandler) HandleGetServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	session, errSession := h.getSession(r)
	if errSession != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	username := strings.ToLower(session.Username)

	// 1. Auto-claim any orphaned servers
	orphanedRows, err := h.db.Query("SELECT id FROM servers s WHERE NOT EXISTS (SELECT 1 FROM server_members m WHERE m.server_id = s.id)")
	if err == nil && orphanedRows != nil {
		var oIDs []string
		for orphanedRows.Next() {
			var oID string
			if err := orphanedRows.Scan(&oID); err == nil {
				oIDs = append(oIDs, oID)
			}
		}
		orphanedRows.Close()
		for _, oID := range oIDs {
			_, _ = h.db.Exec("INSERT INTO server_members (server_id, username, role) VALUES ($1, $2, 'admin') ON CONFLICT (server_id, username) DO NOTHING", oID, username)
		}
	}

	// 2. Fetch servers that current user is a member/admin of
	query := `
		SELECT s.id, s.hostname, s.ip_address, s.os_family, s.status, s.last_seen, s.created_at, m.role
		FROM servers s
		JOIN server_members m ON s.id = m.server_id
		WHERE m.username = $1
		ORDER BY s.hostname ASC
	`
	rows, err := h.db.Query(query, username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	servers := []domain.Server{}
	for rows.Next() {
		var s domain.Server
		if err := rows.Scan(&s.ID, &s.Hostname, &s.IPAddress, &s.OSFamily, &s.Status, &s.LastSeen, &s.CreatedAt, &s.Role); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Evaluate online/offline state dynamically based on last seen heartbeat (threshold: 90 seconds)
		info, _ := ssh.LoadServerSSHInfo(h.db, h.encKey, s.ID)
		if wsPkg.Manager.IsConnected(s.ID) || ssh.IsDemoServer(info, s.ID) {
			s.Status = "online"
			s.LastSeen = time.Now()
			_, _ = h.db.Exec("UPDATE servers SET status = 'online', last_seen = NOW() WHERE id = $1 AND status != 'online'", s.ID)
		} else if time.Since(s.LastSeen.UTC()) > 90*time.Second {
			s.Status = "offline"
			_, _ = h.db.Exec("UPDATE servers SET status = 'offline' WHERE id = $1 AND status != 'offline'", s.ID)
		}
		servers = append(servers, s)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(servers)
}

// 3. Recently Viewed / Active Servers List
func (h *APIHandler) HandleGetActiveServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	session, errSession := h.getSession(r)
	if errSession != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	username := strings.ToLower(session.Username)

	// 1. Auto-claim any orphaned servers
	orphanedRows, err := h.db.Query("SELECT id FROM servers s WHERE NOT EXISTS (SELECT 1 FROM server_members m WHERE m.server_id = s.id)")
	if err == nil && orphanedRows != nil {
		var oIDs []string
		for orphanedRows.Next() {
			var oID string
			if err := orphanedRows.Scan(&oID); err == nil {
				oIDs = append(oIDs, oID)
			}
		}
		orphanedRows.Close()
		for _, oID := range oIDs {
			_, _ = h.db.Exec("INSERT INTO server_members (server_id, username, role) VALUES ($1, $2, 'admin') ON CONFLICT (server_id, username) DO NOTHING", oID, username)
		}
	}

	query := `
		SELECT s.id, s.hostname, s.ip_address, s.os_family, s.status, s.last_seen, s.created_at, m.role
		FROM servers s
		JOIN server_members m ON s.id = m.server_id
		LEFT JOIN (
			SELECT server_id, MAX(viewed_at) as last_viewed
			FROM recently_viewed
			GROUP BY server_id
		) r ON s.id = r.server_id
		WHERE m.username = $1 AND s.status = 'online' AND s.last_seen >= NOW() - INTERVAL '90 seconds'
		ORDER BY COALESCE(r.last_viewed, '1970-01-01'::timestamp) DESC, s.last_seen DESC
		LIMIT 6`

	rows, err := h.db.Query(query, username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	servers := []domain.Server{}
	for rows.Next() {
		var s domain.Server
		if err := rows.Scan(&s.ID, &s.Hostname, &s.IPAddress, &s.OSFamily, &s.Status, &s.LastSeen, &s.CreatedAt, &s.Role); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if time.Since(s.LastSeen.UTC()) > 90*time.Second {
			s.Status = "offline"
			continue // Exclude inactive servers
		}
		servers = append(servers, s)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(servers)
}

// 4. domain.Server Details Proxy API (Queries metrics from Prometheus & logs from Loki)
func (h *APIHandler) HandleServerDetail(w http.ResponseWriter, r *http.Request) {
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

	session, errSession := h.getSession(r)
	if errSession != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
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

	// Load fine-grained permissions
	perms, role := h.getUserServerPermissions(serverID, session.Username)

	// Map subPath to tabName
	var tabName string
	switch {
	case subPath == "metrics" || subPath == "" || subPath == "/":
		tabName = "overview"
	case subPath == "history":
		tabName = "history"
	case subPath == "containers" || subPath == "docker-info" || subPath == "container-action" || subPath == "docker-run":
		tabName = "containers"
	case subPath == "systemlogs":
		tabName = "systemlogs"
	case subPath == "networks" || subPath == "network-connections":
		tabName = "networks"
	case subPath == "storage":
		tabName = "storage"
	case subPath == "commands" || strings.HasPrefix(subPath, "commands"):
		tabName = "commands"
	case subPath == "processes":
		// Allowed if either processes or applications tab is enabled
		if role != "admin" && !perms.HasTabAccess("processes") && !perms.HasTabAccess("applications") {
			http.Error(w, "Forbidden: You do not have permission to access processes or applications.", http.StatusForbidden)
			return
		}
	}

	if tabName != "" && role != "admin" && !perms.HasTabAccess(tabName) {
		http.Error(w, fmt.Sprintf("Forbidden: You do not have permission to access the '%s' panel.", tabName), http.StatusForbidden)
		return
	}

	// 1. Enforce Role check for subPath action/POST endpoints (Operator required)
	if subPath == "docker-run" || subPath == "container-action" {
		allowed, _ := h.checkServerPermission(serverID, session.Username, "operator")
		if !allowed {
			http.Error(w, "Forbidden: You do not have permission to execute container actions on this server.", http.StatusForbidden)
			return
		}
		if subPath == "docker-run" {
			h.HandleDockerRun(w, r, serverID)
		} else {
			h.HandleContainerActionProxy(w, r, serverID)
		}
		return
	}

	// 2. Enforce Role check for all other read/GET endpoints (Viewer required)
	allowed, _ := h.checkServerPermission(serverID, session.Username, "viewer")
	if !allowed {
		http.Error(w, "Forbidden: You do not have permission to access this server.", http.StatusForbidden)
		return
	}

	// Route commands request: /api/servers/detail/:id/commands (supports GET/POST/DELETE)
	if subPath == "commands" || strings.HasPrefix(subPath, "commands/") {
		h.HandleServerCommands(w, r, serverID)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Route processes request: /api/servers/detail/:id/processes
	if subPath == "processes" {
		h.HandleGetProcessesProxy(w, r, serverID)
		return
	}

	// Route metrics request: /api/servers/detail/:id/metrics
	if subPath == "metrics" {
		h.HandleGetMetrics(w, r, serverID)
		return
	}

	// Route containers request: /api/servers/detail/:id/containers
	if subPath == "containers" {
		h.HandleGetContainersProxy(w, r, serverID)
		return
	}

	// Route systemlogs request: /api/servers/detail/:id/systemlogs
	if subPath == "systemlogs" {
		h.HandleGetSystemLogsProxy(w, r, serverID)
		return
	}

	// Route networks request: /api/servers/detail/:id/networks
	if subPath == "networks" {
		h.HandleGetNetworksProxy(w, r, serverID)
		return
	}

	// Route history request: /api/servers/detail/:id/history
	if subPath == "history" {
		h.HandleGetHistory(w, r, serverID)
		return
	}

	// Route storage request: /api/servers/detail/:id/storage
	if subPath == "storage" {
		h.HandleGetStorage(w, r, serverID)
		return
	}

	// Route docker-info request: /api/servers/detail/:id/docker-info
	if subPath == "docker-info" {
		h.HandleGetDockerInfo(w, r, serverID)
		return
	}

	// Route network-connections request: /api/servers/detail/:id/network-connections
	if subPath == "network-connections" {
		h.HandleGetNetworkConnections(w, r, serverID)
		return
	}

	// Fetch server info
	var s domain.Server
	err := h.db.QueryRow("SELECT id, hostname, ip_address, os_family, status, last_seen FROM servers WHERE id = $1", serverID).Scan(
		&s.ID, &s.Hostname, &s.IPAddress, &s.OSFamily, &s.Status, &s.LastSeen)
	if err == sql.ErrNoRows {
		http.Error(w, "domain.Server not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var permissionsBytes []byte
	_ = h.db.QueryRow("SELECT role, permissions FROM server_members WHERE server_id = $1 AND LOWER(username) = LOWER($2)", s.ID, session.Username).Scan(&s.Role, &permissionsBytes)
	effPerms := getEffectivePermissions(s.Role, permissionsBytes)
	s.Permissions = &effPerms

	// Update recently viewed log
	h.db.Exec("INSERT INTO recently_viewed (server_id) VALUES ($1)", s.ID)

	// Fetch tracked services list
	rows, err := h.db.Query("SELECT service_name, is_tracked FROM monitored_services WHERE server_id = $1", s.ID)
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

func (h *APIHandler) HandleGetProcessesProxy(w http.ResponseWriter, r *http.Request, serverID string) {
	session, errSession := h.getSession(r)
	if errSession != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	perms, role := h.getUserServerPermissions(serverID, session.Username)

	info, err := ssh.LoadServerSSHInfo(h.db, h.encKey, serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "domain.Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cacheKey := "processes:" + serverID
	var procs []map[string]interface{}
	if val, ok := h.redis.GetCachedJSON(cacheKey); ok {
		if err := json.Unmarshal([]byte(val), &procs); err != nil {
			procs = nil
		}
	}

	if procs == nil {
		if ssh.IsDemoServer(info, serverID) {
			procs = []map[string]interface{}{
				{"pid": "1", "name": "systemd", "user": "root", "cpu": "0.1", "mem": "12.4"},
				{"pid": "824", "name": "alloy", "user": "alloy", "cpu": "1.2", "mem": "64.8"},
				{"pid": "912", "name": "cluster-agent", "user": "root", "cpu": "0.5", "mem": "18.2"},
				{"pid": "1042", "name": "postgres", "user": "postgres", "cpu": "0.8", "mem": "142.1"},
				{"pid": "1205", "name": "nginx", "user": "nginx", "cpu": "0.2", "mem": "8.5"},
				{"pid": "1530", "name": "go-backend", "user": "root", "cpu": "2.4", "mem": "32.0"},
				{"pid": "2054", "name": "node_exporter", "user": "prometheus", "cpu": "0.4", "mem": "14.1"},
				{"pid": "2100", "name": "loki", "user": "loki", "cpu": "1.5", "mem": "98.3"},
			}
			h.redis.SetCachedJSON(cacheKey, procs, 60)
		} else {
			liveProcs, err := ssh.SSHGetProcesses(info)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-SSH-Unavailable", "1")
				w.WriteHeader(http.StatusBadGateway)
				json.NewEncoder(w).Encode(map[string]string{"error": "SSH collection unavailable", "detail": err.Error()})
				return
			}
			procs = liveProcs
			h.redis.SetCachedJSON(cacheKey, procs, 60)
		}
	}

	// Filter processes based on permissions
	filteredProcs := []map[string]interface{}{}
	if role == "admin" {
		filteredProcs = procs
	} else {
		for _, p := range procs {
			name := fmt.Sprintf("%v", p["name"])
			if perms.CanViewProcess(name) || perms.CanViewApplication(name) {
				filteredProcs = append(filteredProcs, p)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(filteredProcs)
}

func (h *APIHandler) HandleGetContainersProxy(w http.ResponseWriter, r *http.Request, serverID string) {
	session, errSession := h.getSession(r)
	if errSession != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	perms, role := h.getUserServerPermissions(serverID, session.Username)

	info, err := ssh.LoadServerSSHInfo(h.db, h.encKey, serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "domain.Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cacheKey := "containers:" + serverID
	var payload map[string]interface{}
	if val, ok := h.redis.GetCachedJSON(cacheKey); ok {
		if err := json.Unmarshal([]byte(val), &payload); err != nil {
			payload = nil
		}
	}

	if payload == nil {
		livePayload, err := ssh.SSHGetContainers(info)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-SSH-Unavailable", "1")
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": "Docker query failed", "detail": err.Error()})
			return
		}
		payload = livePayload
		h.redis.SetCachedJSON(cacheKey, payload, 60)
	}

	// Filter containers based on permissions
	if role != "admin" {
		if rawContainers, ok := payload["containers"].([]interface{}); ok {
			filteredContainers := []interface{}{}
			for _, rc := range rawContainers {
				if cMap, ok := rc.(map[string]interface{}); ok {
					var name string
					if n, exists := cMap["name"]; exists {
						name = fmt.Sprintf("%v", n)
					} else if n, exists := cMap["Names"]; exists {
						name = fmt.Sprintf("%v", n)
					}
					name = strings.TrimPrefix(name, "/")
					if perms.CanViewContainer(name) {
						filteredContainers = append(filteredContainers, rc)
					}
				} else {
					filteredContainers = append(filteredContainers, rc)
				}
			}
			payload["containers"] = filteredContainers
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(payload)
}

func (h *APIHandler) HandleContainerActionProxy(w http.ResponseWriter, r *http.Request, serverID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	info, err := ssh.LoadServerSSHInfo(h.db, h.encKey, serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "domain.Server not registered", http.StatusNotFound)
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

	// Parse action/target and perform checks
	var req struct {
		Action    string `json:"action"`
		Container string `json:"container"`
		Target    string `json:"target"`
		Dir       string `json:"dir"`
		Image     string `json:"image"`
	}
	if jErr := json.Unmarshal(body, &req); jErr != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	containerName := req.Container
	if containerName == "" {
		containerName = req.Target
	}

	session, errSession := h.getSession(r)
	if errSession != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	perms, role := h.getUserServerPermissions(serverID, session.Username)
	if role != "admin" && !perms.CanOperateContainer(containerName, req.Action) {
		http.Error(w, fmt.Sprintf("Forbidden: You do not have permission to execute container action '%s' on '%s'.", req.Action, containerName), http.StatusForbidden)
		return
	}

	// 1. Try direct HTTP to the target agent (/api/v1/container-action)
	if agentResp, dErr := ssh.DoAgentPostRequest(info, "container-action", body); dErr == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write(agentResp)
		return
	}

	// 2. SSH fallback — parse action/target and run docker directly on the remote host

	var dockerCmd string
	switch req.Action {
	case "start":
		dockerCmd = fmt.Sprintf("start %s", ssh.ShellQuote(req.Target))
	case "stop":
		dockerCmd = fmt.Sprintf("stop %s", ssh.ShellQuote(req.Target))
	case "pause":
		dockerCmd = fmt.Sprintf("pause %s", ssh.ShellQuote(req.Target))
	case "unpause":
		dockerCmd = fmt.Sprintf("unpause %s", ssh.ShellQuote(req.Target))
	case "restart":
		dockerCmd = fmt.Sprintf("restart %s", ssh.ShellQuote(req.Target))
	case "remove":
		dockerCmd = fmt.Sprintf("rm -f %s", ssh.ShellQuote(req.Target))
	case "logs":
		dockerCmd = fmt.Sprintf("logs --tail 300 --timestamps %s", ssh.ShellQuote(req.Target))
	case "pull":
		dockerCmd = fmt.Sprintf("pull %s", ssh.ShellQuote(req.Image))
	case "compose-up":
		dockerCmd = fmt.Sprintf("compose -f %s up -d", ssh.ShellQuote(req.Dir+"/docker-compose.yml"))
	case "compose-down":
		dockerCmd = fmt.Sprintf("compose -f %s down", ssh.ShellQuote(req.Dir+"/docker-compose.yml"))
	case "compose-rebuild":
		dockerCmd = fmt.Sprintf("compose -f %s up -d --build", ssh.ShellQuote(req.Dir+"/docker-compose.yml"))
	case "compose-logs":
		if req.Target != "" {
			dockerCmd = fmt.Sprintf("compose -f %s logs --tail 200 --timestamps %s", ssh.ShellQuote(req.Dir+"/docker-compose.yml"), ssh.ShellQuote(req.Target))
		} else {
			dockerCmd = fmt.Sprintf("compose -f %s logs --tail 200 --timestamps", ssh.ShellQuote(req.Dir+"/docker-compose.yml"))
		}
	default:
		http.Error(w, "Unknown action: "+req.Action, http.StatusBadRequest)
		return
	}

	out, err := ssh.SSHDockerRun(info, dockerCmd)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error(), "output": out})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "output": out})
}

// handleGetStorage returns disk/partition info via SSH.
func (h *APIHandler) HandleGetStorage(w http.ResponseWriter, r *http.Request, serverID string) {
	info, err := ssh.LoadServerSSHInfo(h.db, h.encKey, serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "domain.Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cacheKey := "storage:" + serverID
	if val, ok := h.redis.GetCachedJSON(cacheKey); ok {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(val))
		return
	}

	if ssh.IsDemoServer(info, serverID) {
		mockStorage := []map[string]interface{}{
			{"name": "sda1", "size": "80G", "type": "part", "fstype": "ext4", "mountpoint": "/", "model": "Demo Disk"},
			{"name": "sdb1", "size": "200G", "type": "part", "fstype": "ext4", "mountpoint": "/home", "model": ""},
		}
		h.redis.SetCachedJSON(cacheKey, mockStorage, 60)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockStorage)
		return
	}
	parts, err := ssh.SSHGetStorage(info)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "SSH collection unavailable", "detail": err.Error()})
		return
	}
	h.redis.SetCachedJSON(cacheKey, parts, 60)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(parts)
}

// handleGetDockerInfo returns Docker version and images.
func (h *APIHandler) HandleGetDockerInfo(w http.ResponseWriter, r *http.Request, serverID string) {
	info, err := ssh.LoadServerSSHInfo(h.db, h.encKey, serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "domain.Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ssh.IsDemoServer(info, serverID) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"available": true,
			"version":   map[string]string{"domain.Server": "24.0.5"},
			"images": []map[string]interface{}{
				{"Repository": "postgres", "Tag": "15-alpine", "Size": "87.2MB"},
				{"Repository": "nginx", "Tag": "latest", "Size": "45.3MB"},
			},
		})
		return
	}
	dinfo, err := ssh.SSHGetDockerInfo(info)
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
func (h *APIHandler) HandleDockerRun(w http.ResponseWriter, r *http.Request, serverID string) {
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
	info, err := ssh.LoadServerSSHInfo(h.db, h.encKey, serverID)
	if err != nil {
		http.Error(w, "domain.Server not registered", http.StatusNotFound)
		return
	}
	if ssh.IsDemoServer(info, serverID) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "output": "Demo: no real action taken"})
		return
	}

	// Try WebSocket first
	agentReq := struct {
		Action string `json:"action"`
		Target string `json:"target"`
		Dir    string `json:"dir"`
	}{
		Action: req.Action,
		Target: req.Container,
		Dir:    req.Dir,
	}
	agentBody, _ := json.Marshal(agentReq)
	if agentResp, dErr := ssh.DoAgentPostRequest(info, "container-action", agentBody); dErr == nil {
		var agentRes struct {
			Ok     bool   `json:"ok"`
			Output string `json:"output"`
		}
		if json.Unmarshal(agentResp, &agentRes) == nil {
			w.Header().Set("Content-Type", "application/json")
			if agentRes.Ok {
				json.NewEncoder(w).Encode(map[string]string{"status": "ok", "output": agentRes.Output})
			} else {
				w.WriteHeader(http.StatusBadGateway)
				json.NewEncoder(w).Encode(map[string]string{"error": "Agent action failed", "output": agentRes.Output})
			}
			return
		}
	}

	var dockerCmd string
	switch req.Action {
	case "logs":
		dockerCmd = fmt.Sprintf("logs --tail 200 %s", ssh.ShellQuote(req.Container))
	case "start":
		dockerCmd = fmt.Sprintf("start %s", ssh.ShellQuote(req.Container))
	case "stop":
		dockerCmd = fmt.Sprintf("stop %s", ssh.ShellQuote(req.Container))
	case "restart":
		dockerCmd = fmt.Sprintf("restart %s", ssh.ShellQuote(req.Container))
	case "compose-up":
		dockerCmd = fmt.Sprintf("compose -f %s up -d", ssh.ShellQuote(req.Dir+"/docker-compose.yml"))
	case "compose-down":
		dockerCmd = fmt.Sprintf("compose -f %s down", ssh.ShellQuote(req.Dir+"/docker-compose.yml"))
	case "compose-rebuild":
		dockerCmd = fmt.Sprintf("compose -f %s up -d --build", ssh.ShellQuote(req.Dir+"/docker-compose.yml"))
	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
		return
	}
	out, err := ssh.SSHDockerRun(info, dockerCmd)
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
func (h *APIHandler) HandleGetNetworkConnections(w http.ResponseWriter, r *http.Request, serverID string) {
	info, err := ssh.LoadServerSSHInfo(h.db, h.encKey, serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "domain.Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ssh.IsDemoServer(info, serverID) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tcp": []map[string]string{{"local": "0.0.0.0:22", "remote": "0.0.0.0:0", "state": "LISTEN"}, {"local": "192.168.21.206:443", "remote": "10.0.0.1:54321", "state": "ESTABLISHED"}},
			"udp": []map[string]string{},
		})
		return
	}
	conns, err := ssh.SSHGetNetworkConnections(info)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "SSH collection unavailable", "detail": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(conns)
}

func (h *APIHandler) HandleGetSystemLogsProxy(w http.ResponseWriter, r *http.Request, serverID string) {
	info, err := ssh.LoadServerSSHInfo(h.db, h.encKey, serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "domain.Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if ssh.IsDemoServer(info, serverID) {
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

	logs, err := ssh.SSHGetSystemLogs(info)
	w.Header().Set("Content-Type", "text/plain")
	if err != nil || len(logs) == 0 {
		if err != nil {
			w.Write([]byte("System log collection unavailable: " + err.Error()))
		} else {
			w.Write([]byte("No system logs collected for this server."))
		}
		return
	}
	w.Write([]byte(logs))
}

func (h *APIHandler) HandleGetNetworksProxy(w http.ResponseWriter, r *http.Request, serverID string) {
	info, err := ssh.LoadServerSSHInfo(h.db, h.encKey, serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "domain.Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if ssh.IsDemoServer(info, serverID) {
		mockNets := []map[string]interface{}{
			{"name": "lo", "ip": "127.0.0.1", "rxSpeed": "12 KB/s", "txSpeed": "12 KB/s", "rxTotal": "2.5 GB", "txTotal": "2.5 GB"},
			{"name": "eth0", "ip": "192.168.21.206", "rxSpeed": "1.2 MB/s", "txSpeed": "240 KB/s", "rxTotal": "142.6 GB", "txTotal": "38.4 GB"},
			{"name": "docker0", "ip": "172.17.0.1", "rxSpeed": "0 KB/s", "txSpeed": "0 KB/s", "rxTotal": "12.4 GB", "txTotal": "8.1 GB"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockNets)
		return
	}

	nets, err := ssh.SSHGetNetworks(info)
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

func (h *APIHandler) getLatestDBMetrics(serverID string) (map[string]interface{}, error) {
	var cpu, ramPct, ramUsed, ramTotal, swapPct, swapUsed, swapTotal, diskPct, diskUsed, diskTotal, rx, tx float64
	query := `
		SELECT cpu, ram_used_pct, ram_used_gb, ram_total_gb, swap_used_pct, swap_used_gb, swap_total_gb, disk_used_pct, disk_used_gb, disk_total_gb, net_rx_kb, net_tx_kb
		FROM metrics_history
		WHERE server_id = $1
		ORDER BY sampled_at DESC
		LIMIT 1`
	err := h.db.QueryRow(query, serverID).Scan(&cpu, &ramPct, &ramUsed, &ramTotal, &swapPct, &swapUsed, &swapTotal, &diskPct, &diskUsed, &diskTotal, &rx, &tx)
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

func (h *APIHandler) HandleGetMetrics(w http.ResponseWriter, r *http.Request, serverID string) {
	info, err := ssh.LoadServerSSHInfo(h.db, h.encKey, serverID)
	if err != nil {
		http.Error(w, "domain.Server not found", http.StatusNotFound)
		return
	}

	// Return cached metrics from Redis if present to keep Dashboard and Overview in sync
	if cached, ok := h.redis.GetCachedMetrics(serverID); ok {
		_, _ = h.db.Exec("UPDATE servers SET status = 'online', last_seen = NOW() WHERE id = $1", serverID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cached)
		return
	}

	if ssh.IsDemoServer(info, serverID) {
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
		h.redis.SetCachedMetrics(serverID, metrics, 60)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metrics)
		return
	}

	metrics, err := ssh.SSHGetMetrics(info)
	if err != nil {
		// Fallback: get the latest sample from PostgreSQL database (metrics_history table)
		log.Printf("[metrics-fallback] SSH/HTTP direct failed for %s, falling back to DB: %v", serverID, err)
		metrics, dbErr := h.getLatestDBMetrics(serverID)
		if dbErr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-SSH-Unavailable", "1")
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": "Metrics unavailable", "detail": fmt.Sprintf("Agent offline and no database history: %v (DB err: %v)", err, dbErr)})
			return
		}

		h.redis.SetCachedMetrics(serverID, metrics, 60)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metrics)
		return
	}

	// Update last_seen and status in the servers table since we successfully queried the agent
	_, _ = h.db.Exec("UPDATE servers SET status = 'online', last_seen = NOW() WHERE id = $1", serverID)

	// Persist a sample so the History tab has stored trends even without an agent push.
	if !ssh.IsDemoServer(info, serverID) {
		h.persistMetricSample(serverID, metrics)
	}

	h.redis.SetCachedMetrics(serverID, metrics, 60)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

var (
	lastSampleMu   sync.Mutex
	lastSampleTime = make(map[string]time.Time)
)

// persistMetricSample writes a metrics snapshot into metrics_history (throttled to max 1 sample per 5s per server).
func (h *APIHandler) persistMetricSample(serverID string, m map[string]interface{}) {
	lastSampleMu.Lock()
	if t, exists := lastSampleTime[serverID]; exists && time.Since(t) < 5*time.Second {
		lastSampleMu.Unlock()
		return
	}
	lastSampleTime[serverID] = time.Now()
	lastSampleMu.Unlock()

	getF := func(k string) float64 {
		if v, ok := m[k].(float64); ok {
			return v
		}
		return 0
	}
	_, err := h.db.Exec(`INSERT INTO metrics_history
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
func (h *APIHandler) HandleTestSSH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var p struct {
		IPAddress   string `json:"ip_address"`
		SSHUser     string `json:"ssh_user"`
		SSHKey      string `json:"ssh_key"`
		SSHPassword string `json:"ssh_password"`
		SSHPort     int    `json:"ssh_port"`
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

	info := ssh.ServerSSHInfo{User: p.SSHUser, Password: p.SSHPassword, Key: p.SSHKey, Host: p.IPAddress, Port: p.SSHPort, OSFamily: "linux"}
	// Attempt to run a trivial command to prove auth + connectivity.
	out, err := ssh.RunSSHCommand("test", info.User, info.Password, info.Key, info.Host, info.Port, "echo ok")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "output": strings.TrimSpace(out)})
}

// handleGetHistory returns stored time-series from metrics_history (fed by agent
// pushes and/or any stats collection). Supports ?limit= (default 200) and ?hours=.
func (h *APIHandler) HandleGetHistory(w http.ResponseWriter, r *http.Request, serverID string) {
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
		rows, err = h.db.Query(
			`SELECT sampled_at, cpu, ram_used_pct, swap_used_pct, disk_used_pct, net_rx_kb, net_tx_kb
			 FROM metrics_history WHERE server_id=$1 AND sampled_at > NOW() - ($2 || ' hours')::interval
			 ORDER BY sampled_at ASC LIMIT $3`,
			serverID, hours, limit)
	} else {
		rows, err = h.db.Query(
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
		Time        string  `json:"time"`
		CPU         float64 `json:"cpu"`
		RAMUsedPct  float64 `json:"ram_used_pct"`
		SwapUsedPct float64 `json:"swap_used_pct"`
		DiskUsedPct float64 `json:"disk_used_pct"`
		NetRxKB     float64 `json:"net_rx_kb"`
		NetTxKB     float64 `json:"net_tx_kb"`
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
func (h *APIHandler) HandleToggleService(w http.ResponseWriter, r *http.Request) {
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

	session, errSession := h.getSession(r)
	if errSession != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	allowed, _ := h.checkServerPermission(serverID, session.Username, "operator")
	if !allowed {
		http.Error(w, "Forbidden: You do not have permission to toggle services on this server.", http.StatusForbidden)
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

	_, err := h.db.Exec(query, serverID, payload.Service, payload.IsTracked)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}

// 6. Proxy Service Commands to Go Agent (Start, Stop, Restart)
func (h *APIHandler) HandleServiceControl(w http.ResponseWriter, r *http.Request) {
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

	session, errSession := h.getSession(r)
	if errSession != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	allowed, _ := h.checkServerPermission(serverID, session.Username, "operator")
	if !allowed {
		http.Error(w, "Forbidden: You do not have permission to execute service controls on this server.", http.StatusForbidden)
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
	info, err := ssh.LoadServerSSHInfo(h.db, h.encKey, serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "domain.Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if ssh.IsDemoServer(info, serverID) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "success",
			"output": fmt.Sprintf("Service '%s' has successfully completed action '%s' on demo-server-01.", payload.Service, payload.Action),
		})
		return
	}

	result, err := ssh.SSHServiceControl(info, payload.Service, payload.Action)
	if err != nil {
		ssh.SSHError(w, fmt.Sprintf("Failed to control service over SSH at %s: %v", info.Host, err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// Proxy Kill Process Command to Go Agent
func (h *APIHandler) HandleKillProcessControl(w http.ResponseWriter, r *http.Request) {
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

	session, errSession := h.getSession(r)
	if errSession != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	allowed, _ := h.checkServerPermission(serverID, session.Username, "operator")
	if !allowed {
		http.Error(w, "Forbidden: You do not have permission to execute process kills on this server.", http.StatusForbidden)
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
	info, err := ssh.LoadServerSSHInfo(h.db, h.encKey, serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "domain.Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if ssh.IsDemoServer(info, serverID) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": fmt.Sprintf("Signal %s sent to PID %s on demo-server-01.", signalClean, pidClean),
		})
		return
	}

	result, err := ssh.SSHKillProcess(info, pidClean, signalClean)
	if err != nil {
		ssh.SSHError(w, fmt.Sprintf("Failed to kill process over SSH at %s: %v", info.Host, err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// Proxy Kill Application Command to Go Agent (by process name, all instances)
func (h *APIHandler) HandleKillApplicationControl(w http.ResponseWriter, r *http.Request) {
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

	session, errSession := h.getSession(r)
	if errSession != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	allowed, _ := h.checkServerPermission(serverID, session.Username, "operator")
	if !allowed {
		http.Error(w, "Forbidden: You do not have permission to execute application kills on this server.", http.StatusForbidden)
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

	info, err := ssh.LoadServerSSHInfo(h.db, h.encKey, serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "domain.Server not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if ssh.IsDemoServer(info, serverID) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": fmt.Sprintf("Signal %s sent to application '%s' on demo-server-01.", signalClean, payload.Name),
		})
		return
	}

	result, err := ssh.SSHKillProcessByName(info, payload.Name, signalClean)
	if err != nil {
		ssh.SSHError(w, fmt.Sprintf("Failed to signal application over SSH at %s: %v", info.Host, err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// 7. Alert Rules Configuration API
func (h *APIHandler) HandleAlertRules(w http.ResponseWriter, r *http.Request) {
	session, errSession := h.getSession(r)
	if errSession != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	username := strings.ToLower(strings.TrimSpace(session.Username))

	if r.Method == http.MethodGet {
		// List active alert rules scoped to servers user is member of
		query := `
			SELECT r.id, r.server_id, r.metric_type, r.operator, r.threshold, r.duration_minutes, r.recipient_email, COALESCE(r.recipient_type, 'self'), r.is_active, r.is_firing, r.target_type, r.target_value 
			FROM alert_rules r
			JOIN server_members m ON r.server_id = m.server_id
			WHERE m.username = $1`
		rows, err := h.db.Query(query, username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		rules := []domain.AlertRule{}
		for rows.Next() {
			var rule domain.AlertRule
			if err := rows.Scan(&rule.ID, &rule.ServerID, &rule.MetricType, &rule.Operator, &rule.Threshold, &rule.DurationMinutes, &rule.RecipientEmail, &rule.RecipientType, &rule.IsActive, &rule.IsFiring, &rule.TargetType, &rule.TargetValue); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			perms, role := h.getUserServerPermissions(rule.ServerID, username)
			if role == "admin" || perms.HasTabAccess("alerts") {
				rules = append(rules, rule)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rules)
		return
	}

	if r.Method == http.MethodPost {
		// Create new alert rule
		var rule domain.AlertRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		if rule.RecipientType == "" {
			rule.RecipientType = "self"
		}
		if rule.RecipientType == "self" {
			rule.RecipientEmail = session.Email
		} else if rule.RecipientType == "all" {
			rows, err := h.db.Query("SELECT COALESCE(email, '') FROM server_members WHERE server_id = $1 AND email != ''", rule.ServerID)
			if err == nil {
				var emails []string
				for rows.Next() {
					var e string
					rows.Scan(&e)
					if e != "" {
						emails = append(emails, e)
					}
				}
				rows.Close()
				if len(emails) > 0 {
					rule.RecipientEmail = strings.Join(emails, ",")
				} else {
					rule.RecipientEmail = session.Email
				}
			} else {
				rule.RecipientEmail = session.Email
			}
		}

		if !uuidRegex.MatchString(rule.ServerID) || rule.MetricType == "" || rule.RecipientEmail == "" {
			http.Error(w, "Invalid parameters (missing UUID, metric, or user email)", http.StatusBadRequest)
			return
		}

		// Enforce Operator permission
		allowed, role := h.checkServerPermission(rule.ServerID, username, "operator")
		perms, _ := h.getUserServerPermissions(rule.ServerID, username)
		if !allowed || (role != "admin" && !perms.HasTabAccess("alerts")) {
			http.Error(w, "Forbidden: You do not have permission to manage alert rules on this server.", http.StatusForbidden)
			return
		}

		if rule.Operator == "" {
			rule.Operator = ">"
		}
		validOp := false
		for _, op := range []string{">", "<", ">=", "<=", "==", "!="} {
			if rule.Operator == op {
				validOp = true
				break
			}
		}
		if !validOp {
			http.Error(w, "Invalid operator", http.StatusBadRequest)
			return
		}

		query := `
			INSERT INTO alert_rules (server_id, metric_type, operator, threshold, duration_minutes, recipient_email, recipient_type, is_active, is_firing, target_type, target_value)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE, $9, $10)`
		_, err := h.db.Exec(query, rule.ServerID, rule.MetricType, rule.Operator, rule.Threshold, rule.DurationMinutes, rule.RecipientEmail, rule.RecipientType, rule.IsActive, rule.TargetType, rule.TargetValue)
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

		// Enforce Operator permission by looking up the server_id of the rule
		var serverID string
		err := h.db.QueryRow("SELECT server_id FROM alert_rules WHERE id = $1", ruleID).Scan(&serverID)
		if err != nil {
			http.Error(w, "Rule not found", http.StatusNotFound)
			return
		}

		allowed, role := h.checkServerPermission(serverID, username, "operator")
		perms, _ := h.getUserServerPermissions(serverID, username)
		if !allowed || (role != "admin" && !perms.HasTabAccess("alerts")) {
			http.Error(w, "Forbidden: You do not have permission to manage alert rules on this server.", http.StatusForbidden)
			return
		}

		_, err = h.db.Exec("DELETE FROM alert_rules WHERE id = $1", ruleID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"deleted"}`))
		return
	}

	if r.Method == http.MethodPut {
		var rule domain.AlertRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		ruleIDStr := r.URL.Query().Get("id")
		var ruleID int
		var err error
		if ruleIDStr != "" {
			ruleID, err = strconv.Atoi(ruleIDStr)
			if err != nil {
				http.Error(w, "Invalid rule id in query", http.StatusBadRequest)
				return
			}
		} else {
			ruleID = rule.ID
		}

		if ruleID == 0 {
			http.Error(w, "Missing rule id", http.StatusBadRequest)
			return
		}

		// Enforce Operator permission on the existing server ID of the rule
		var existingServerID string
		err = h.db.QueryRow("SELECT server_id FROM alert_rules WHERE id = $1", ruleID).Scan(&existingServerID)
		if err != nil {
			http.Error(w, "Rule not found", http.StatusNotFound)
			return
		}

		allowed, role := h.checkServerPermission(existingServerID, username, "operator")
		perms, _ := h.getUserServerPermissions(existingServerID, username)
		if !allowed || (role != "admin" && !perms.HasTabAccess("alerts")) {
			http.Error(w, "Forbidden: You do not have permission to manage alert rules on this server.", http.StatusForbidden)
			return
		}

		// Also check permission on new server ID if it's changing
		if rule.ServerID != "" && rule.ServerID != existingServerID {
			allowedNew, roleNew := h.checkServerPermission(rule.ServerID, username, "operator")
			permsNew, _ := h.getUserServerPermissions(rule.ServerID, username)
			if !allowedNew || (roleNew != "admin" && !permsNew.HasTabAccess("alerts")) {
				http.Error(w, "Forbidden: You do not have permission to manage alert rules on the target server.", http.StatusForbidden)
				return
			}
		}

		if rule.RecipientType == "" {
			rule.RecipientType = "self"
		}
		if rule.RecipientType == "self" {
			rule.RecipientEmail = session.Email
		} else if rule.RecipientType == "all" {
			rows, err := h.db.Query("SELECT COALESCE(email, '') FROM server_members WHERE server_id = $1 AND email != ''", rule.ServerID)
			if err == nil {
				var emails []string
				for rows.Next() {
					var e string
					rows.Scan(&e)
					if e != "" {
						emails = append(emails, e)
					}
				}
				rows.Close()
				if len(emails) > 0 {
					rule.RecipientEmail = strings.Join(emails, ",")
				} else {
					rule.RecipientEmail = session.Email
				}
			} else {
				rule.RecipientEmail = session.Email
			}
		}

		if !uuidRegex.MatchString(rule.ServerID) || rule.MetricType == "" || rule.RecipientEmail == "" {
			http.Error(w, "Invalid parameters (missing UUID, metric, or user email)", http.StatusBadRequest)
			return
		}

		if rule.Operator == "" {
			rule.Operator = ">"
		}
		validOp := false
		for _, op := range []string{">", "<", ">=", "<=", "==", "!="} {
			if rule.Operator == op {
				validOp = true
				break
			}
		}
		if !validOp {
			http.Error(w, "Invalid operator", http.StatusBadRequest)
			return
		}

		query := `
			UPDATE alert_rules
			SET server_id = $1, metric_type = $2, operator = $3, threshold = $4, duration_minutes = $5, recipient_email = $6, recipient_type = $7, is_active = $8, is_firing = $9, target_type = $10, target_value = $11
			WHERE id = $12`
		_, err = h.db.Exec(query, rule.ServerID, rule.MetricType, rule.Operator, rule.Threshold, rule.DurationMinutes, rule.RecipientEmail, rule.RecipientType, rule.IsActive, rule.IsFiring, rule.TargetType, rule.TargetValue, ruleID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"updated"}`))
		return
	}

	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

// 7b. Custom Commands handler (dispatched from handleServerDetail)
func (h *APIHandler) HandleServerCommands(w http.ResponseWriter, r *http.Request, serverID string) {
	session, err := h.getSession(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	username := strings.ToLower(strings.TrimSpace(session.Username))

	trimmed := strings.TrimPrefix(r.URL.Path, "/api/servers/detail/"+serverID+"/commands")
	trimmed = strings.TrimSuffix(trimmed, "/")

	switch {
	case trimmed == "" || trimmed == "/":
		if r.Method == http.MethodGet {
			allowed, _ := h.checkServerPermission(serverID, username, "viewer")
			if !allowed {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			rows, err := h.db.Query("SELECT id, server_id, service_name, commands, created_by, updated_at FROM custom_commands WHERE server_id = $1 ORDER BY service_name", serverID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer rows.Close()
			sets := []domain.CustomCommandSet{}
			perms, role := h.getUserServerPermissions(serverID, username)
			for rows.Next() {
				var s domain.CustomCommandSet
				var cmdsBytes []byte
				if err := rows.Scan(&s.ID, &s.ServerID, &s.ServiceName, &cmdsBytes, &s.CreatedBy, &s.UpdatedAt); err == nil {
					json.Unmarshal(cmdsBytes, &s.Commands)
					if role == "admin" || perms.CanViewCustomCommandGroup(s.ServiceName) {
						sets = append(sets, s)
					}
				}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(sets)
			return
		}

		if r.Method == http.MethodPost {
			allowed, _ := h.checkServerPermission(serverID, username, "admin")
			if !allowed {
				http.Error(w, "Forbidden: Only admins can manage command sets.", http.StatusForbidden)
				return
			}
			var payload struct {
				ServiceName string            `json:"service_name"`
				Commands    map[string]string `json:"commands"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, "Invalid JSON", http.StatusBadRequest)
				return
			}
			if payload.ServiceName == "" || len(payload.Commands) == 0 {
				http.Error(w, "service_name and commands are required", http.StatusBadRequest)
				return
			}
			cmdsBytes, _ := json.Marshal(payload.Commands)
			_, err := h.db.Exec(`
				INSERT INTO custom_commands (server_id, service_name, commands, created_by, updated_at)
				VALUES ($1, $2, $3, $4, NOW())
				ON CONFLICT (server_id, service_name)
				DO UPDATE SET commands = $3, created_by = $4, updated_at = NOW()
			`, serverID, payload.ServiceName, cmdsBytes, username)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
			return
		}

		if r.Method == http.MethodDelete {
			allowed, _ := h.checkServerPermission(serverID, username, "admin")
			if !allowed {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			name := r.URL.Query().Get("name")
			if name == "" {
				http.Error(w, "Missing name parameter", http.StatusBadRequest)
				return
			}
			_, err := h.db.Exec("DELETE FROM custom_commands WHERE server_id = $1 AND service_name = $2", serverID, name)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}

		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)

	case trimmed == "/execute":
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		allowed, role := h.checkServerPermission(serverID, username, "operator")
		if !allowed {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		var payload struct {
			ServiceName string `json:"service_name"`
			CommandType string `json:"command_type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		perms, _ := h.getUserServerPermissions(serverID, username)
		if role != "admin" && !perms.CanExecuteCustomCommand(payload.ServiceName, payload.CommandType) {
			http.Error(w, fmt.Sprintf("Forbidden: You do not have permission to execute custom command '%s' on service '%s'.", payload.CommandType, payload.ServiceName), http.StatusForbidden)
			return
		}
		if payload.ServiceName == "" || payload.CommandType == "" {
			http.Error(w, "service_name and command_type are required", http.StatusBadRequest)
			return
		}

		var cmdsBytes []byte
		err := h.db.QueryRow("SELECT commands FROM custom_commands WHERE server_id = $1 AND service_name = $2", serverID, payload.ServiceName).Scan(&cmdsBytes)
		if err != nil {
			http.Error(w, "Command set not found", http.StatusNotFound)
			return
		}
		var commands map[string]string
		json.Unmarshal(cmdsBytes, &commands)
		command, ok := commands[payload.CommandType]
		if !ok {
			http.Error(w, fmt.Sprintf("Command type '%s' not found in set '%s'", payload.CommandType, payload.ServiceName), http.StatusNotFound)
			return
		}

		info, err := ssh.LoadServerSSHInfo(h.db, h.encKey, serverID)
		var output string
		var status string
		startTime := time.Now()
		if err != nil {
			status = "failed"
			output = err.Error()
		} else if ssh.IsDemoServer(info, serverID) {
			status = "success"
			output = fmt.Sprintf("Demo execution: %s %s => %s", payload.ServiceName, payload.CommandType, command)
		} else {
			out, execErr := ssh.RunSSHCommand(info.ServerID, info.User, info.Password, info.Key, info.Host, info.Port, command)
			if execErr != nil {
				status = "failed"
				// out already contains the command's output (stderr + stdout);
				// execErr.Error() is the same content, so just show out directly.
				if strings.TrimSpace(out) != "" {
					output = out
				} else {
					output = execErr.Error()
				}
			} else {
				status = "success"
				output = out
			}
		}
		durationMs := int(time.Since(startTime).Milliseconds())

		_, _ = h.db.Exec(`
			INSERT INTO command_execution_log (server_id, service_name, command_type, command, executed_by, status, output, duration_ms)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, serverID, payload.ServiceName, payload.CommandType, command, username, status, output, durationMs)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      status,
			"output":      output,
			"duration_ms": durationMs,
		})

	case trimmed == "/logs":
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		allowed, _ := h.checkServerPermission(serverID, username, "viewer")
		if !allowed {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		rows, err := h.db.Query(`
			SELECT id, server_id, service_name, command_type, command, executed_by, executed_at, status, COALESCE(output, ''), COALESCE(duration_ms, 0)
			FROM command_execution_log
			WHERE server_id = $1
			ORDER BY executed_at DESC
			LIMIT 100
		`, serverID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		logs := []domain.CommandExecutionLog{}
		for rows.Next() {
			var l domain.CommandExecutionLog
			if err := rows.Scan(&l.ID, &l.ServerID, &l.ServiceName, &l.CommandType, &l.Command, &l.ExecutedBy, &l.ExecutedAt, &l.Status, &l.Output, &l.DurationMs); err == nil {
				logs = append(logs, l)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logs)

	default:
		http.Error(w, "Unknown command sub-path", http.StatusNotFound)
	}
}



func (h *APIHandler) HandleMonitoredProcesses(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	session, errSession := h.getSession(r)
	if errSession != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodGet {
		serverID := r.URL.Query().Get("server_id")
		if serverID == "" {
			http.Error(w, "server_id parameter required", http.StatusBadRequest)
			return
		}

		allowed, _ := h.checkServerPermission(serverID, session.Username, "viewer")
		if !allowed {
			http.Error(w, "Forbidden: You do not have permission to view monitored processes on this server.", http.StatusForbidden)
			return
		}

		rows, err := h.db.Query("SELECT id, server_id, process_name, process_pid, command_line FROM monitored_processes WHERE server_id = $1", serverID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		processes := []domain.MonitoredProcess{}
		for rows.Next() {
			var p domain.MonitoredProcess
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

		allowed, _ := h.checkServerPermission(payload.ServerID, session.Username, "operator")
		if !allowed {
			http.Error(w, "Forbidden: You do not have permission to manage monitored processes on this server.", http.StatusForbidden)
			return
		}

		// Clear existing monitored processes for this server
		_, err := h.db.Exec("DELETE FROM monitored_processes WHERE server_id = $1", payload.ServerID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Insert new monitored processes
		for _, proc := range payload.Processes {
			_, err := h.db.Exec("INSERT INTO monitored_processes (server_id, process_name, process_pid, command_line) VALUES ($1, $2, $3, $4) ON CONFLICT (server_id, process_name, process_pid) DO UPDATE SET command_line = EXCLUDED.command_line",
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
func (h *APIHandler) HandleMonitoredApplications(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	session, errSession := h.getSession(r)
	if errSession != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodGet {
		serverID := r.URL.Query().Get("server_id")
		if serverID == "" {
			http.Error(w, "server_id parameter required", http.StatusBadRequest)
			return
		}

		allowed, _ := h.checkServerPermission(serverID, session.Username, "viewer")
		if !allowed {
			http.Error(w, "Forbidden: You do not have permission to view monitored applications on this server.", http.StatusForbidden)
			return
		}

		rows, err := h.db.Query("SELECT id, server_id, application_name FROM monitored_applications WHERE server_id = $1", serverID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		applications := []domain.MonitoredApplication{}
		for rows.Next() {
			var app domain.MonitoredApplication
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

		allowed, _ := h.checkServerPermission(payload.ServerID, session.Username, "operator")
		if !allowed {
			http.Error(w, "Forbidden: You do not have permission to manage monitored applications on this server.", http.StatusForbidden)
			return
		}

		// Clear existing monitored applications for this server
		_, err := h.db.Exec("DELETE FROM monitored_applications WHERE server_id = $1", payload.ServerID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Insert new monitored applications
		for _, appName := range payload.Applications {
			_, err := h.db.Exec("INSERT INTO monitored_applications (server_id, application_name) VALUES ($1, $2) ON CONFLICT (server_id, application_name) DO NOTHING",
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

func (h *APIHandler) HandleRoot(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/index.html")
}

// handleAgentIngest receives metrics pushed by a target agent (hybrid push path).
// Route: POST /api/ingest/{serverID}/metrics
func (h *APIHandler) HandleAgentIngest(w http.ResponseWriter, r *http.Request) {
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

	if parts[3] == "logs" {
		var entry struct {
			Endpoint   string `json:"endpoint"`
			Action     string `json:"action"`
			StatusCode int    `json:"status_code"`
			Error      string `json:"error"`
		}
		if err := json.NewDecoder(r.Body).Decode(&entry); err == nil {
			log.Printf("[Agent Log Ingest] API failure on server %s (%s %s, status %d): %s",
				serverID, entry.Endpoint, entry.Action, entry.StatusCode, entry.Error)
			_, _ = h.db.Exec(`
				INSERT INTO api_failure_logs (server_id, endpoint, action, status_code, error_message)
				VALUES ($1, $2, $3, $4, $5)`,
				serverID, entry.Endpoint, entry.Action, entry.StatusCode, entry.Error)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
	if err := h.db.QueryRow("SELECT EXISTS(SELECT 1 FROM servers WHERE id=$1)", serverID).Scan(&exists); err != nil || !exists {
		http.Error(w, "Unknown server", http.StatusNotFound)
		return
	}

	metricsMap := map[string]interface{}{
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
	}

	h.redis.SetCachedMetrics(serverID, metricsMap, 60)
	h.persistMetricSample(serverID, metricsMap)
	_, _ = h.db.Exec("UPDATE servers SET status = 'online', last_seen = NOW() WHERE id = $1", serverID)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"stored"}`))
}

// detectHostIP picks the best address for agents to push metrics to.
// Inside Docker, host.docker.internal resolves to the host but that's only
// reachable from within Docker containers, not from remote LAN servers.
// We prefer actual LAN IPs (192.168.x.x, 10.x.x.x) so remote targets can reach us.


	



func (h *APIHandler) getSession(r *http.Request) (*domain.UserSession, error) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil, err
	}
	sessionJSON, err := h.redis.Get("session:" + cookie.Value)
	if err != nil || sessionJSON == "" {
		return nil, fmt.Errorf("session not found")
	}
	var session domain.UserSession
	if err := json.Unmarshal([]byte(sessionJSON), &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func roleSatisfies(role, required string) bool {
	if role == "admin" {
		return true
	}
	if role == "operator" || role == "member" {
		return required == "operator" || required == "member" || required == "viewer"
	}
	if role == "viewer" {
		return required == "viewer"
	}
	return false
}

func (h *APIHandler) checkServerPermission(serverID string, username string, requiredRole string) (bool, string) {
	username = strings.ToLower(strings.TrimSpace(username))
	var count int
	_ = h.db.QueryRow("SELECT COUNT(*) FROM server_members WHERE server_id = $1", serverID).Scan(&count)
	if count == 0 {
		_, _ = h.db.Exec("INSERT INTO server_members (server_id, username, role) VALUES ($1, $2, 'admin') ON CONFLICT (server_id, username) DO NOTHING", serverID, username)
		return true, "admin"
	}

	var role string
	err := h.db.QueryRow("SELECT role FROM server_members WHERE server_id = $1 AND LOWER(username) = $2", serverID, username).Scan(&role)
	if err != nil {
		return false, ""
	}

	return roleSatisfies(role, requiredRole), role
}

func (h *APIHandler) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Bypass authorization for OAuth endpoints
		if strings.HasPrefix(path, "/api/auth/") {
			next(w, r)
			return
		}

		// Bypass authorization for agent-facing endpoints (push-model)
		if path == "/api/register" || strings.HasPrefix(path, "/api/ingest/") {
			next(w, r)
			return
		}

		// Check session
		_, err := h.getSession(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func (h *APIHandler) HandleAuthLogin(w http.ResponseWriter, r *http.Request) {
	clientID := os.Getenv("GITHUB_CLIENT_ID")
	if clientID == "" {
		log.Println("[auth] Warning: GITHUB_CLIENT_ID is not configured.")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>OAuth Configuration Required</title><style>body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#f8fafc;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;} .card{background:#1e293b;padding:32px;border-radius:12px;border:1px solid #334155;box-shadow:0 10px 25px rgba(0,0,0,0.5);max-width:500px;text-align:center;} h2{color:#f59e0b;margin-top:0;font-size:20px;} p{color:#94a3b8;line-height:1.6;font-size:14px;} code{background:#0f172a;padding:3px 8px;border-radius:6px;color:#38bdf8;font-family:monospace;font-size:13px;} .btn{display:inline-block;margin-top:16px;padding:10px 20px;background:#3b82f6;color:#fff;text-decoration:none;border-radius:6px;font-weight:500;}</style></head>
<body>
<div class="card">
<h2>⚠️ GitHub OAuth Credentials Missing</h2>
<p>To enable GitHub Single Sign-On, please add your <code>GITHUB_CLIENT_ID</code> and <code>GITHUB_CLIENT_SECRET</code> to your <code>cluster-host/.env</code> file and restart the stack.</p>
<a href="/" class="btn">&larr; Return to Dashboard</a>
</div>
</body>
</html>`)
		return
	}

	var redirectURI string
	if envRedirect := os.Getenv("GITHUB_REDIRECT_URI"); envRedirect != "" {
		redirectURI = envRedirect
	} else if hostEP := os.Getenv("HOST_ENDPOINT"); hostEP != "" {
		redirectURI = strings.TrimRight(hostEP, "/") + "/api/auth/github/callback"
	} else {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		}
		redirectURI = fmt.Sprintf("%s://%s/api/auth/github/callback", scheme, r.Host)
	}

	authURL := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=user:email", clientID, redirectURI)
	if prompt := r.URL.Query().Get("prompt"); prompt != "" {
		authURL += fmt.Sprintf("&prompt=%s", url.QueryEscape(prompt))
	}
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (h *APIHandler) HandleAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code from GitHub", http.StatusBadRequest)
		return
	}

	clientID := os.Getenv("GITHUB_CLIENT_ID")
	clientSecret := os.Getenv("GITHUB_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		http.Error(w, "GitHub OAuth credentials not configured on Host", http.StatusInternalServerError)
		return
	}

	// 1. Exchange code for access token
	tokenURL := "https://github.com/login/oauth/access_token"
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code", code)

	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(w, "Failed to create token exchange request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		http.Error(w, "Failed to parse token response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if tokenResp.AccessToken == "" {
		http.Error(w, "Access token was empty. Check credentials.", http.StatusUnauthorized)
		return
	}

	// 2. Fetch User Profile
	userReq, err := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	userReq.Header.Set("Accept", "application/json")

	userResp, err := client.Do(userReq)
	if err != nil {
		http.Error(w, "Failed to retrieve user profile: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer userResp.Body.Close()

	var githubUser struct {
		Login string `json:"login"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&githubUser); err != nil {
		http.Error(w, "Failed to decode user profile: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 3. Fetch User Emails to find primary verified email
	emailReq, err := http.NewRequest(http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	emailReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	emailReq.Header.Set("Accept", "application/json")

	emailResp, err := client.Do(emailReq)
	if err != nil {
		http.Error(w, "Failed to retrieve emails: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer emailResp.Body.Close()

	type GitHubEmail struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	var githubEmails []GitHubEmail
	if err := json.NewDecoder(emailResp.Body).Decode(&githubEmails); err != nil {
		log.Printf("[auth] Warning: Failed to parse emails list: %v", err)
	}

	primaryEmail := githubUser.Email
	for _, e := range githubEmails {
		if e.Primary {
			primaryEmail = e.Email
			break
		}
	}
	if primaryEmail == "" && len(githubEmails) > 0 {
		primaryEmail = githubEmails[0].Email
	}
	if primaryEmail == "" {
		primaryEmail = fmt.Sprintf("%s@users.noreply.github.com", githubUser.Login)
	}

	// 3.5 Sync email to server_members table
	if primaryEmail != "" {
		_, _ = h.db.Exec("UPDATE server_members SET email = $1 WHERE username = $2", primaryEmail, strings.ToLower(githubUser.Login))
	}

	// 4. Save session in Redis (expires in 24 hours)
	sessionID := uuid.New().String()
	sessionData := domain.UserSession{
		Username: strings.ToLower(githubUser.Login),
		Email:    primaryEmail,
	}
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		http.Error(w, "Failed to serialize session", http.StatusInternalServerError)
		return
	}

	err = h.redis.SetEX("session:"+sessionID, string(sessionBytes), 86400)
	if err != nil {
		http.Error(w, "Failed to save session in cache", http.StatusInternalServerError)
		return
	}

	// 5. Set session cookie and redirect to root dashboard
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400,
	})

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (h *APIHandler) HandleAuthLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil && cookie.Value != "" {
		_ = h.redis.Del("session:" + cookie.Value)
	}

	// Evict cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/static/login.html", http.StatusTemporaryRedirect)
}

func (h *APIHandler) HandleAuthUser(w http.ResponseWriter, r *http.Request) {
	session, err := h.getSession(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

func (h *APIHandler) HandleStreamMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	serverID := r.URL.Query().Get("server_id")
	channel := "metrics_stream_global"
	if serverID != "" {
		channel = "metrics_stream:" + serverID
	}

	if h.redis == nil || h.redis.Client == nil {
		http.Error(w, "Redis PubSub unavailable", http.StatusInternalServerError)
		return
	}

	pubsub := h.redis.Client.Subscribe(r.Context(), channel)
	defer pubsub.Close()

	ch := pubsub.Channel()
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case msg, open := <-ch:
			if !open {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", msg.Payload)
			flusher.Flush()
		}
	}
}

func (h *APIHandler) HandleAgentWS(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	token := r.URL.Query().Get("token")

	log.Printf("[ws-server] incoming request from client: server_id=%s, token=%s", serverID, token)

	if serverID == "" {
		log.Printf("[ws-server] reject: missing server_id")
		http.Error(w, "Bad Request: missing server_id query parameter", http.StatusBadRequest)
		return
	}

	var dbToken string
	err := h.db.QueryRow("SELECT COALESCE(agent_token, '') FROM servers WHERE id=$1", serverID).Scan(&dbToken)
	if err != nil {
		log.Printf("[ws-server] reject: database error querying server %s: %v", serverID, err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if dbToken != "" && dbToken != token {
		log.Printf("[ws-server] reject: token mismatch for server %s (db:%s, req:%s)", serverID, dbToken, token)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	log.Printf("[ws-server] auth successful for server %s. Upgrading connection...", serverID)

	var wsUpgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ws-server] upgrade failed for %s: %v", serverID, err)
		return
	}

	_ = wsPkg.Manager.Register(serverID, conn)
	log.Printf("[ws-server] agent registered: server_id=%s", serverID)

	_, _ = h.db.Exec("UPDATE servers SET status = 'online', last_seen = NOW() WHERE id = $1", serverID)

	go func() {
		defer func() {
			wsPkg.Manager.Unregister(serverID)
			_, _ = h.db.Exec("UPDATE servers SET status = 'offline' WHERE id = $1", serverID)
			log.Printf("[ws-server] agent disconnected: server_id=%s", serverID)
		}()

		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				log.Printf("[ws-server] read error from server %s: %v", serverID, err)
				break
			}

			var resp struct {
				ID      string          `json:"id"`
				Status  int             `json:"status"`
				Payload json.RawMessage `json:"payload"`
			}

			if err := json.Unmarshal(msg, &resp); err == nil && resp.ID != "" {
				wsPkg.Manager.DispatchResponse(resp.ID, resp.Payload)
			}
		}
	}()
}

func (h *APIHandler) HandleHostDiagnostics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}
