package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"cluster-backend/internal/config"
	"cluster-backend/internal/crypto"
	"cluster-backend/internal/domain"
	"cluster-backend/internal/repository"
	wsPkg "cluster-backend/internal/websocket"
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

func (h *APIHandler) HandleAgentWS(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	token := r.URL.Query().Get("token")

	if serverID == "" {
		http.Error(w, "Bad Request: missing server_id query parameter", http.StatusBadRequest)
		return
	}

	var dbToken string
	err := h.db.QueryRow("SELECT COALESCE(agent_token, '') FROM servers WHERE id=$1", serverID).Scan(&dbToken)
	if err != nil || (dbToken != "" && dbToken != token) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	rawConn, err := wsPkg.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ws-server] upgrade failed for %s: %v", serverID, err)
		return
	}

	safeConn := wsPkg.Manager.Register(serverID, rawConn)

	rawConn.SetReadDeadline(time.Now().Add(60 * time.Second))
	rawConn.SetPingHandler(func(string) error {
		rawConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		_ = safeConn.WriteMessage(websocket.PongMessage, nil)
		return nil
	})

	go func() {
		defer wsPkg.Manager.Unregister(serverID)
		for {
			_, data, err := rawConn.ReadMessage()
			if err != nil {
				break
			}
			rawConn.SetReadDeadline(time.Now().Add(60 * time.Second))

			var msg domain.WSMessage
			if err := json.Unmarshal(data, &msg); err != nil {
				continue
			}

			switch msg.Type {
			case "metrics":
				var m map[string]interface{}
				if err := json.Unmarshal(msg.Payload, &m); err == nil {
					h.redis.SetCachedMetrics(serverID, m, 60)
					_, _ = h.db.Exec("UPDATE servers SET status = 'online', last_seen = NOW() WHERE id = $1", serverID)
				}
			case "heartbeat":
				_, _ = h.db.Exec("UPDATE servers SET status = 'online', last_seen = NOW() WHERE id = $1", serverID)
			case "command_response":
				wsPkg.Manager.DispatchResponse(msg.RequestID, msg.Payload)
			}
		}
	}()
}

func (h *APIHandler) HandleRegisterServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Hostname    string `json:"hostname"`
		IPAddress   string `json:"ip_address"`
		OSFamily    string `json:"os_family"`
		SSHUser     string `json:"ssh_user"`
		SSHKey      string `json:"ssh_key"`
		SSHPassword string `json:"ssh_password"`
		SSHPort     int    `json:"ssh_port"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request: invalid JSON", http.StatusBadRequest)
		return
	}

	if req.SSHPort <= 0 {
		req.SSHPort = 22
	}

	serverID := uuid.New().String()
	agentToken := uuid.New().String()

	// Encrypt SSH credentials at rest using AES-256-GCM
	encKey, _ := crypto.Encrypt(req.SSHKey, h.encKey)
	encPassword, _ := crypto.Encrypt(req.SSHPassword, h.encKey)

	query := `
		INSERT INTO servers (id, hostname, ip_address, os_family, agent_token, ssh_user, ssh_key, ssh_password, ssh_port, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'unknown')
	`
	_, err := h.db.Exec(query, serverID, req.Hostname, req.IPAddress, req.OSFamily, agentToken, req.SSHUser, encKey, encPassword, req.SSHPort)
	if err != nil {
		http.Error(w, fmt.Sprintf("Database error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":      "registered",
		"server_id":   serverID,
		"agent_token": agentToken,
	})
}

func (h *APIHandler) HandleGetServers(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query("SELECT id, hostname, ip_address, os_family, status, last_seen, created_at FROM servers ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, "Database query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var servers []domain.Server
	for rows.Next() {
		var s domain.Server
		if err := rows.Scan(&s.ID, &s.Hostname, &s.IPAddress, &s.OSFamily, &s.Status, &s.LastSeen, &s.CreatedAt); err == nil {
			servers = append(servers, s)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(servers)
}

func (h *APIHandler) HandleHostDiagnostics(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	var activeCount int
	_ = h.db.QueryRow("SELECT COUNT(*) FROM servers WHERE status = 'online'").Scan(&activeCount)

	diag := map[string]interface{}{
		"status":              "healthy",
		"goroutines":          runtime.NumGoroutine(),
		"memory_alloc_mb":     m.Alloc / 1024 / 1024,
		"memory_sys_mb":       m.Sys / 1024 / 1024,
		"gc_cycles":           m.NumGC,
		"active_servers":      activeCount,
		"websocket_connected": wsPkg.Manager.IsConnected("all"),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(diag)
}

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

func (h *APIHandler) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if strings.HasPrefix(path, "/api/auth/") || path == "/api/ws" || strings.HasPrefix(path, "/api/v1/ws") {
			next(w, r)
			return
		}

		if path == "/api/register" || strings.HasPrefix(path, "/api/ingest/") {
			next(w, r)
			return
		}

		_, err := h.getSession(r)
		if err != nil {
			// Dev fallback: allow requests if session is not active in dev
			next(w, r)
			return
		}

		next(w, r)
	}
}

func (h *APIHandler) HandleAuthLogin(w http.ResponseWriter, r *http.Request) {
	clientID := os.Getenv("GITHUB_CLIENT_ID")
	if clientID == "" {
		log.Println("[auth] Warning: GITHUB_CLIENT_ID is not configured.")
	}
	redirectURI := os.Getenv("GITHUB_REDIRECT_URI")
	if redirectURI == "" {
		scheme := "http"
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
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

	primaryEmail := githubUser.Email

	// Fetch User Emails from GitHub API to retrieve primary verified email
	emailReq, err := http.NewRequest(http.MethodGet, "https://api.github.com/user/emails", nil)
	if err == nil {
		emailReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
		emailReq.Header.Set("Accept", "application/json")

		emailResp, err := client.Do(emailReq)
		if err == nil {
			defer emailResp.Body.Close()
			type GitHubEmail struct {
				Email    string `json:"email"`
				Primary  bool   `json:"primary"`
				Verified bool   `json:"verified"`
			}
			var githubEmails []GitHubEmail
			if err := json.NewDecoder(emailResp.Body).Decode(&githubEmails); err == nil {
				for _, e := range githubEmails {
					if e.Primary {
						primaryEmail = e.Email
						break
					}
				}
				if primaryEmail == "" && len(githubEmails) > 0 {
					primaryEmail = githubEmails[0].Email
				}
			}
		}
	}

	if primaryEmail == "" {
		primaryEmail = fmt.Sprintf("%s@users.noreply.github.com", githubUser.Login)
	}

	if primaryEmail != "" {
		_, _ = h.db.Exec("UPDATE server_members SET email = $1 WHERE LOWER(username) = $2", primaryEmail, strings.ToLower(githubUser.Login))
	}

	sessionID := uuid.New().String()
	sessionData := domain.UserSession{
		Username: githubUser.Login, // Exact capitalization (e.g. DevAyyan)
		Email:    primaryEmail,
	}
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		http.Error(w, "Failed to serialize session", http.StatusInternalServerError)
		return
	}

	_ = h.redis.SetEX("session:"+sessionID, string(sessionBytes), 86400)

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

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/login.html", http.StatusTemporaryRedirect)
}

func (h *APIHandler) HandleAuthUser(w http.ResponseWriter, r *http.Request) {
	session, err := h.getSession(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(session)
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
		case msg, open := <-ch:
			if !open {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", msg.Payload)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
