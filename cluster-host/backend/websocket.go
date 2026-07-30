package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// WSMessage represents the outer JSON envelope for all socket communications.
type WSMessage struct {
	Type      string          `json:"type"`       // "metrics", "command_request", "command_response", "heartbeat"
	RequestID string          `json:"request_id"` // Matches asynchronous replies to HTTP routines
	ServerID  string          `json:"server_id"`  // Identifies the agent
	Payload   json.RawMessage `json:"payload"`    // Inner payload
}

// WSRequestPayload models the HTTP-like request structure forwarded to the agent.
type WSRequestPayload struct {
	Method string `json:"method"` // GET or POST
	Path   string `json:"path"`   // e.g. "processes", "containers", "container-action"
	Body   []byte `json:"body"`   // Raw request body
}

// WSResponsePayload models the HTTP-like response returned by the agent.
type WSResponsePayload struct {
	StatusCode int    `json:"status_code"`
	Body       []byte `json:"body"`
}

// WSConnManager manages active agent connections and pending dashboard commands.
type WSConnManager struct {
	connections   map[string]*websocket.Conn
	connectionsMu sync.RWMutex

	pendingCommands   map[string]chan []byte
	pendingCommandsMu sync.Mutex
}

var wsManager = &WSConnManager{
	connections:     make(map[string]*websocket.Conn),
	pendingCommands: make(map[string]chan []byte),
}

func (m *WSConnManager) Register(serverID string, conn *websocket.Conn) {
	m.connectionsMu.Lock()
	defer m.connectionsMu.Unlock()
	if existing, exists := m.connections[serverID]; exists {
		existing.Close()
	}
	m.connections[serverID] = conn
	log.Printf("[ws-manager] Server %s connected via WebSocket", serverID)
}

func (m *WSConnManager) Unregister(serverID string) {
	m.connectionsMu.Lock()
	defer m.connectionsMu.Unlock()
	if conn, exists := m.connections[serverID]; exists {
		conn.Close()
		delete(m.connections, serverID)
		log.Printf("[ws-manager] Server %s disconnected from WebSocket", serverID)
	}
}

func (m *WSConnManager) Get(serverID string) (*websocket.Conn, bool) {
	m.connectionsMu.RLock()
	defer m.connectionsMu.RUnlock()
	conn, exists := m.connections[serverID]
	return conn, exists
}

// SendCommand serializes a command, sends it over the WebSocket, and waits synchronously for the response.
func (m *WSConnManager) SendCommand(serverID string, method string, path string, body []byte) ([]byte, error) {
	conn, online := m.Get(serverID)
	if !online {
		return nil, fmt.Errorf("target server offline (no active WebSocket connection)")
	}

	requestID := uuid.New().String()
	responseChan := make(chan []byte, 1)

	m.pendingCommandsMu.Lock()
	m.pendingCommands[requestID] = responseChan
	m.pendingCommandsMu.Unlock()

	defer func() {
		m.pendingCommandsMu.Lock()
		delete(m.pendingCommands, requestID)
		m.pendingCommandsMu.Unlock()
	}()

	// Construct request payload
	reqPayload := WSRequestPayload{
		Method: method,
		Path:   path,
		Body:   body,
	}
	rawPayload, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request payload: %w", err)
	}

	msg := WSMessage{
		Type:      "command_request",
		RequestID: requestID,
		ServerID:  serverID,
		Payload:   rawPayload,
	}

	rawMsg, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal websocket envelope: %w", err)
	}

	// Write command message
	if err := conn.WriteMessage(websocket.TextMessage, rawMsg); err != nil {
		// Connection might have broken
		m.Unregister(serverID)
		return nil, fmt.Errorf("failed to send command over WebSocket: %w", err)
	}

	// Wait with 8s timeout
	select {
	case resData := <-responseChan:
		var resp WSResponsePayload
		if err := json.Unmarshal(resData, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse agent response: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("agent returned error status %d: %s", resp.StatusCode, string(resp.Body))
		}
		return resp.Body, nil

	case <-time.After(8 * time.Second):
		return nil, fmt.Errorf("agent response timed out after 8s")
	}
}

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024 * 1024,
	WriteBufferSize: 1024 * 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connection from the dashboard stack
	},
}

func handleAgentWS(w http.ResponseWriter, r *http.Request) {
	serverID := r.URL.Query().Get("server_id")
	token := r.URL.Query().Get("token")

	log.Printf("[ws-server] incoming request from client: server_id=%s, token=%s", serverID, token)

	if serverID == "" {
		log.Printf("[ws-server] reject: missing server_id")
		http.Error(w, "Bad Request: missing server_id query parameter", http.StatusBadRequest)
		return
	}

	// Validate agent token
	var dbToken string
	err := db.QueryRow("SELECT COALESCE(agent_token, '') FROM servers WHERE id=$1", serverID).Scan(&dbToken)
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

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ws-server] upgrade failed for %s: %v", serverID, err)
		return
	}

	wsManager.Register(serverID, conn)

	// Keep-alive settings
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPingHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		_ = conn.WriteMessage(websocket.PongMessage, nil)
		return nil
	})

	// Read loop
	go func() {
		defer wsManager.Unregister(serverID)
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				log.Printf("[ws-server] connection closed for %s: %v", serverID, err)
				break
			}

			// Extend read deadline
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))

			var msg WSMessage
			if err := json.Unmarshal(data, &msg); err != nil {
				continue
			}

			switch msg.Type {
			case "metrics":
				var m map[string]interface{}
				if err := json.Unmarshal(msg.Payload, &m); err == nil {
					// 1. Save to Redis Cache (for fast UI updates)
					setCachedMetrics(serverID, m, 60)
					// 2. Persist to Postgres database (throttled to 1 sample per 5s)
					persistMetricSample(serverID, m)
					// 3. Update server status
					_, _ = db.Exec("UPDATE servers SET status = 'online', last_seen = NOW() WHERE id = $1", serverID)
				}
			case "heartbeat":
				_, _ = db.Exec("UPDATE servers SET status = 'online', last_seen = NOW() WHERE id = $1", serverID)
			case "command_response":
				wsManager.pendingCommandsMu.Lock()
				ch, exists := wsManager.pendingCommands[msg.RequestID]
				if exists {
					ch <- msg.Payload
					delete(wsManager.pendingCommands, msg.RequestID)
				}
				wsManager.pendingCommandsMu.Unlock()
			}
		}
	}()
}
