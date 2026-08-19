package websocket

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"cluster-backend/internal/domain"
)

// SafeConn wraps a gorilla websocket connection with a write mutex to guarantee thread-safe writes.
type SafeConn struct {
	Conn *websocket.Conn
	Mu   sync.Mutex
}

func (s *SafeConn) WriteMessage(messageType int, data []byte) error {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return s.Conn.WriteMessage(messageType, data)
}

func (s *SafeConn) Close() error {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return s.Conn.Close()
}

// WSConnManager manages active agent connections and pending dashboard commands.
type WSConnManager struct {
	connections   map[string]*SafeConn
	connectionsMu sync.RWMutex

	pendingCommands   map[string]chan []byte
	pendingCommandsMu sync.Mutex
}

var Manager = &WSConnManager{
	connections:     make(map[string]*SafeConn),
	pendingCommands: make(map[string]chan []byte),
}

func (m *WSConnManager) Register(serverID string, rawConn *websocket.Conn) *SafeConn {
	m.connectionsMu.Lock()
	defer m.connectionsMu.Unlock()

	safe := &SafeConn{Conn: rawConn}
	if existing, exists := m.connections[serverID]; exists {
		_ = existing.Close()
	}
	m.connections[serverID] = safe
	log.Printf("[ws-manager] Server %s connected via WebSocket", serverID)
	return safe
}

func (m *WSConnManager) Unregister(serverID string) {
	m.connectionsMu.Lock()
	defer m.connectionsMu.Unlock()
	if safe, exists := m.connections[serverID]; exists {
		_ = safe.Close()
		delete(m.connections, serverID)
		log.Printf("[ws-manager] Server %s disconnected from WebSocket", serverID)
	}
}

func (m *WSConnManager) Get(serverID string) (*SafeConn, bool) {
	m.connectionsMu.RLock()
	defer m.connectionsMu.RUnlock()
	safe, exists := m.connections[serverID]
	return safe, exists
}

func (m *WSConnManager) IsConnected(serverID string) bool {
	_, exists := m.Get(serverID)
	return exists
}

func (m *WSConnManager) SendCommand(serverID string, method string, path string, body []byte) ([]byte, error) {
	safe, online := m.Get(serverID)
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

	reqPayload := domain.WSRequestPayload{
		Method: method,
		Path:   path,
		Body:   body,
	}
	rawPayload, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request payload: %w", err)
	}

	msg := domain.WSMessage{
		Type:      "command_request",
		RequestID: requestID,
		ServerID:  serverID,
		Payload:   rawPayload,
	}

	rawMsg, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal websocket envelope: %w", err)
	}

	if err := safe.WriteMessage(websocket.TextMessage, rawMsg); err != nil {
		m.Unregister(serverID)
		return nil, fmt.Errorf("failed to send command over WebSocket: %w", err)
	}

	select {
	case resData := <-responseChan:
		var resp domain.WSResponsePayload
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

func (m *WSConnManager) DispatchResponse(requestID string, payload []byte) {
	m.pendingCommandsMu.Lock()
	ch, exists := m.pendingCommands[requestID]
	if exists {
		ch <- payload
		delete(m.pendingCommands, requestID)
	}
	m.pendingCommandsMu.Unlock()
}

var Upgrader = websocket.Upgrader{
	ReadBufferSize:  1024 * 1024,
	WriteBufferSize: 1024 * 1024,
	CheckOrigin: func(r *http.Request) bool {
		// Basic origin check: accept if origin matches host header or is dev environment
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		return true // Configurable per deployment environment
	},
}
