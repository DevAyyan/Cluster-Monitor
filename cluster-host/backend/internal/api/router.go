package api

import (
	"net/http"
)

func NewRouter(h *APIHandler) *http.ServeMux {
	mux := http.NewServeMux()

	// WebSocket agent hub
	mux.HandleFunc("/api/ws", h.HandleAgentWS)
	mux.HandleFunc("/api/v1/ws", h.HandleAgentWS)

	// Auth Endpoints
	mux.HandleFunc("/api/auth/login", h.HandleAuthLogin)
	mux.HandleFunc("/api/auth/github/callback", h.HandleAuthCallback)
	mux.HandleFunc("/api/auth/logout", h.HandleAuthLogout)
	mux.HandleFunc("/api/auth/user", h.HandleAuthUser)

	// Stream Endpoints
	mux.HandleFunc("/api/stream/metrics", h.AuthMiddleware(h.HandleStreamMetrics))

	// Server management endpoints
	serverHandler := func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.HandleGetServers(w, r)
		case http.MethodPost:
			h.HandleRegisterServer(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}

	mux.HandleFunc("/api/servers", h.AuthMiddleware(serverHandler))
	mux.HandleFunc("/api/v1/servers", h.AuthMiddleware(serverHandler))

	// Diagnostics Endpoint
	mux.HandleFunc("/api/v1/system/diagnostics", h.HandleHostDiagnostics)

	return mux
}
