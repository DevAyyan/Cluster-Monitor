package api

import (
	"net/http"
)

func NewRouter(h *APIHandler) *http.ServeMux {
	mux := http.NewServeMux()

	// Persistent agent WebSocket handlers
	mux.HandleFunc("/api/ws", h.HandleAgentWS)
	mux.HandleFunc("/api/v1/ws", h.HandleAgentWS)

	// Agent-initiated self-registration & public ingestion (no auth/SSH needed)
	mux.HandleFunc("/api/agent/self-register", h.HandleAgentSelfRegister)
	mux.HandleFunc("/api/register", h.HandleRegister)
	mux.HandleFunc("/api/ingest/", h.HandleAgentIngest)

	// Server management & control endpoints
	mux.HandleFunc("/api/servers", h.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.HandleGetServers(w, r)
		case http.MethodPost:
			h.HandleRegister(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))

	mux.HandleFunc("/api/v1/servers", h.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.HandleGetServers(w, r)
		case http.MethodPost:
			h.HandleRegister(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))

	mux.HandleFunc("/api/servers/active", h.AuthMiddleware(h.HandleGetActiveServers))
	mux.HandleFunc("/api/servers/unregister", h.AuthMiddleware(h.HandleUnregisterServer))
	mux.HandleFunc("/api/servers/detail/", h.AuthMiddleware(h.HandleServerDetail))
	mux.HandleFunc("/api/servers/toggle/", h.AuthMiddleware(h.HandleToggleService))
	mux.HandleFunc("/api/servers/control/", h.AuthMiddleware(h.HandleServiceControl))
	mux.HandleFunc("/api/servers/control/kill/", h.AuthMiddleware(h.HandleKillProcessControl))
	mux.HandleFunc("/api/servers/control/kill-by-name/", h.AuthMiddleware(h.HandleKillApplicationControl))
	mux.HandleFunc("/api/servers/test-ssh", h.AuthMiddleware(h.HandleTestSSH))

	// Server members & RBAC
	mux.HandleFunc("/api/servers/members", h.AuthMiddleware(h.HandleServerMembers))
	mux.HandleFunc("/api/servers/members/invite", h.AuthMiddleware(h.HandleServerInvite))
	mux.HandleFunc("/api/servers/members/remove", h.AuthMiddleware(h.HandleServerRemove))
	mux.HandleFunc("/api/servers/members/role", h.AuthMiddleware(h.HandleServerRole))

	// Alerts & monitored assets
	mux.HandleFunc("/api/alerts/rules", h.AuthMiddleware(h.HandleAlertRules))
	mux.HandleFunc("/api/monitored/processes", h.AuthMiddleware(h.HandleMonitoredProcesses))
	mux.HandleFunc("/api/monitored/applications", h.AuthMiddleware(h.HandleMonitoredApplications))

	// Stream Endpoints
	mux.HandleFunc("/api/stream/metrics", h.AuthMiddleware(h.HandleStreamMetrics))

	// Auth Endpoints
	mux.HandleFunc("/api/auth/login", h.HandleAuthLogin)
	mux.HandleFunc("/api/auth/github/callback", h.HandleAuthCallback)
	mux.HandleFunc("/api/auth/logout", h.HandleAuthLogout)
	mux.HandleFunc("/api/auth/user", h.HandleAuthUser)

	// Host Self-Diagnostics Endpoint
	mux.HandleFunc("/api/v1/system/diagnostics", h.HandleHostDiagnostics)

	return mux
}
