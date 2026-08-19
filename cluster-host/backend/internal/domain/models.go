package domain

import (
	"database/sql"
	"encoding/json"
	"time"
)

type UserSession struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

type Server struct {
	ID          string           `json:"id"`
	Hostname    string           `json:"hostname"`
	IPAddress   string           `json:"ip_address"`
	OSFamily    string           `json:"os_family"`
	AgentToken  string           `json:"agent_token,omitempty"`
	SSHUser     string           `json:"ssh_user,omitempty"`
	SSHKey      string           `json:"ssh_key,omitempty"`
	SSHPassword string           `json:"ssh_password,omitempty"`
	SSHPort     int              `json:"ssh_port,omitempty"`
	Status      string           `json:"status"`
	LastSeen    time.Time        `json:"last_seen"`
	CreatedAt   time.Time        `json:"created_at"`
	Role        string           `json:"role,omitempty"`
	Permissions *UserPermissions `json:"permissions,omitempty"`
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
	RecipientType   string       `json:"recipient_type"` // "self", "specific", "all"
	IsActive        bool         `json:"is_active"`
	LastTriggered   sql.NullTime `json:"last_triggered"`
	IsFiring        bool         `json:"is_firing"`
	TargetType      string       `json:"target_type"`  // "server", "process", "application"
	TargetValue     string       `json:"target_value"` // e.g. "postgres"
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

type CustomCommandSet struct {
	ID          int               `json:"id"`
	ServerID    string            `json:"server_id"`
	ServiceName string            `json:"service_name"`
	Commands    map[string]string `json:"commands"`
	CreatedBy   string            `json:"created_by"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type CommandExecutionLog struct {
	ID          int       `json:"id"`
	ServerID    string    `json:"server_id"`
	ServiceName string    `json:"service_name"`
	CommandType string    `json:"command_type"`
	ExecutedBy  string    `json:"executed_by"`
	ExecutedAt  time.Time `json:"executed_at"`
	Status      string    `json:"status"`
	Output      string    `json:"output"`
}

type UserPermissions struct {
	Tabs                   []string `json:"tabs"`
	Applications           []string `json:"applications"`
	Processes              []string `json:"processes"`
	AllowProcessKill       bool     `json:"allow_process_kill"`
	Containers             []string `json:"containers"`
	AllowContainerOperate  bool     `json:"allow_container_operate"`
	CustomCommandGroups    []string `json:"custom_command_groups"`
	AllowedCommandActions map[string][]string `json:"allowed_command_actions"`
}

func (p UserPermissions) HasTabAccess(tab string) bool {
	if len(p.Tabs) == 0 {
		return true
	}
	for _, t := range p.Tabs {
		if t == tab {
			return true
		}
	}
	return false
}

func (p UserPermissions) CanViewApplication(appName string) bool {
	if len(p.Applications) == 0 {
		return true
	}
	for _, a := range p.Applications {
		if a == appName {
			return true
		}
	}
	return false
}

func (p UserPermissions) CanViewProcess(procName string) bool {
	if len(p.Processes) == 0 {
		return true
	}
	for _, pr := range p.Processes {
		if pr == procName {
			return true
		}
	}
	return false
}

func (p UserPermissions) CanViewContainer(containerName string) bool {
	if len(p.Containers) == 0 {
		return true
	}
	for _, c := range p.Containers {
		if c == containerName {
			return true
		}
	}
	return false
}

func (p UserPermissions) CanOperateContainer(containerName string, command string) bool {
	if !p.CanViewContainer(containerName) {
		return false
	}
	return p.AllowContainerOperate
}

func (p UserPermissions) CanViewCustomCommandGroup(serviceName string) bool {
	if len(p.CustomCommandGroups) == 0 {
		return true
	}
	for _, g := range p.CustomCommandGroups {
		if g == serviceName {
			return true
		}
	}
	return false
}

func (p UserPermissions) CanExecuteCustomCommand(serviceName string, actionKey string) bool {
	if !p.CanViewCustomCommandGroup(serviceName) {
		return false
	}
	if len(p.AllowedCommandActions) == 0 {
		return true
	}
	allowedActions, exists := p.AllowedCommandActions[serviceName]
	if !exists {
		return true
	}
	for _, act := range allowedActions {
		if act == actionKey {
			return true
		}
	}
	return false
}

type WSMessage struct {
	Type      string          `json:"type"`       // "metrics", "command_request", "command_response", "heartbeat"
	RequestID string          `json:"request_id"` // Matches asynchronous replies to HTTP routines
	ServerID  string          `json:"server_id"`  // Identifies the agent
	Payload   json.RawMessage `json:"payload"`    // Inner payload
}

type WSRequestPayload struct {
	Method string `json:"method"` // GET or POST
	Path   string `json:"path"`   // e.g. "processes", "containers", "container-action"
	Body   []byte `json:"body"`   // Raw request body
}

type WSResponsePayload struct {
	StatusCode int    `json:"status_code"`
	Body       []byte `json:"body"`
}

type FleetJob struct {
	ID       string `json:"id"`
	Type     string `json:"type"` // "fetch_metrics", "fetch_processes", "fetch_storage", "fetch_containers"
	ServerID string `json:"server_id"`
}
