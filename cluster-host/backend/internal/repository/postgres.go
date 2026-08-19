package repository

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
	"cluster-backend/internal/config"
)

type PostgresDB struct {
	DB *sql.DB
}

func NewPostgres(cfg *config.Config) (*PostgresDB, error) {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s timezone=UTC",
		cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBSSLMode)

	var db *sql.DB
	var err error
	for i := 0; i < 15; i++ {
		log.Printf("[postgres] Connecting to PostgreSQL (attempt %d/15)...", i+1)
		db, err = sql.Open("postgres", connStr)
		if err == nil {
			err = db.Ping()
			if err == nil {
				log.Println("[postgres] Successfully connected to PostgreSQL database!")
				break
			}
		}
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		return nil, fmt.Errorf("could not connect to database: %w", err)
	}

	p := &PostgresDB{DB: db}
	if err := p.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return p, nil
}

func (p *PostgresDB) initSchema() error {
	createTablesQueries := []string{
		`CREATE TABLE IF NOT EXISTS servers (
			id UUID PRIMARY KEY,
			hostname VARCHAR(255) NOT NULL,
			ip_address VARCHAR(45) NOT NULL,
			os_family VARCHAR(50) NOT NULL,
			agent_token VARCHAR(255) NOT NULL,
			ssh_user VARCHAR(255),
			ssh_key TEXT,
			ssh_password TEXT,
			ssh_port INTEGER DEFAULT 22,
			status VARCHAR(50) DEFAULT 'unknown',
			last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
			created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
			owner_id VARCHAR(255)
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
			is_firing BOOLEAN DEFAULT FALSE,
			target_type VARCHAR(50) DEFAULT 'server',
			target_value VARCHAR(255) DEFAULT '',
			recipient_type VARCHAR(50) DEFAULT 'self',
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
		`CREATE TABLE IF NOT EXISTS api_failure_logs (
			id SERIAL PRIMARY KEY,
			server_id UUID NOT NULL,
			endpoint VARCHAR(255) NOT NULL,
			action VARCHAR(100),
			status_code INTEGER,
			error_message TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS server_members (
			id SERIAL PRIMARY KEY,
			server_id UUID NOT NULL,
			username VARCHAR(255) NOT NULL,
			role VARCHAR(50) DEFAULT 'member',
			email VARCHAR(255) DEFAULT '',
			permissions JSONB,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE,
			CONSTRAINT unique_server_member UNIQUE(server_id, username)
		);`,
		`CREATE TABLE IF NOT EXISTS server_access_tokens (
			id SERIAL PRIMARY KEY,
			server_id UUID NOT NULL,
			token VARCHAR(255) UNIQUE NOT NULL,
			created_by VARCHAR(255) NOT NULL,
			expires_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
		);`,
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
		`CREATE TABLE IF NOT EXISTS custom_commands (
			id SERIAL PRIMARY KEY,
			server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
			service_name VARCHAR(255) NOT NULL,
			commands JSONB NOT NULL,
			created_by VARCHAR(255) NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			CONSTRAINT unique_server_service_command UNIQUE(server_id, service_name)
		);`,
		`CREATE TABLE IF NOT EXISTS command_execution_log (
			id SERIAL PRIMARY KEY,
			server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
			service_name VARCHAR(255) NOT NULL,
			command_type VARCHAR(50) NOT NULL,
			command TEXT NOT NULL,
			executed_by VARCHAR(255) NOT NULL,
			executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			status VARCHAR(50) DEFAULT 'pending',
			output TEXT,
			duration_ms INTEGER DEFAULT 0
		);`,
		`CREATE INDEX IF NOT EXISTS idx_metrics_history_server_time ON metrics_history(server_id, sampled_at);`,
		`CREATE INDEX IF NOT EXISTS idx_monitored_services_server_id ON monitored_services(server_id);`,
		`CREATE INDEX IF NOT EXISTS idx_alert_rules_server_id ON alert_rules(server_id);`,
		`CREATE INDEX IF NOT EXISTS idx_servers_status ON servers(status);`,
		`CREATE INDEX IF NOT EXISTS idx_server_members_user ON server_members(username);`,
	}

	for _, query := range createTablesQueries {
		if _, err := p.DB.Exec(query); err != nil {
			log.Printf("[postgres] Table creation query note: %v", err)
		}
	}

	log.Println("[postgres] Database schema successfully initialized.")
	return nil
}
