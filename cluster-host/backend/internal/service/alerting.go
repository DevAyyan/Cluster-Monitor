package service

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/smtp"
	"strconv"
	"strings"
	"sync"
	"time"

	"cluster-backend/internal/config"
	"cluster-backend/internal/domain"
	"cluster-backend/internal/repository"
	"cluster-backend/internal/ssh"
)

type AlertService struct {
	db     *sql.DB
	redis  *repository.RedisClient
	cfg    *config.Config
	encKey string
}

func NewAlertService(db *sql.DB, redis *repository.RedisClient, cfg *config.Config) *AlertService {
	return &AlertService{
		db:     db,
		redis:  redis,
		cfg:    cfg,
		encKey: cfg.EncryptionKey,
	}
}

func (s *AlertService) StartAlertingLoop() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			rows, err := s.db.Query("SELECT id, server_id, metric_type, operator, threshold, duration_minutes, recipient_email, last_triggered, is_firing, target_type, target_value FROM alert_rules WHERE is_active = TRUE")
			if err != nil {
				log.Printf("[AlertEngine] Error querying rules: %v", err)
				continue
			}

			var rules []domain.AlertRule
			for rows.Next() {
				var rule domain.AlertRule
				if scanErr := rows.Scan(&rule.ID, &rule.ServerID, &rule.MetricType, &rule.Operator, &rule.Threshold, &rule.DurationMinutes, &rule.RecipientEmail, &rule.LastTriggered, &rule.IsFiring, &rule.TargetType, &rule.TargetValue); scanErr == nil {
					rules = append(rules, rule)
				}
			}
			rows.Close()

			var wg sync.WaitGroup
			for _, rule := range rules {
				wg.Add(1)
				go func(r domain.AlertRule) {
					defer wg.Done()
					s.evaluateAlertRule(r)
				}(rule)
			}
			wg.Wait()
		}
	}()
}

func (s *AlertService) StartMetricsPruningLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		s.pruneOldMetrics()
		for range ticker.C {
			s.pruneOldMetrics()
		}
	}()
}

func (s *AlertService) pruneOldMetrics() {
	res, err := s.db.Exec("DELETE FROM metrics_history WHERE sampled_at < NOW() - INTERVAL '7 days'")
	if err != nil {
		log.Printf("[cleanup] failed to prune metrics_history: %v", err)
	} else {
		rows, _ := res.RowsAffected()
		if rows > 0 {
			log.Printf("[cleanup] successfully pruned %d records older than 7 days from metrics_history", rows)
		}
	}
}

func ConvertToFloat(val interface{}) float64 {
	if val == nil {
		return 0
	}
	switch v := val.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return 0
}

func (s *AlertService) evaluateAlertRule(rule domain.AlertRule) {
	info, err := ssh.LoadServerSSHInfo(s.db, s.encKey, rule.ServerID)
	if err != nil {
		return
	}
	hostname := info.Host
	ipAddress := info.Host

	var val float64
	var found bool = false
	var triggered bool = false

	if rule.TargetType == "process" || rule.TargetType == "application" {
		var processes []map[string]interface{}
		if ssh.IsDemoServer(info, rule.ServerID) {
			processes = []map[string]interface{}{
				{"pid": "1", "name": "systemd", "user": "root", "cpu": 0.1, "mem": 12.4},
				{"pid": "1042", "name": "postgres", "user": "postgres", "cpu": 85.2, "mem": 142.1},
			}
		} else {
			procsJSON, ok := s.redis.GetCachedJSON("processes:" + rule.ServerID)
			if ok && procsJSON != "" {
				_ = json.Unmarshal([]byte(procsJSON), &processes)
			}
			if len(processes) == 0 {
				procs, err := ssh.SSHGetProcesses(info)
				if err == nil {
					processes = procs
					s.redis.SetCachedJSON("processes:"+rule.ServerID, procs, 60)
				}
			}
		}

		var sumCPU float64
		var sumRAM float64
		var instances int

		for _, proc := range processes {
			procName, _ := proc["name"].(string)
			if strings.EqualFold(procName, rule.TargetValue) {
				instances++
				if cpuVal, ok := proc["cpu"]; ok {
					sumCPU += ConvertToFloat(cpuVal)
				}
				if memVal, ok := proc["mem"]; ok {
					sumRAM += ConvertToFloat(memVal)
				}
			}
		}

		if rule.MetricType == "process_down" {
			found = true
			val = float64(instances)
			triggered = (instances == 0)
		} else {
			found = instances > 0
			if rule.MetricType == "cpu" {
				val = sumCPU
			} else if rule.MetricType == "ram" {
				val = sumRAM
			}
		}
	} else {
		// Server metrics
		m, ok := s.redis.GetCachedMetrics(rule.ServerID)
		if !ok {
			freshM, err := ssh.SSHGetMetrics(info)
			if err == nil {
				m = freshM
				s.redis.SetCachedMetrics(rule.ServerID, m, 60)
				ok = true
			}
		}
		if ok {
			found = true
			switch rule.MetricType {
			case "cpu":
				val = ConvertToFloat(m["cpu"])
			case "ram":
				val = ConvertToFloat(m["ram_used_pct"])
			case "disk":
				val = ConvertToFloat(m["disk_used_pct"])
			}
		}
	}

	if !found {
		return
	}

	if rule.MetricType != "process_down" {
		if rule.Operator == ">" {
			triggered = val > rule.Threshold
		} else if rule.Operator == "<" {
			triggered = val < rule.Threshold
		}
	}

	if triggered {
		if !rule.IsFiring {
			_, _ = s.db.Exec("UPDATE alert_rules SET is_firing = TRUE, last_triggered = NOW() WHERE id = $1", rule.ID)
			rule.IsFiring = true
			s.SendAlertEmail(rule, hostname, ipAddress, val, false)
		}
	} else {
		if rule.IsFiring {
			_, _ = s.db.Exec("UPDATE alert_rules SET is_firing = FALSE WHERE id = $1", rule.ID)
			rule.IsFiring = false
			s.SendAlertEmail(rule, hostname, ipAddress, val, true)
		}
	}
}

func (s *AlertService) SendAlertEmail(rule domain.AlertRule, hostname, ipAddress string, currentValue float64, isResolved bool) {
	if s.cfg.SMTPHost == "" {
		log.Printf("[alerting] SMTP host not configured, skipping alert email for rule #%d", rule.ID)
		return
	}

	subject := fmt.Sprintf("[ALERT] %s high %s usage (%.1f%%)", hostname, rule.MetricType, currentValue)
	if isResolved {
		subject = fmt.Sprintf("[RESOLVED] %s %s usage back to normal (%.1f%%)", hostname, rule.MetricType, currentValue)
	}

	body := fmt.Sprintf("Server: %s (%s)\nMetric: %s\nThreshold: %s %.1f\nCurrent Value: %.1f\nState: %s\n",
		hostname, ipAddress, rule.MetricType, rule.Operator, rule.Threshold, currentValue, map[bool]string{true: "RESOLVED", false: "FIRING"}[isResolved])

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		s.cfg.SMTPFrom, rule.RecipientEmail, subject, body)

	addr := fmt.Sprintf("%s:%d", s.cfg.SMTPHost, s.cfg.SMTPPort)
	var auth smtp.Auth
	if s.cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPassword, s.cfg.SMTPHost)
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true, ServerName: s.cfg.SMTPHost}
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		log.Printf("[alerting] TLS dial error sending email to %s: %v", rule.RecipientEmail, err)
		return
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, s.cfg.SMTPHost)
	if err != nil {
		log.Printf("[alerting] SMTP client creation error: %v", err)
		return
	}
	defer c.Quit()

	if auth != nil {
		if err = c.Auth(auth); err != nil {
			log.Printf("[alerting] SMTP auth error: %v", err)
			return
		}
	}

	if err = c.Mail(s.cfg.SMTPFrom); err != nil {
		return
	}
	if err = c.Rcpt(rule.RecipientEmail); err != nil {
		return
	}
	w, err := c.Data()
	if err != nil {
		return
	}
	_, _ = w.Write([]byte(msg))
	_ = w.Close()
	log.Printf("[alerting] Alert notification sent to %s for rule #%d", rule.RecipientEmail, rule.ID)
}
