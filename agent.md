# Agent Memory: Cluster Monitor Project

This file serves as the persistent memory and context register for AI coding assistants working on the **Cluster Monitor** project. Read this file at the start of any new session or task to understand the architecture, completed progress, database decisions, and next steps.

---

## 1. Project Context & Overview

**Cluster Monitor** is a lightweight, system-monitor dashboard composed of two core parts:
1. **Cluster Host**: Runs inside Docker Compose. Aggregates system metrics and logs, exposes a web dashboard, stores system state/settings in a **PostgreSQL** database, and coordinates email alerts.
2. **Cluster Agent**: Installed on monitored machines. Runs **Grafana Alloy** (telemetry shipping) and a custom **Go Agent** (executes lifecycle service controls securely). Supports Linux, Windows, and macOS (Darwin).

---

## 2. Key Architectural Decisions

* **Database Choice**: PostgreSQL is used on the Cluster Host to manage agent catalogs, tracked/ignored services, and user-configured alert thresholds.
* **Telemetry Routing (Push-based)**:
  * To avoid firewall/port forwarding issues on agents (e.g., behind NAT), **Grafana Alloy** *pushes* metrics to Prometheus via remote write, and *pushes* logs to Loki's API.
  * Host Prometheus runs with `--web.enable-remote-write-receiver` enabled.
  * Target agents only expose port `9191` (Go Agent control port), which is locked down by certificate security and bearer tokens.
* **Networking Option (Same Local Network / LAN)**:
  * Since Host and Agents reside on the same local network (LAN) or single virtual network, Tailscale is omitted.
  * Communications are established using local network IP addresses directly (e.g., `http://<host-local-ip>:9090` for metrics push and `https://<agent-local-ip>:9191` for service management controls).
  * Port maps are exposed directly on the Docker containers: `8080` (Backend Dashboard UI), `9090` (Prometheus metric ingress), and `3100` (Loki log ingress).
* **Go Agent Execution**:
  * Cross-platform execution is handled via Go's `runtime.GOOS`.
  * Avoids shell wrappers entirely to eliminate Remote Code Execution (RCE) risk. Calls system APIs directly:
    * **Linux**: `exec.Command("sudo", "systemctl", action, service)`
    * **Windows**: `exec.Command("powershell.exe", "-Command", "Action-Service -Name Service")`
    * **macOS**: `exec.Command("launchctl", subcommand, service)`
* **Alerting**:
  * Dynamic user alerts configured in the dashboard (e.g. CPU > 90% for 5 mins) are evaluated periodically by the Host Backend querying Prometheus.
  * Email alerts are sent directly from the Host Backend using SMTP (Alertmanager handles infrastructure alerts).

---

## 3. Directory & File Structure

```
Cluster Monitor/
├── agent.md                  # This persistent AI memory and project status file
├── implementation_plan.md    # Master architecture and execution plan (updated for Postgres)
├── cluster-host/             # Host infrastructure and dashboard code
│   ├── docker-compose.yml    # Docker services config
│   ├── .env                  # Environment configs for DB
│   ├── prometheus/
│   │   └── prometheus.yml    # Prometheus config
│   ├── loki/
│   │   └── loki-config.yml   # Loki storage config
│   └── alertmanager/
│       └── alertmanager.yml  # Alertmanager routing
└── cluster-agent/            # Agent binaries and configurations
    ├── README.md             # Detailed agent deployment guide (Linux, Windows, macOS)
    ├── main.go               # Reference Go agent code skeleton
    └── config.json           # Go agent config template
```

---

## 4. Current Progress & Status

* **Status**: Complete and ready for deployment.
* **Completed Milestones**:
  * [x] Drafted system architecture and conducted security audit.
  * [x] Created cross-platform Go Agent control module code (`main.go`).
  * [x] Built the `/api/v1/processes` endpoint inside the Go Agent to fetch real-time active system processes list.
  * [x] Configured Grafana Alloy collector templates for Linux, Windows, and macOS.
  * [x] Implemented Host Backend in Go (database migration, registration endpoints, service toggles/controls proxy, alerting evaluator engine).
  * [x] Formulated UI Dashboard featuring a collapsible server sidebar, summary counters, and a rich modal dashboard parity with Linux's System Monitor (Swap, CPU core grid, Network interface details, File system partitions, Service controls, and Process manager search table).
  * [x] Configured LAN port bindings and bridge networking across the docker-compose stack.

---

## 5. Deployment Instructions

To verify and run the stack:
1. **Deploy Host**:
   * Run: `docker compose up -d --build` in `cluster-host/`.
2. **Deploy Agents**:
   * Inside `cluster-agent/`, configure `config.json` (generate a unique token).
   * Run `go mod tidy` and build/execute the compiled binary on your target nodes.
   * Deploy Grafana Alloy using the matching OS HCL configuration template pointing to the host machine's Local LAN IP address.
