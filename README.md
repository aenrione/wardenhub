# WardHub

[![Build](https://github.com/aenrione/wardenhub/actions/workflows/ci.yml/badge.svg)](https://github.com/aenrione/wardenhub/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)

Periodic security auditing for homelabs. Runs checks across VMs, LXC containers, Docker hosts, and bare-metal Linux boxes — pushes findings as Prometheus metrics, surfaces them in Grafana, and alerts on regressions.

WardHub is not a real-time intrusion detection system. It is a scheduled auditing tool: run checks every few hours, track your hardening score over time, get alerted when something critical appears or regresses.

**Target audience:** Self-hosters running Proxmox, Docker, LXC, or plain Linux.

<img width="1302" height="742" alt="image" src="https://github.com/user-attachments/assets/7834e575-8b17-4bcd-aaa6-8c02accf3622" />


---

## Contents

- [Architecture](#architecture)
- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
  - [Hub (Docker Compose)](#hub-docker-compose)
  - [Agent (per host)](#agent-per-host)
- [Configuration Reference](#configuration-reference)
  - [Agent config](#agent-config)
  - [Coordinator config](#coordinator-config)
- [BYOB Mode](#byob-mode-bring-your-own-prometheus)
- [Proxmox API Setup](#proxmox-api-setup)
- [Metrics Reference](#metrics-reference)
- [Custom Checks](#custom-checks)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Architecture

```
                         ┌─────────────────────────────────────┐
                         │         WardHub (Compose Stack)      │
                         │                                      │
                         │  ┌─────────────┐  ┌──────────────┐  │
                         │  │ Coordinator  │  │ Pushgateway  │  │
                         │  │ - agent reg  │  │              │  │
                         │  │ - cluster    │  │              │  │
                         │  │   checks     │  │              │  │
                         │  │ - cleanup    │  │              │  │
                         │  └──────┬───────┘  └──────▲───────┘  │
                         │         │                  │          │
                         │  ┌──────▼──────────────────┤──────┐  │
                         │  │ Prometheus              │      │  │
                         │  └──────┬──────────────────┘──────┘  │
                         │    ┌────▼─────┐  ┌────▼──────────┐   │
                         │    │ Grafana  │  │ Alertmanager  │   │
                         │    └──────────┘  └───────────────┘   │
                         └──────────────────▲───────────────────┘
                                            │
                    ┌───────────────────────┼───────────────────┐
                    │                       │                   │
             ┌──────┴───────┐  ┌────────────┴──┐  ┌────────────┴──┐
             │  Warden      │  │  Warden        │  │  Warden       │
             │  (Proxmox    │  │  (Docker host) │  │  (Linux box)  │
             │   node)      │  │                │  │               │
             │  - lynis     │  │  - lynis       │  │  - lynis      │
             │  - proxmox   │  │  - docker      │  │  - network    │
             │  - network   │  │  - network     │  │               │
             └──────────────┘  └───────────────┘  └───────────────┘
```

**Three layers:**

1. **Warden agents** — lightweight Python process on each audited host. Auto-detects available providers (Lynis, Docker, Proxmox, Network). Runs on a schedule (default: 3 hours). Pushes findings to Pushgateway and registers with the Coordinator.

2. **Coordinator** — FastAPI service in the hub Compose stack. Manages the agent registry, runs cluster-level checks, handles stale metric cleanup on Pushgateway.

3. **Observability stack** — Pushgateway + Prometheus + Grafana + Alertmanager. Either bundled (batteries-included) or external (BYOB: point agents at your own Pushgateway).

**Communication is push-based.** Agents run autonomously on their own schedule. The coordinator never SSH-es into agents or pulls data from them.

---

## Features

- **Auto-detecting providers** — agents detect what is available on each host at startup; no manual configuration required in most cases
- **Lynis integration** — parses `/var/log/lynis-report.dat` after each audit run; exports hardening index, warnings, and suggestions as metrics
- **Docker checks** — privileged containers, host network mode, sensitive host mounts, missing resource limits, latest-tag images, root user, extra capabilities
- **Proxmox checks** — privileged LXC containers, per-VM firewall, resource limits, 2FA coverage, API token privilege separation (local via `pvesh` or remote via API token)
- **Network checks** — unexpected open ports, firewall status, SSH root login, SSH password auth, exposed management interfaces
- **Hardening score trend** — track improvement over time per host with Grafana line charts
- **Alerting** — critical findings fire immediately; warning findings batch into daily digests via Alertmanager grouping
- **Stale metric cleanup** — coordinator automatically removes Pushgateway metrics for agents that have stopped reporting
- **Extensible** — drop a `.py` file into `custom_checks/` to add checks without touching core code
- **BYOB mode** — run only coordinator + pushgateway alongside your existing Prometheus/Grafana stack

---

## Quick Start

**Minimum requirements:** Docker, Docker Compose v2, Python 3.11+ on each host to audit.

```bash
# 1. Clone the repo
git clone https://github.com/aenrione/wardenhub.git
cd wardenhub

# 2. Copy and edit coordinator config
cp config/coordinator.yaml.example config/coordinator.yaml
# Edit config/coordinator.yaml — set your pushgateway URL (default is fine for bundled mode)

# 3. Start the hub (batteries-included: coordinator + pushgateway + prometheus + grafana + alertmanager)
docker compose --profile full up -d

# 4. On each host you want to audit, install the agent
curl -fsSL https://raw.githubusercontent.com/aenrione/wardenhub/main/install-agent.sh | bash
# The script prompts for hub URL and sets up a systemd timer

# 5. Run a manual audit to verify
wardenhub-agent run --config /etc/wardenhub/agent.yaml

# 6. Open Grafana at http://<hub-ip>:3000 (admin / changeme)
```

---

## Installation

### Hub (Docker Compose)

The hub runs on any machine on your LAN — a dedicated VM, your Proxmox node, or a Pi. It needs to be reachable from all agents on ports `8080` (coordinator) and `9091` (pushgateway).

**Batteries-included mode** (coordinator + pushgateway + prometheus + grafana + alertmanager):

```bash
docker compose --profile full up -d
```

**Minimal mode** (coordinator + pushgateway only — use with your own Prometheus/Grafana):

```bash
docker compose up -d
```

Ports exposed:

| Service | Port | Profile |
|---------|------|---------|
| Coordinator API | 8080 | always |
| Pushgateway | 9091 | always |
| Prometheus | 9090 | `full` |
| Grafana | 3000 | `full` |
| Alertmanager | 9093 | `full` |

Data is persisted in named Docker volumes (`wardenhub-data`, `prometheus-data`, `grafana-data`, `alertmanager-data`).

### Agent (per host)

**Option 1 — install script (recommended):**

```bash
curl -fsSL https://raw.githubusercontent.com/aenrione/wardenhub/main/install-agent.sh | bash
```

The script installs Python + pip if missing, installs `wardenhub-agent`, runs auto-detection, generates `/etc/wardenhub/agent.yaml`, prompts for hub URL, and installs a systemd timer.

**Option 2 — manual with uv:**

```bash
uv tool install wardenhub-agent

# Generate config (auto-detects providers, prompts for hub URL)
wardenhub-agent init

# One-shot audit
wardenhub-agent run

# Daemon mode (built-in scheduler, interval from config)
wardenhub-agent start

# Check coordinator status
wardenhub-agent status
```

**Option 3 — manual with pip:**

```bash
pip install wardenhub-agent
wardenhub-agent init
wardenhub-agent run
```

**Systemd timer (manual):**

```bash
# Copy units from agent/systemd/
cp agent/systemd/wardenhub-agent.service /etc/systemd/system/
cp agent/systemd/wardenhub-agent.timer   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now wardenhub-agent.timer
```

---

## Configuration Reference

### Agent config

Default path: `/etc/wardenhub/agent.yaml`

```yaml
hub:
  pushgateway_url: "http://192.168.1.34:9091"
  # coordinator_url: "http://192.168.1.34:8080"  # optional, registration disabled if omitted

schedule:
  interval: "3h"

providers:
  # Leave empty for auto-detection (recommended)
  # enabled: [lynis, network]    # explicit list — skips auto-detect
  # disabled: [proxmox]          # exclude specific providers — auto-detect for the rest

network:
  expected_ports: [22]  # ports that should be open; others flagged as warnings

# Proxmox provider config (only needed on PVE nodes)
# proxmox:
#   host: "https://192.168.1.2:8006"
#   verify_ssl: false
#   token_id: "security-audit@pve!audit-token"
#   token_secret_file: "/opt/wardenhub/.token"
```

**Provider auto-detection rules:**

| Provider | Detection condition |
|----------|---------------------|
| Lynis | `which lynis` succeeds |
| Docker | `/var/run/docker.sock` exists or `docker info` succeeds |
| Proxmox | `which pvesh` succeeds (present on PVE nodes) |
| Network | Always enabled |

If `enabled` is set, only those providers run (no auto-detect). If `disabled` is set, auto-detect runs but the listed providers are skipped. Setting both is a config error — the agent exits with a clear message.

**CLI flags:**

```
wardenhub-agent run   [--config PATH] [--log-level LEVEL]   # single audit, exit
wardenhub-agent start [--config PATH] [--log-level DEBUG]   # daemon with scheduler
wardenhub-agent init  [--config PATH]                       # generate config file
wardenhub-agent status                                       # query coordinator
```

### Coordinator config

Default path: `/etc/wardenhub/coordinator.yaml` (mounted into the container at `./config/coordinator.yaml`).

```yaml
coordinator:
  host: "0.0.0.0"
  port: 8080
  db_path: "/data/wardenhub.db"

pushgateway:
  url: "http://pushgateway:9091"
  cleanup_threshold: "6h"   # remove metrics for agents silent longer than this

schedule:
  interval: "3h"

# Proxmox remote checks (Phase 3 — leave commented until configured)
# proxmox:
#   host: "https://192.168.1.2:8006"
#   verify_ssl: false
#   token_id: "security-audit@pve!audit-token"
#   token_secret_file: "/etc/wardenhub/.proxmox-token"
```

**Coordinator API endpoints:**

```
GET  /health            coordinator health check
GET  /api/status        list registered agents + last-seen timestamps
POST /api/register      called by agents on each run
GET  /api/findings      latest findings summary across all agents
```

---

## BYOB Mode (Bring Your Own Prometheus)

If you already have a Prometheus + Grafana stack, you do not need the bundled observability services. Run only the coordinator and pushgateway, then add a scrape job to your existing Prometheus config.

**1. Start only coordinator + pushgateway:**

```bash
docker compose up -d
# No --profile flag — prometheus, grafana, alertmanager are not started
```

**2. Add a scrape job to your existing `prometheus.yml`:**

```yaml
scrape_configs:
  - job_name: wardenhub
    honor_labels: true
    static_configs:
      - targets: ["<hub-ip>:9091"]
```

The `honor_labels: true` directive is required. Agents push with `job=wardenhub_agent` and `instance=<hostname>` labels. Without `honor_labels`, Prometheus would overwrite these with its own job/instance labels.

**3. Import dashboards into your Grafana:**

The dashboard JSON files are in `config/grafana/dashboards/`. Import them via Grafana UI (Dashboards > Import) or drop them into your provisioning directory.

**4. Add alert rules to your Prometheus:**

```yaml
# In prometheus.yml
rule_files:
  - /path/to/wardenhub/config/alert_rules.yml
```

That is the full integration. Agents and coordinator push metrics to Pushgateway; your existing Prometheus scrapes it.

---

## Proxmox API Setup

For the Proxmox provider (both local on-node mode and remote coordinator mode), create a dedicated read-only API token:

```bash
# On the Proxmox node
pveum user add security-audit@pve
pveum aclmod / -user security-audit@pve -role PVEAuditor
pveum user token add security-audit@pve audit-token --privsep 1
```

Store the token secret in a file with `600` permissions, then reference it by path in the config:

```bash
echo "<token-secret>" > /opt/wardenhub/.token
chmod 600 /opt/wardenhub/.token
```

```yaml
proxmox:
  host: "https://192.168.1.2:8006"
  verify_ssl: false
  token_id: "security-audit@pve!audit-token"
  token_secret_file: "/opt/wardenhub/.token"
```

Never put the token secret in environment variables or inline in the config file.

---

## Metrics Reference

All metrics use the `wardenhub_` prefix. Agents push with `job=wardenhub_agent`, `instance=<hostname>`. The coordinator pushes with `job=wardenhub_coordinator`, `instance=cluster`.

**Common (all providers):**

| Metric | Type | Key labels |
|--------|------|------------|
| `wardenhub_check_result` | Gauge | `instance, provider, check_id, target, severity` — 1=pass, 0=fail |
| `wardenhub_findings_total` | Gauge | `instance, provider, severity` — count by severity |
| `wardenhub_last_run_timestamp` | Gauge | `instance, provider` — Unix timestamp of last run |
| `wardenhub_provider_error` | Gauge | `instance, provider` — 1 if provider errored |
| `wardenhub_finding_info` | Gauge (always 1) | `instance, provider, check_id, target, severity, message, remediation` — human-readable detail for Grafana tables |

**Lynis-specific:**

| Metric | Type |
|--------|------|
| `wardenhub_lynis_hardening_index` | Gauge |
| `wardenhub_lynis_tests_performed` | Gauge |

**Built-in alert rules** (`config/alert_rules.yml`):

| Alert | Condition | Severity |
|-------|-----------|----------|
| `WardenCriticalFinding` | `wardenhub_check_result{severity="critical"} == 0` | critical |
| `WardenHardeningScoreDrop` | `delta(wardenhub_lynis_hardening_index[6h]) < -10` | critical |
| `WardenAgentStale` | `time() - wardenhub_last_run_timestamp > 14400` | critical |
| `WardenLowScore` | `wardenhub_lynis_hardening_index < 50` for 24h | warning |
| `WardenNewWarnings` | `increase(wardenhub_findings_total{severity="warning"}[6h]) > 0` | warning |
| `WardenProviderError` | `wardenhub_provider_error == 1` for 1h | warning |

Critical alerts fire immediately. Warning alerts are designed to be grouped by Alertmanager into daily digests.

---

## Custom Checks

Both the agent and coordinator support a `custom_checks/` directory. Any `.py` file dropped there is auto-discovered on the next run — no code changes needed.

Configure the path:

```yaml
custom_checks_dir: "/etc/wardenhub/custom_checks"
```

**Adding a check within an existing provider:**

```python
from wardenhub_agent.models import Finding, Severity
from wardenhub_agent.providers.base import BaseCheck

class DockerComposeCheck(BaseCheck):
    id = "docker_compose_managed"
    provider = "docker"
    severity = Severity.INFO
    description = "Flags containers not managed by Compose"

    def evaluate(self, context: dict) -> list[Finding]:
        findings = []
        for container in context["containers"]:
            if "com.docker.compose.project" not in container.get("labels", {}):
                findings.append(Finding(
                    provider=self.provider,
                    check_id=self.id,
                    target=f"container/{container['name']}",
                    severity=self.severity,
                    passed=False,
                    message=f"Container {container['name']} not managed by Compose",
                    remediation="Consider managing with Docker Compose for reproducibility",
                ))
        return findings
```

**Adding a new provider** (for technologies not covered out of the box):

```python
from wardenhub_agent.providers.base import BaseProvider
from wardenhub_agent.models import Finding, Severity

class TrueNASProvider(BaseProvider):
    id = "truenas"
    name = "TrueNAS"

    @classmethod
    def detect(cls) -> bool:
        return config_has_key("truenas.api_url")

    def audit(self) -> list[Finding]:
        # Query TrueNAS API, return findings
        ...
```

---

## Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | Agent (Lynis + Network), Coordinator (registry + cleanup), Compose stack, overview dashboard + alert rules | In progress |
| 2 | Docker provider, host-detail Grafana dashboard | Planned |
| 3 | Proxmox provider (local `pvesh` + remote API), cluster dashboard | Planned |
| 4 | Custom checks support, `install-agent.sh`, PyPI packaging | Planned |
| 5+ | Community checks repo, additional providers (TrueNAS, OPNsense, Kubernetes), Coordinator web UI | Future |

---

## Contributing

Contributions are welcome. The project is early-stage — the most useful contributions right now are provider implementations, check additions, and bug reports.

**Getting started:**

```bash
git clone https://github.com/aenrione/wardenhub.git
cd wardenhub

# Agent development
cd agent
uv sync
uv run wardenhub-agent --help

# Coordinator development
cd coordinator
uv sync
uv run uvicorn wardenhub_coordinator.app:app --reload

# Run tests
uv run pytest tests/
```

**Guidelines:**

- New checks go in the appropriate provider file or as a standalone file in `providers/`
- Every check needs a `check_id`, clear `message`, and actionable `remediation` string
- Provider `detect()` must not raise exceptions — return `False` on any error
- Provider `audit()` must not raise exceptions — return an empty list and log the error
- Match the existing metric naming convention (`wardenhub_` prefix, snake_case)
- Open an issue before starting significant work to avoid duplication

**Project layout:**

```
wardenhub/
├── agent/                  # Warden agent (uv package)
│   └── wardenhub_agent/
│       ├── cli.py          # CLI entrypoint (typer)
│       ├── config.py
│       ├── models.py       # Finding, CheckResult, Severity
│       ├── runner.py
│       ├── pusher.py
│       └── providers/
├── coordinator/            # Coordinator service (FastAPI, uv package)
│   └── wardenhub_coordinator/
├── config/                 # Config examples, Prometheus rules, Grafana dashboards
├── tests/
├── docker-compose.yml
└── install-agent.sh
```

---

## License

MIT. See [LICENSE](LICENSE).
