# Ataraxia -- AI-Powered Security Operations Center

A full-stack SOC platform with ML anomaly detection, automated incident response,
threat intelligence correlation, and AI-assisted investigation. Built for lab
environments, presentations, and security research.

---
> ⚠️ **Project Status:** In testing and active development. Features, detections, and interfaces are subject to change.


## Learning Objectives

- Simulate SOC alert triage and investigation workflows
- Apply machine learning techniques to security telemetry
- Correlate multi‑event attack patterns
- Evaluate automated vs. human‑driven incident response
- Gain hands‑on experience with modern SOC architectures


## Architecture
All IP addresses and infrastructure shown are part of a simulated lab environment and do not represent live systems.
``

```
  Windows Host (<VM_HOST_IP>)              Ubuntu VM (<SOC_UBUNTU_IP>)
  ===========================              ==========================
                                           Docker Compose
  Browser ──────────────────────────────►  ┌──────────────────────┐
  http://<SOC_UBUNTU_IP>:3000               │  frontend (Vite/React)│ :3000
                                           │         │             │
  soc_manage.py ────────────────────────►  │  backend (FastAPI)    │ :8000
  send_local_logs.py ───────────────────►  │    ├── anomaly_detection (Isolation Forest ML)
                                           │    ├── correlation_engine (multi-event patterns)
                                           │    ├── detection_rules (custom rules)
                                           │    ├── threat_intel (IOC correlation)
                                           │    ├── playbook_executor (auto-response)
                                           │    └── claude_service (AI analyst)
                                           │         │             │
                                           │  worker (Redis Stream) │
                                           │    └── processes queued logs
                                           │         │             │
                                           │  redis (Streams)      │ :6379
                                           │  db (PostgreSQL 16)   │ :5432
                                           └──────────────────────┘

                                           systemd services:
                                             soc-agent  (tails /var/log/* -> backend)
                                             cron       (archive logs every 10 min)
```

## Detection Pipeline

```
  Log Ingested ──► Redis Stream ──► Worker picks up
       │
       ▼
  1. ML Anomaly Scoring (Isolation Forest, 15-feature vector)
       │     - Hour, weekday, source IP bucket, event type, fan-out,
       │       auth failure count, external IP, lateral movement, etc.
       │     - Risk score 0-100, anomalous if raw score < -0.05
       │
  2. Custom Detection Rules (operator-defined threshold/pattern rules)
       │     - Can boost risk_score to 70+
       │     - Suppression support (by IP, with expiry)
       │
  3. Event Correlation Engine (multi-log patterns)
       │     - Brute Force -> Success (5+ failures + success, 10 min)
       │     - Lateral Movement Chain (3+ distinct destinations, 15 min)
       │     - Priv Esc After Login (auth + escalation, 5 min)
       │     - Port Scan (10+ firewall events, 5 min)
       │     - C2 Beaconing (3+ beacons, 30 min)
       │     - Data Exfil After Compromise (auth + exfil, 60 min)
       │
  4. Threat Intel Correlation (IOC matching)
       │     - IP, domain, hash, URL, email indicators
       │     - Multiple feed sources, confidence scoring
       │
  5. Incident Creation (if anomalous OR rules match OR IOC hit)
       │     - Severity: critical/high/medium/low/info
       │     - AI recommendation (Claude Haiku or fallback template)
       │     - 30-minute deduplication window
       │
  6. Automated Playbook Execution
         - isolate_host, revoke_credentials, block_ip, collect_forensics
         - send_alert (Slack, PagerDuty, email -- simulated)
         - Auto-selects based on severity + event type
```

## Quick Start (Ubuntu VM)

### Prerequisites
- Ubuntu 22.04+ VM with Docker and Docker Compose
- VirtualBox Host-Only adapter (<LAB_SUBNET>.x network)
- Python 3.10+

### 1. Clone and configure

```bash
cd /home/$USER/Lab-Repo
cp .env.example .env
# Edit .env: set ANTHROPIC_API_KEY if you want AI features
```

### 2. Start all services

```bash
docker-compose up -d
# Verify: 5 containers running
docker-compose ps
```

Services:
| Service  | Port | Description |
|----------|------|-------------|
| frontend | 3000 | React dashboard |
| backend  | 8000 | FastAPI API |
| worker   | --   | Redis Stream log processor |
| redis    | 6379 | Message queue |
| db       | 5432 | PostgreSQL 16 |

### 3. Start the Linux log agent

```bash
sudo systemctl start soc-agent
sudo systemctl enable soc-agent
# Check: sudo journalctl -u soc-agent -f
```

### 4. Login

Open http://<SOC_UBUNTU_IP>:3000 in your browser.

| Field    | Value |
|----------|-------|
| Username | soc_operator |
| Password | change-me-locally |

## Connecting from Windows

### Frontend (browser)
Navigate to: `http://<SOC_UBUNTU_IP>:3000`

### API access (scripts)
All scripts default to `http://<SOC_UBUNTU_IP>:8000`.

### Management tool (no SSH required)
```powershell
cd "C:\path\to\Lab-Repo-main"

python scripts/soc_manage.py status          # Full health dashboard
python scripts/soc_manage.py incidents       # List incidents
python scripts/soc_manage.py incidents --open
python scripts/soc_manage.py logs            # Log statistics
python scripts/soc_manage.py alarms          # View alarms
python scripts/soc_manage.py playbooks       # List playbooks
python scripts/soc_manage.py detections      # Detection rules
python scripts/soc_manage.py services        # Docker status (via SSH)
python scripts/soc_manage.py restart         # Restart containers (via SSH)
python scripts/soc_manage.py seed            # Inject attack simulation
python scripts/soc_manage.py resolve-all     # Resolve all open incidents
```

### Windows endpoint log sender
```powershell
# Send demo Windows logs
python scripts/send_local_logs.py --demo --once

# Continuous collection (requires pywin32 or falls back to wevtutil)
python scripts/send_local_logs.py --interval 15

# One-shot collection
python scripts/send_local_logs.py --once
```

## Sending Logs

### From Linux (soc-agent -- already running)
The systemd agent tails `/var/log/auth.log`, `/var/log/syslog`, `/var/log/kern.log`
and sends to the backend every 10 seconds.

### From any machine (curl)
```bash
curl -X POST http://<SOC_UBUNTU_IP>:8000/api/logs/ingest \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: lab-ingest-token" \
  -d '{
    "logs": [{
      "source": "test",
      "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
      "log_level": "error",
      "message": "Failed password for root from 10.0.0.45 port 22 ssh2",
      "ip_src": "10.0.0.45",
      "event_type": "auth_failure",
      "user": "root",
      "raw_data": {"host": "test-host"}
    }]
  }'
```

### From Python
```python
import json, urllib.request
url = "http://<SOC_UBUNTU_IP>:8000/api/logs/ingest"
logs = [{"source":"test","timestamp":"2026-03-28T12:00:00Z",
         "log_level":"error","message":"Test alert","ip_src":"10.0.0.1",
         "event_type":"auth_failure","user":"admin"}]
data = json.dumps({"logs": logs}).encode()
req = urllib.request.Request(url, data=data, method="POST",
    headers={"Content-Type":"application/json","X-Agent-Token":"lab-ingest-token"})
with urllib.request.urlopen(req) as resp:
    print(resp.read().decode())
```

## Simulating Attacks

Run the setup script to inject realistic attack scenarios:

```bash
# On the VM
python3 scripts/setup_soc.py

# From Windows
python scripts/soc_manage.py seed
```

This injects:
- **SSH brute force** (15 failed logins from 10.0.0.45)
- **Successful breach** (attacker gains root access)
- **Privilege escalation** (sudo to root)
- **Lateral movement** (SSH from compromised host to another)
- **C2 beaconing** (outbound connections to known-bad IP)
- **Data exfiltration** (2.3 GB transfer to external IP)
- **Port scanning** (firewall blocks across subnet)
- **Malware detection** (ClamAV trojan find)
- **Sensitive file access** (/etc/shadow read)
- **Account tampering** (backdoor user created with UID 0)

Plus 20 normal baseline logs for ML contrast.

## Key Configuration

### Environment variables (.env on VM)

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | (none) | Enable AI analyst features |
| `ANTHROPIC_MODEL` | claude-3-haiku-20240307 | AI model (haiku = cheapest) |
| `AI_AUTO_ENABLED` | true | Auto-generate AI recommendations on incidents |
| `AUTH_TOKEN_SECRET` | (set in .env) | HMAC secret for auth tokens |
| `INGEST_TOKEN` | lab-ingest-token | Token for log ingestion API |
| `USE_REDIS_STREAMS` | true | Async log processing via Redis |
| `LOG_RETENTION_MINUTES` | 1440 | Auto-cleanup after 24h |
| `RATE_LIMIT_ENABLED` | true | Enable API rate limiting |

### AI Cost Management

The AI analyst uses Claude Haiku by default (~60x cheaper than Opus).

- **AI runs when**: a new incident is auto-created (not on every log)
- **To save credits**: set `AI_AUTO_ENABLED=false` in `.env` -- the system
  uses high-quality fallback templates instead
- **Manual AI**: use the AI Advisor tab to query specific incidents on-demand
- **Cost estimate**: ~$0.001 per incident recommendation with Haiku

## Application Logging

All backend services write structured logs to `backend/logs/`.

### Log files

| File | Content | Level |
|------|---------|-------|
| `backend/logs/app.log` | All application activity | INFO+ |
| `backend/logs/error.log` | Errors only | ERROR+ |

### Format

```
timestamp | level | source | message
2026-03-29T03:41:17 | INFO     | app.main | Ataraxia backend ready.
2026-03-29T03:41:28 | ERROR    | worker | Redis connection error: ...
```

### Viewing logs

```bash
# Live tail (from VM)
tail -f backend/logs/app.log

# Errors only
tail -f backend/logs/error.log

# Docker container output (also uses the same format)
docker-compose logs -f backend
docker-compose logs -f worker
```

### Rotation and purge policy

- **Automatic rotation**: 5 MB max per file, 3 backups (`app.log.1`, `.2`, `.3`)
- **Startup trim**: if `app.log` exceeds 10,000 lines, truncated to newest 5,000
- **Never grows unbounded** -- RotatingFileHandler + startup trim ensures this

### Configuration

| Env Variable | Default | Description |
|-------------|---------|-------------|
| `LOG_DIR` | `logs` | Log directory path |
| `LOG_LEVEL` | `INFO` | Console output level (DEBUG, INFO, WARNING, ERROR) |

### For modules

All backend modules use the centralized config:
```python
from app.logging_config import get_logger
logger = get_logger(__name__)

logger.info("Processing log %s", log_id)
logger.error("Failed to connect: %s", exc)
```

## Troubleshooting

### "Authentication bootstrap failed"
- Check that the backend is running: `curl http://<SOC_UBUNTU_IP>:8000/api/auth/status`
- Check `VITE_API_BASE_URL` in `frontend/.env` matches your VM IP

### Logs not appearing
1. Check agent: `sudo journalctl -u soc-agent -f`
2. Check worker: `docker-compose logs -f worker`
3. Check Redis queue: `curl http://<SOC_UBUNTU_IP>:8000/api/system/health`
4. Manual test: `curl -X POST http://<SOC_UBUNTU_IP>:8000/api/logs/ingest -H "X-Agent-Token: lab-ingest-token" -H "Content-Type: application/json" -d '{"logs":[{"source":"test","message":"test","log_level":"info","event_type":"syslog"}]}'`

### Incidents not being created
- Incidents only create when: anomaly detected (risk > threshold) OR detection rule matches OR IOC correlation hit
- Check if `AI_AUTO_ENABLED=true` or `false` -- both work, just different recommendation quality
- Check worker logs: `docker-compose logs -f worker`

### Frontend not updating
```bash
docker-compose restart frontend
```

### Worker crashing
```bash
docker-compose logs worker | tail -20
# Common fix: restart after config changes
docker-compose restart worker
```

### Cannot reach VM from Windows
- Check VirtualBox Host-Only adapter is enabled
- Ping test: `ping <SOC_UBUNTU_IP>`
- Check VM IP: `ip addr show` on the VM

### Docker containers not starting
```bash
docker-compose down
docker-compose up -d
docker-compose ps   # all 5 should be Up
```

## Project Structure

```
backend/
  app/
    main.py                  # FastAPI entry point, startup hooks
    worker.py                # Redis Stream consumer
    routes/
      incidents.py           # Incident CRUD + playbook trigger
      logs.py                # Log ingestion + query
      config_playbooks.py    # Playbook CRUD
      ...
    services/
      anomaly_detection.py   # Isolation Forest ML (15 features)
      correlation_engine.py  # Multi-event pattern detection
      detection_rules.py     # Custom rule evaluation
      log_pipeline.py        # Main processing pipeline
      threat_intel.py        # IOC management + correlation
      playbook.py            # Automated response actions
      claude_service.py      # AI analyst (Claude API + fallback)
      database.py            # SQLAlchemy models
      security.py            # Auth, rate limiting, token validation
frontend/
  src/
    App.jsx                  # Main app shell + navigation
    components/
      CommandCenter.jsx      # Overview dashboard
      IncidentList.jsx       # Incident management
      LiveFeed.jsx           # Real-time log viewer (clickable)
      AIAdvisor.jsx          # AI analyst interface
      Alarms.jsx             # Alarm management
      ...
    services/
      api.js                 # API client
scripts/
  soc_agent.py               # Linux log agent (systemd)
  soc-agent.service           # systemd unit file
  soc_manage.py              # Windows management tool
  send_local_logs.py         # Windows endpoint log sender
  setup_soc.py               # Attack simulation + SOC setup
  archive_logs.py            # Log archival (cron)
```

## Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Vite 5, Tailwind CSS |
| Backend | FastAPI, SQLAlchemy, Pydantic |
| Database | PostgreSQL 16 |
| Queue | Redis 7 Streams |
| ML | scikit-learn Isolation Forest |
| AI | Anthropic Claude API (optional) |
| Auth | HMAC-SHA256 tokens, TOTP MFA |
| Deploy | Docker Compose, systemd |

## Authentication

| Role | Permissions |
|------|------------|
| super_admin | Full access (*) |
| admin | User management, config, audit, playbooks |
| analyst | View all, manage incidents, ingest logs, run playbooks |
| viewer | Read-only access |

Default user: `soc_operator` / `change-me-locally` (analyst role)

## License
Lab/educational use. Not for production deployment.
## Security & Disclaimer

This project is developed for academic and educational purposes

All IP addresses, logs, infrastructure, indicators, and scenarios shown in this repository are part of a **simulated lab environment**. No production systems, real organizations, or live networks are represented.

The application is currently in testing and active development and should not be deployed in production environments.
``
