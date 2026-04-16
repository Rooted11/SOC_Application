# Enterprise SOC Stack

This folder contains the two pillars of the enterprise SOC ingestion pipeline:

1. `windows-agent/SocAgent`: a .NET 8 Windows Service that collects filtered security events and forwards them as JSON to the SOC backend.
2. `soc-backend`: an Ubuntu-friendly FastAPI application that ingests logs, stores them in SQLite, and triggers a failed-login detection rule.

## Architecture

```
Windows endpoints -> SocAgent Windows service -> HTTP POST JSON -> FastAPI SOC backend -> SQLite + alert table
```

## 1. Windows Agent (SocAgent)

### Build & Configuration

- Restore/build with `.NET 8 SDK` installed: `dotnet publish SocAgent/SocAgent.csproj -c Release -o C:\Deploy\SocAgent`
- Copy the published binaries into a host directory and keep `agentsettings.json` there.
- Modify `agentsettings.json` to point at your backend IP (`ApiEndpoint`) and optionally set the enabled event IDs, retry/backoff, log path, and agent token.

### PowerShell helper

Use the bundled `install-service.ps1` (runs relative to the published `SocAgent.exe`) or the commands below that achieve the same effect:

```powershell
New-Service -Name SocAgent -BinaryPathName "C:\Deploy\SocAgent\SocAgent.exe" -DisplayName "SOC Log Collector" -StartupType Automatic
Start-Service SocAgent
# To stop or restart:
Stop-Service SocAgent
Start-Service SocAgent
# To remove:
Stop-Service SocAgent
Remove-Service SocAgent
```

Logs are written to `%ProgramData%\SocAgent\logs\agent.log` (configurable in `agentsettings.json`).

## 2. Ubuntu SOC Backend

### Environment & dependencies

```bash
cd soc-system/soc-backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run server (binding 0.0.0.0:8000)

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The app initializes `data/soc.db` automatically and writes structured logs to `logs/app.log`. `config.py`/`.env` control the database file, logging directory, thresholds, and host/port values.

### Docker (optional)

```bash
docker build -t soc-backend ./soc-system/soc-backend
docker run -p 8000:8000 --rm soc-backend
```

### APIs

- `POST /logs/` – ingest a single log payload.
- `GET /logs/?limit=100` – retrieve the latest `limit` entries.
- `GET /alerts/` – list triggered alerts (failed-login brute-force detection).
- `GET /health` – check service health.

## 3. Testing & Validation

1. Start the FastAPI backend (`uvicorn app.main:app --host 0.0.0.0 --port 8000`).
2. Confirm `GET /logs` returns `[]` when no logs yet.
3. Build and launch the Windows agent; confirm `agent.log` entries appear.
4. Trigger security events on the Windows host (failed login, privilege usage) and verify they reach the backend.
5. Re-query `/logs` and `/alerts` to confirm ingestion and detection.
6. To test detection, generate >5 4625 events from the same host within two minutes and ensure `/alerts` contains a `failed-login-bruteforce` alert.

## Example Payload

```json
{
  "event_id": 4625,
  "message": "An account failed to log on.",
  "hostname": "WIN-EVAL-01",
  "source_ip": "<CLIENT_IP>",
  "timestamp": "2026-03-30T15:02:10Z",
  "log_name": "Security",
  "level": "Warning",
  "user": "DOMAIN\\alice",
  "details": {
    "Property0": "Failure Reason",
    "Property1": "0xC000006E"
  }
}
``` 

Agent payloads will include extra metadata (`LocalIp`, `MachineIp`, `details`, etc.) to keep the backend schema flexible for future enrichment.
