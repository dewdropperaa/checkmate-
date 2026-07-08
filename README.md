# Sentinel Scan

Multi-agent web vulnerability scanner with a **Chrome Manifest V3 extension** frontend and a **Python FastAPI** backend. This repository is the production scaffold — scanning agents and external tool integrations are added in later phases.

## Architecture

```
sentinel-scan/
├── backend/          # FastAPI API, agents, tool wrappers, scope enforcement
└── extension/        # Chrome MV3 extension (Vite + TypeScript)
```

## Prerequisites

- Python 3.12+
- Node.js 20+ (for the extension build)
- Docker & Docker Compose (optional)

## Backend setup

```bash
cd backend
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and set `AUTHORIZED_TARGETS` to a comma-separated list of domains or URLs you are **explicitly authorized** to scan, for example:

```env
AUTHORIZED_TARGETS=authorized.example.com,https://staging.example.com
```

Start the API:

```bash
uvicorn app.main:app --reload
```

The server listens on `http://127.0.0.1:8000`. Interactive docs: `http://127.0.0.1:8000/docs`.

### API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scan` | Queue a scan for an authorized target |
| `GET` | `/scan/{id}/status?target=...` | Poll scan status |
| `GET` | `/scan/{id}/report?target=...` | Retrieve scan report |
| `GET` | `/scan/{id}/report/{format}?target=...` | Download report artifact in `json`, `md`, or `html` |

Every endpoint validates the target against the allowlist **before** any other logic. Out-of-scope targets receive **403 Forbidden**.
The `/scan` endpoint is also rate-limited and concurrency-limited per client identity (IP or API key) to prevent unbounded scan launches.

### Run tests

```bash
cd backend
pytest
```

### Docker

```bash
cd backend
cp .env.example .env
# Edit .env with authorized targets
docker compose up --build
```

External tool binaries can be placed in `backend/tools-bin/` and are mounted at `/opt/tools` inside the container.

## Extension setup

```bash
cd extension
npm install
npm run build
```

Load the unpacked extension in Chrome:

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select `extension/dist`

Ensure the backend is running at `http://localhost:8000` and that the active tab target appears in `AUTHORIZED_TARGETS`.

## Project layout

```
backend/
  app/main.py           # FastAPI application
  agents/               # Multi-agent pipeline (stubs)
  tools/                # External CLI wrappers (stubs)
  core/
    config.py           # Pydantic settings (reads .env)
    scope.py            # Allowlist enforcement
    logging.py          # Structured JSON logging
  tests/                # Pytest suite
extension/
  manifest.json         # Manifest V3
  popup.html / popup.ts
  background.ts
  content-script.ts
  dist/                 # Build output (after npm run build)
```

## Security

Read [SECURITY.md](SECURITY.md) before using this tool. **Only scan targets you own or have written authorization to test.**

## Legal & Scope

This tool must only be used against systems you are explicitly authorized to test (for example, your own assets or targets with written permission).

**Allowlist enforcement is currently disabled** so the extension can auto-target the open tab. The `AUTHORIZED_TARGETS` setting remains in config for later re-enable; `core/scope.py` and tool `validate_scope` calls are no-ops until then. You are responsible for ensuring legal authorization before scanning.

## License

Use responsibly and in compliance with applicable laws and engagement scope.
