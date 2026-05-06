# Local Testing Guide

Three ways to run Q-BOM AI, from quickest to most complete.

---

## Option A — Zero-config quickstart (no API keys, no Postgres)

Uses mocked LLM + SQLite. Runs in under a minute.

```bash
# 1. Install only the lightweight deps
cd qbom-ai
pip install -r backend/requirements-quickstart.txt

# 2. Start
python quickstart.py
```

Then open:
- **Swagger UI**: http://localhost:8000/docs  — click Authorize, enter `qbom-demo-key-2025`
- **Dashboard**:  open `frontend/dashboard.html` directly in your browser (no server needed)

---

## Option B — Docker Compose (needs Docker Desktop)

```bash
cd qbom-ai
cp backend/.env.example backend/.env   # defaults work without real keys

docker-compose up postgres backend -d

# Wait ~15s, then:
docker-compose exec backend python ../scripts/manage.py init-db
docker-compose exec backend python ../scripts/manage.py seed-db

# Frontend (hot-reload dev server)
docker-compose --profile dev up frontend-dev -d
# → http://localhost:5173

# Full observability stack (OTel + Jaeger + Prometheus) — optional
docker-compose --profile observability up -d
# Jaeger:     http://localhost:16686
# Prometheus: http://localhost:9090
```

---

## Option C — Full install with real Azure OpenAI

### Install

```bash
cd qbom-ai/backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

If you hit dependency conflicts, run this instead (uses looser pins):
```bash
pip install fastapi "uvicorn[standard]" pydantic pydantic-settings httpx \
  "langchain==0.3.7" "langchain-community==0.3.7" "langchain-openai==0.2.9" \
  "langchain-core==0.3.15" "langgraph==0.2.50" langsmith \
  "sqlalchemy[asyncio]" asyncpg alembic aiosqlite \
  rank-bm25 pinecone-client sentence-transformers \
  gitpython beautifulsoup4 numpy lxml \
  openai azure-identity mcp
```

### Configure

```bash
cp .env.example .env
```

Minimum required keys for real LLM:
```env
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/qbom
AZURE_OPENAI_ENDPOINT=https://YOUR-RESOURCE.openai.azure.com/
AZURE_OPENAI_API_KEY=your-real-key
AZURE_OPENAI_DEPLOYMENT=gpt-4o
AZURE_OPENAI_API_VERSION=2024-08-01-preview
```

### Run

```bash
# Postgres (if not using Docker)
docker run -d -e POSTGRES_DB=qbom -e POSTGRES_USER=qbom \
  -e POSTGRES_PASSWORD=qbom_dev_password -p 5432:5432 postgres:16-alpine

alembic upgrade head
python ../scripts/manage.py seed-db
uvicorn main:app --reload --port 8000
```

### Test a scan

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "X-API-Key: qbom-demo-key-2025" \
  -H "Content-Type: application/json" \
  -d '{"target":"https://github.com/psf/requests","target_type":"repo"}'
# → {"scan_id":"abc-123","status":"queued"}

# Poll
curl http://localhost:8000/api/scan/abc-123 -H "X-API-Key: qbom-demo-key-2025"

# Download BOM
curl http://localhost:8000/api/scan/abc-123/bom -H "X-API-Key: qbom-demo-key-2025"
```

### Run tests

```bash
# Unit tests (all mocked — no real APIs)
cd qbom-ai
pytest tests/unit/ -v

# Integration tests (needs Postgres)
pytest tests/integration/ -v --asyncio-mode=auto

# Frontend
cd frontend && npm install && npm test -- --run
```

---

## Troubleshooting

**Dependency conflict on `langchain-core`**
The versions in `requirements.txt` are pinned to a compatible set:
`langchain-core==0.3.15` + `langgraph==0.2.50` (LangGraph 0.2.28+ lifted the `<0.3` constraint).
If pip still conflicts, use the manual install command in Option C above.

**`ModuleNotFoundError` when running `quickstart.py`**
```bash
pip install -r backend/requirements-quickstart.txt
```

**Port 8000 already in use**
```bash
# Kill whatever is on 8000
lsof -ti:8000 | xargs kill -9    # macOS/Linux
netstat -ano | findstr :8000     # Windows — then taskkill /PID <pid> /F
```

**SQLite "table not found" on first run**
Tables are auto-created on startup via `init_db()`. If you see this error, the startup didn't complete — check the terminal output for earlier errors.

**Dashboard shows "Network Error"**
Backend must be running on port 8000. Check: `curl http://localhost:8000/api/health`

---

## API Keys (built-in)

| Key | Tier | Rate limit |
|-----|------|-----------|
| `qbom-demo-key-2025` | free | 20 req/min |
| `qbom-pro-key-2025`  | pro  | 200 req/min |

Pass as header: `X-API-Key: qbom-demo-key-2025`
