# Q-BOM AI — Quantum Cryptographic Bill of Materials Generator

Autonomous multi-agent system that scans GitHub repos and live websites for 
quantum-vulnerable cryptographic primitives and generates CycloneDX v1.7 CBOMs.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    LangGraph Agent Graph                     │
│                                                             │
│  Supervisor ──► Scanner ──► Enricher ──► Reflector ──► Reporter
│      │              │           │            │              │
│   (CoT routing) (tool-call) (tool-call) (self-reflect) (BOM gen)
│                                                             │
│  Tools available to agents (via LangChain tool-calling):   │
│  • scan_target          — repo clone + CodeQL + regex      │
│  • retrieve_crypto_knowledge — Hybrid BM25 + Dense (RRF)  │
│  • calculate_hndl_score — HNDL risk scoring               │
│  • get_migration_guidance — NIST PQC migration paths      │
│  • MCP database tools   — Postgres via Model Context Protocol│
└─────────────────────────────────────────────────────────────┘
           │                              │
    LangSmith tracing              Pinecone (dense)
    (full agent trace)             + Postgres (BM25)
           │                              │
┌──────────▼──────────────────────────────▼──────────────────┐
│              FastAPI (async) + SQLAlchemy                   │
│  POST /api/scan  GET /api/scan/{id}  GET /api/scan/{id}/bom │
└────────────────────────────────────────────────────────────┘
           │
┌──────────▼──────────────────────────────────────────────────┐
│           Azure Kubernetes Service (AKS)                    │
│  • 2-10 replicas (HPA on CPU/memory)                       │
│  • Azure OpenAI Service (GPT-4o deployment)                │
│  • Azure Application Gateway ingress                       │
└────────────────────────────────────────────────────────────┘
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Multi-Agent | LangGraph + LangChain |
| Agentic Logic | Self-reflection loops, tool-calling, CoT |
| LLM | Azure OpenAI GPT-4o |
| Retrieval | BM25 (rank-bm25) + Dense (Pinecone) fused with RRF |
| Tool Integration | MCP (Model Context Protocol) server |
| Observability | LangSmith tracing |
| Evaluation | DeepEval (Answer Relevancy, Faithfulness) + RAGAS |
| Backend | FastAPI (async) + SQLAlchemy |
| Storage | PostgreSQL (Supabase) + Pinecone |
| Cloud | Azure Kubernetes Service + Azure OpenAI |
| BOM Format | CycloneDX v1.7 |

## Quickstart

```bash
cd backend
cp .env.example .env   # fill in your keys
pip install -r requirements.txt
uvicorn main:app --reload
```

```bash
# Trigger a scan
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://github.com/org/repo", "target_type": "repo"}'

# Poll status
curl http://localhost:8000/api/scan/<scan_id>

# Get CycloneDX BOM
curl http://localhost:8000/api/scan/<scan_id>/bom
```

## Agent flow (step by step)

1. **Supervisor** reads state via CoT and routes to Scanner
2. **Scanner** clones the repo, runs regex + CodeQL, returns raw findings
3. **Supervisor** re-evaluates, routes to Enricher
4. **Enricher** runs an agentic tool-calling loop:
   - Calls `retrieve_crypto_knowledge` (BM25 + Dense hybrid)
   - Calls `calculate_hndl_score` for each finding
   - Calls `get_migration_guidance` for each vulnerable algo
   - Persists findings via MCP database tools
5. **Reflector** critiques the enrichment quality. If score < 0.8, routes back to Enricher (max 2 retries)
6. **Reporter** generates the CycloneDX v1.7 CBOM

## Deploy to AKS

```bash
# Build and push image
docker build -t your-acr.azurecr.io/qbom-backend:latest ./backend
docker push your-acr.azurecr.io/qbom-backend:latest

# Deploy
kubectl apply -f k8s-deployment.yaml
```

## Evaluation

```bash
# Run DeepEval + RAGAS evaluation batch
curl http://localhost:8000/api/eval/run
```

LangSmith traces are automatically captured when `LANGCHAIN_TRACING_V2=true`.
