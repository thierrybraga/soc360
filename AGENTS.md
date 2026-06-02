# Open-Monitor v3.0 — SOC360

Enterprise vulnerability management platform. Integrates NVD, EUVD, MITRE ATT&CK, D3FEND, CISA KEV, Fortinet, Wazuh, and Cisco Umbrella for real-time CVE tracking, asset correlation, and AI-driven reporting.

**Stack:** Flask 3.0 · PostgreSQL 15 (dual-DB) · Redis · Celery · SQLAlchemy 2.0 · Gunicorn · NGINX · Airflow (optional) · Ollama/OpenAI

---

## Development Commands

```bash
# Dev server
python run.py

# Docker — core stack (nginx, app, celery, redis)
docker compose up -d
docker compose down
docker compose logs -f app

# Docker — overlays opcionais
docker compose -f docker-compose.yml -f docker-compose.ollama.yml up -d   # + LLM local
docker compose -f docker-compose.yml -f docker-compose.airflow.yml up -d  # + Airflow DAGs

# Oracle Linux 9
./scripts/deploy-linux.sh start                         # core stack
./scripts/deploy-linux.sh start --with-ollama           # + Ollama
./scripts/deploy-linux.sh start --with-airflow          # + Airflow

# Install (dev/test inclui tudo de produção + ferramentas)
pip install -r requirements-dev.txt    # dev local
pip install -r requirements.txt        # produção (Docker usa este)

# Tests (requer requirements-dev.txt)
pytest tests/
pytest tests/unit/
pytest tests/integration/
pytest --cov=app tests/

# Code quality (run before committing — requer requirements-dev.txt)
black app/ tests/
isort app/ tests/
flake8 app/ tests/
mypy app/

# Database migrations
flask db migrate -m "description"
flask db upgrade
flask db downgrade

# Celery workers (local, fora do Docker)
celery -A scripts.workers.celery_worker.celery worker --loglevel=info
celery -A scripts.workers.celery_worker.celery beat --loglevel=info

# NVD manual sync
python scripts/run_nvd_sync.py           # incremental (30 dias)
python scripts/run_full_sync_safe.py     # full sync com rate limit
python scripts/reset_sync_status.py     # resetar status travado

# Secrets
python scripts/generate-secrets.py      # gera secrets/secret_key.txt + redis_password.txt
./scripts/rotate-secrets.sh             # rotacionar em produção
```

---

## Architecture

```
NGINX (80/443)
  └── Flask/Gunicorn (app:5000)
        ├── Controllers (Blueprints)  →  app/controllers/<domain>/
        ├── Services (Business logic)  →  app/services/<domain>/
        ├── Models (ORM)               →  app/models/<domain>/
        └── Tasks (Async)              →  app/tasks/
              ├── PostgreSQL core     (users, assets, rules, reports)
              ├── PostgreSQL public   (CVE, CVSS, MITRE, D3FEND data)
              ├── Redis               (sessions, cache, Celery broker)
              └── Celery + Beat       (NVD sync, reports, alerts)
```

### Dual-Database Design
- **`core` DB** (`openmonitor_core`): transactional — users, assets, monitoring rules, reports, audit logs
- **`public` DB** (`openmonitor_public`): read-heavy — CVE/NVD, CVSS, weaknesses, MITRE, D3FEND data
- Models inherit `CoreModel` (core DB) or `PublicModel` (public DB) from `app/models/system/base_model.py`
- SQLAlchemy bind: `__bind_key__ = 'public'` on public models

---

## Project Structure

```
app/
├── __init__.py          # create_app() factory — registers all 16 blueprints
├── controllers/         # Flask blueprints (routes only, no business logic)
│   ├── auth/            # Login, register, password reset, TACACS+
│   ├── chatbot/         # AI chatbot (Ollama/OpenAI)
│   ├── nvd/             # CVE browsing and management
│   ├── inventory/       # Asset management
│   ├── monitoring/      # Alerting rules
│   ├── reports/         # Report generation (PDF/DOCX)
│   ├── analytics/       # Dashboards
│   ├── api/             # REST API at /api/v1/*
│   ├── d3fend/          # D3FEND defense mapping
│   ├── mitre/           # MITRE ATT&CK
│   ├── euvd/            # European Vulnerability Database
│   ├── fortinet/        # Fortinet advisory matching
│   ├── wazuh/           # Wazuh SIEM
│   ├── umbrella/        # Cisco Umbrella
│   └── account/         # User account settings
├── services/            # Business logic layer
│   ├── core/            # ai_service, ollama_service, openai_service, rag_service, redis_cache_service
│   ├── nvd/             # NVD sync orchestration
│   ├── inventory/       # asset_correlation_service
│   ├── auth/            # tacacs_service
│   └── ...              # one subdir per domain
├── models/              # SQLAlchemy ORM
│   ├── system/          # BaseModel, AuditLog, ChatSession, ChatMessage, enums
│   ├── auth/            # User, Role, UserRole
│   ├── nvd/             # Vulnerability, CvssMetric, Weakness, Reference
│   ├── inventory/       # Asset, AssetVulnerability, Category
│   ├── monitoring/      # MonitoringRule, Alert, Report
│   └── ...
├── forms/               # WTForms (HTML form validation)
├── schemas/             # Marshmallow (API serialization)
├── extensions/          # Flask extension setup (db, login, csrf, celery)
├── tasks/               # Celery async tasks (nvd, euvd, mitre)
├── jobs/                # Scheduled jobs + API fetchers
│   └── fetchers/        # nvd_client, euvd_client, etc.
├── settings/            # Config by environment
│   ├── base.py          # All settings with defaults
│   ├── development.py
│   └── production.py
└── utils/               # Helpers and security utilities

scripts/
├── deploy-linux.sh       # Deploy Linux/OL9 (suporta --with-ollama, --with-airflow)
├── deploy-windows.ps1    # Deploy Windows/Docker Desktop
├── generate-secrets.py   # Gera secrets/secret_key.txt e secrets/redis_password.txt
├── rotate-secrets.sh     # Rotacionar secrets em produção
├── run_nvd_sync.py       # NVD sync incremental manual
├── run_full_sync_safe.py # NVD full sync com rate limiting
├── reset_sync_status.py  # Resetar status de sync travado
└── workers/
    └── celery_worker.py  # Entry point Celery (referenciado pelo docker-compose)

secrets/                  # Arquivos de secret (git-ignored, nunca commitar *.txt)
├── README.md             # Instruções de setup
└── .gitkeep
```

---

## Conventions

### Adding a New Feature
1. Create `app/controllers/<domain>/<domain>_controller.py` with a Blueprint
2. Create `app/services/<domain>/<domain>_service.py` for business logic
3. Create `app/models/<domain>/<domain>_model.py` inheriting CoreModel or PublicModel
4. Register the blueprint in `app/__init__.py`
5. Add migration: `flask db migrate -m "add <domain> tables"`

### API Endpoints
- All REST endpoints live under `/api/v1/*`
- Return JSON: `{"status": "success"|"error", "data": ..., "message": ...}`
- Rate limiting applied by default; configure in `app/settings/base.py`
- CSRF exempt on API routes using API key auth: decorate with `@csrf.exempt`

### Security Rules
- CSRF protection is **mandatory** on all HTML form routes — never disable globally
- Passwords: bcrypt with `rounds=12` — do not change without a password re-hash migration
- Never commit `.env` or `secrets/*.txt` — use `.env.example` and `secrets/README.md` as templates
- `SESSION_COOKIE_SECURE=true` required for HTTPS deployments
- `FLASK_DEBUG=0` in production
- Rotate secrets periodically with `scripts/rotate-secrets.sh`

### Models
- Always inherit from `CoreModel` or `PublicModel` (not directly from `db.Model`)
- Use `CoreModel` for business data, `PublicModel` for CVE/vulnerability data
- All models get `id`, `created_at`, `updated_at`, `save()`, `delete()`, `to_dict()` from base
- Enums are defined centrally in `app/models/system/enums.py`

### Forms vs Schemas
- **WTForms** (`app/forms/`) → HTML form validation (CSRF token included)
- **Marshmallow** (`app/schemas/`) → API request/response serialization

---

## AI / Chatbot

Factory pattern selects provider at runtime:

```python
# app/services/core/ai_service.py
service = get_ai_service()  # Returns OpenAIService or OllamaService
response = service.generate_chat_response(message, context, history)
```

- `AI_PROVIDER=openai` **(default)** → `OpenAIService`
  - Com `OPENAI_API_KEY`: respostas reais, modelo `gpt-4o-mini`
  - Sem chave: demo mode automático (respostas simuladas, sem erros)
- `AI_PROVIDER=ollama` → `OllamaService` (local, requer overlay `docker-compose.ollama.yml`)
  - `OLLAMA_BASE_URL` aponta para container: `http://ollama:11434/v1`
  - Default model: `gemma4:e4b`
- RAG pipeline: `app/services/core/rag_service.py` — enriches context with CVE DB data
- Chat history: `ChatSession` + `ChatMessage` models in `app/models/system/chat.py`

---

## Environment Variables (Critical)

```bash
# Core security
SECRET_KEY=          # gerado em secrets/secret_key.txt pelo deploy script
FLASK_ENV=           # development | production
FLASK_DEBUG=0        # 1 apenas em dev

# Databases
POSTGRES_USER=openmonitor
POSTGRES_PASSWORD=
POSTGRES_CORE_DB=openmonitor_core
POSTGRES_PUBLIC_DB=openmonitor_public

# Redis
REDIS_PASSWORD=      # obrigatório em produção
REDIS_DB_SESSIONS=0
REDIS_DB_CELERY_BROKER=1
REDIS_DB_CELERY_RESULT=2

# External APIs
NVD_API_KEY=         # 5 req/30s sem key; 50 req/30s com key
UMBRELLA_USE_MOCK=true

# AI provider (default: openai)
AI_PROVIDER=openai   # openai (default) | ollama
OPENAI_API_KEY=      # recomendado; sem key → demo mode automático
OPENAI_MODEL=gpt-4o-mini
# Ollama — apenas com overlay docker-compose.ollama.yml:
# OLLAMA_MODEL=gemma4:e4b

# Email
MAIL_SERVER=
MAIL_PORT=587
MAIL_SUPPRESS_SEND=true   # false para enviar de verdade
```

Full reference: [`.env.example`](.env.example) · [`app/settings/base.py`](app/settings/base.py)

---

## Testing

```bash
pytest tests/

# Fixtures em tests/conftest.py:
# - SQLite in-memory (sem PostgreSQL necessário para unit tests)
# - CSRF desabilitado
# - Roles padrão pré-criadas (ADMIN, ANALYST, VIEWER, API_USER)
# - Admin user fixture disponível

# Use factory-boy para model fixtures
# Testes de integração requerem DB real — tests/integration/verify_nvd_sync.py
```

---

## External Integrations

| Integration | Service file | Mock mode |
|-------------|-------------|-----------|
| NVD (NIST) | `app/jobs/fetchers/nvd_client.py` | Not needed (rate-limited) |
| EUVD | `app/services/euvd/euvd_service.py` | — |
| MITRE ATT&CK | `app/services/mitre/mitre_attack_service.py` | — |
| D3FEND | `app/services/d3fend/d3fend_service.py` | — |
| Fortinet | `app/services/fortinet/fortinet_matching.py` | Preset data |
| Cisco Umbrella | `app/controllers/umbrella/` | `UMBRELLA_USE_MOCK=true` |
| Wazuh | `app/services/wazuh/` | — |
| OpenAI | `app/services/core/openai_service.py` | No key → demo responses |
| Ollama | `app/services/core/ollama_service.py` | Local inference |
| SMTP | `app/services/core/email_service.py` | `MAIL_SUPPRESS_SEND=true` |

---

## Key Files Reference

| File | What it does |
|------|-------------|
| `app/__init__.py` | App factory — start here to understand blueprint registration |
| `app/settings/base.py` | All configurable settings with defaults |
| `app/extensions/db.py` | Dual-database SQLAlchemy setup |
| `app/models/system/base_model.py` | `CoreModel` and `PublicModel` — base for all models |
| `app/models/system/enums.py` | All system enums (Severity, AssetType, VulnerabilityStatus, etc.) |
| `app/services/core/ai_service.py` | AI provider factory |
| `app/jobs/fetchers/nvd_client.py` | NVD API 2.0 client with rate limiting |
| `tests/conftest.py` | All test fixtures and app configuration |
| `docs/ARCHITECTURE.md` | Detailed architecture documentation |
| `docs/DEPLOYMENT.md` | Production deployment guide |
| `secrets/README.md` | Setup instructions for Docker secrets |
| `.env.example` | Full environment variable template |

---

## Data Pipeline

### Celery Beat (default — incluído no core stack)
NVD sync incremental a cada 4h, configurado em `app/settings/base.py`:
```python
CELERY_BEAT_SCHEDULE = {
    'sync-nvd-incremental': {'task': 'nvd.sync', 'schedule': crontab(hour='*/4'), ...}
}
```

### Airflow (opcional — `docker-compose.airflow.yml`)
DAGs em `airflow/dags/`:
- `nvd_sync.py` — incremental às 04:00 diário, full sync domingos às 02:00
- `euvd_sync.py` — EU Vulnerability Database
- `mitre_sync.py` — MITRE ATT&CK enrichment
- `daily_report.py` — geração e distribuição de relatórios

Requer `airflow/.env` (copie de `airflow/.env.example`).
