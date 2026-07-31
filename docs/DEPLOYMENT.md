# Open-Monitor - Deployment Guide

## Quick Start (Local Development)

```bash
# 1. Clone and setup
git clone <repo-url>
cd open-monitor

# 2. Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your settings

# 5. Run
python run.py
```

The app will start at `http://localhost:5000` with SQLite in development mode.

## Interactive Deploy Menu

```bash
./scripts/deploy.sh
```

This provides options for local dev, Docker, Heroku, cloud deployment, Airflow setup, and database management.

## Docker Deployment

### Full Stack (Recommended)

```bash
# Configure environment
cp .env.example .env
# Edit .env - set SECRET_KEY, POSTGRES_PASSWORD at minimum

# Start all services (run from repo root)
docker compose --project-directory . -f infra/compose/docker-compose.yml up --build -d

# View logs
docker compose --project-directory . -f infra/compose/docker-compose.yml logs -f app
```

Services started:
- **App**: Flask application (port 5000, behind Nginx)
- **Nginx**: Reverse proxy (ports 80/443)
- **PostgreSQL Core**: User/asset data (port 5432)
- **PostgreSQL Public**: CVE/NVD data (port 5433)
- **Redis**: Cache & sessions (port 6379)
- **Celery Worker/Beat**: Background tasks
- **Airflow**: DAG scheduling (port 8080)

### Build Image Only

```bash
docker build -t open-monitor:latest .
docker run -p 5000:5000 --env-file .env open-monitor:latest
```

## Database Setup

### SQLite (Development)
Automatic - no configuration needed. Database created at `app.db`.

### PostgreSQL (Production)

```bash
# Initialize databases
python scripts/db/init_postgres.py

# Run migrations
flask db upgrade

# Create admin user
python scripts/admin/create_admin.py

# Seed sample data (optional)
python scripts/db/seed_vulns.py
python scripts/db/seed_assets.py
```

## Airflow Setup

DAGs are located in `infra/airflow/dags/`. They trigger the Flask API endpoints for:
- NVD incremental sync (daily at 04:00 AM)
- NVD full sync (weekly, Sunday 02:00 AM)
- EUVD sync (triggered after NVD)
- MITRE enrichment (triggered after EUVD)
- Daily executive report (06:00 AM)

```bash
# Start Airflow with Docker
docker compose --project-directory . -f infra/compose/docker-compose.yml -f infra/compose/docker-compose.airflow.yml up -d airflow-init
docker compose --project-directory . -f infra/compose/docker-compose.yml -f infra/compose/docker-compose.airflow.yml up -d airflow-webserver airflow-scheduler

# Access UI at http://localhost:8080
# Default credentials: airflow/airflow
```

## Environment Variables

See `.env.example` for all available configuration options. Key variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes | Flask secret key |
| `POSTGRES_PASSWORD` | Yes (prod) | Database password |
| `NVD_API_KEY` | No | NVD API key (higher rate limits) |
| `OPENAI_API_KEY` | No | For AI-powered reports |
| `REDIS_PASSWORD` | No | Redis authentication |

## Production Checklist

- [ ] Set strong `SECRET_KEY`
- [ ] Configure PostgreSQL with secure passwords
- [ ] Set `SESSION_COOKIE_SECURE=true`
- [ ] Configure SSL certificates in `infra/docker/nginx/ssl/`
- [ ] Set `FLASK_ENV=production`
- [ ] Configure email settings for alerts
- [ ] Set up NVD API key for higher rate limits
- [ ] Review resource limits in `infra/compose/docker-compose.yml`
