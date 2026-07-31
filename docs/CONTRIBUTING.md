# Contributing to Open-Monitor

## Project Structure

```
open-monitor/
├── app/           # Flask application (controllers, models, services)
├── scripts/       # Utility scripts (deploy, secrets, NVD sync)
├── infra/         # Docker compose, nginx, Airflow DAGs, Ollama, PostgreSQL config
├── tests/         # Unit, integration, e2e tests
├── docs/          # Documentation
├── migrations/    # Alembic database migrations
└── run.py         # Development entry point
```

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
python run.py
```

## Code Standards

- **Python**: Follow PEP 8. Use `black` for formatting, `flake8` for linting.
- **Imports**: Always use absolute imports from `app.` (e.g., `from app.models.auth import User`)
- **Controllers**: Each feature has its own Blueprint in `app/controllers/<feature>/`
- **Models**: Organized by domain in `app/models/<domain>/`
- **Services**: Business logic goes in `app/services/`, not in controllers

## Running Tests

```bash
# All tests
pytest

# Unit tests only
pytest tests/unit/

# Integration tests
pytest tests/integration/

# With coverage
pytest --cov=app --cov-report=html
```

## Database Migrations

```bash
# After model changes
flask db migrate -m "Description of change"
flask db upgrade
```

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes
3. Ensure tests pass
4. Submit a PR with a clear description
