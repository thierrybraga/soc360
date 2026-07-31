# Open-Monitor v3.0

<div align="center">

![Open-Monitor Logo](docs/images/logo.png)

**Enterprise Cybersecurity Vulnerability Management Platform**

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)](https://flask.palletsprojects.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-blue.svg)](https://postgresql.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[Features](#features) • [Quick Start](#quick-start) • [Documentation](#documentation) • [API](#api-reference) • [Contributing](#contributing)

</div>

---

## Overview

Open-Monitor is a comprehensive cybersecurity vulnerability management platform that integrates with the National Vulnerability Database (NVD) to provide real-time CVE monitoring, asset inventory management, intelligent alerting, and executive reporting.

Built for enterprise security teams, Open-Monitor helps organizations:
- **Track** vulnerabilities affecting their infrastructure
- **Prioritize** remediation based on business impact
- **Monitor** for new threats in real-time
- **Report** security posture to stakeholders

## Features

### 🔍 Vulnerability Database
- Real-time synchronization with NIST NVD
- Full CVE database with CVSS scores (v2.0, v3.0, v3.1, v4.0)
- CISA Known Exploited Vulnerabilities (KEV) tracking
- Advanced filtering and search capabilities
- Vendor and product classification

### 📦 Asset Inventory
- Comprehensive asset management
- Software inventory with vendor/product mapping
- Automatic CVE matching for installed software
- Business Impact Analysis (BIA) fields
- Risk scoring based on CVSS + business context

### 🔔 Intelligent Monitoring
- Customizable alerting rules
- Multiple notification channels (Email, Webhook, Slack)
- Rule templates for common scenarios
- Severity thresholds and vendor-specific alerts
- CISA KEV automatic notifications

### 📊 Analytics & Reporting
- Executive dashboards with key metrics
- Trend analysis and visualizations
- Compliance reporting (SOC 2, ISO 27001, PCI-DSS)
- AI-powered insights and recommendations
- PDF export with customizable templates

### 🔐 Enterprise Security
- Role-based access control (RBAC)
- Multi-factor authentication support
- API key management
- Audit logging
- OWASP Top 10 compliance

## Quick Start

### Prerequisites

- Docker 20.10+ and Docker Compose 2.0+
- 4GB RAM minimum (8GB recommended)
- 20GB disk space

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/open-monitor.git
   cd open-monitor
   ```

2. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   nano .env
   ```

3. **Generate secure secrets**
   ```bash
   # Generate SECRET_KEY
   python -c "import secrets; print(secrets.token_hex(32))"
   
   # Generate database password
   python -c "import secrets; print(secrets.token_urlsafe(24))"
   ```

4. **Start the services**
   ```bash
   docker compose --project-directory . -f infra/compose/docker-compose.yml up -d
   ```

5. **Access the application**
   - Open http://localhost in your browser
   - Complete the initial setup wizard
   - Create your admin account

### First-Time Setup

1. Navigate to http://localhost/auth/init
2. Create your administrator account
3. (Optional) Enter your NVD API key
4. Start the initial vulnerability sync

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         NGINX (Reverse Proxy)                    │
│                    SSL Termination • Rate Limiting               │
└─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Flask Application (Gunicorn)                  │
│              Controllers • Services • Models • APIs              │
└─────────────────────────────────────────────────────────────────┘
           │                    │                    │
           ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   PostgreSQL    │  │   PostgreSQL    │  │      Redis      │
│   (Core DB)     │  │  (Public DB)    │  │    (Cache)      │
│                 │  │                 │  │                 │
│ • Users         │  │ • CVEs          │  │ • Sessions      │
│ • Assets        │  │ • CVSS Data     │  │ • Rate Limits   │
│ • Rules         │  │ • Weaknesses    │  │ • Sync Status   │
│ • Reports       │  │ • References    │  │ • API Cache     │
└─────────────────┘  └─────────────────┘  └─────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Celery Workers (Background Tasks)             │
│           NVD Sync • Report Generation • Notifications           │
└─────────────────────────────────────────────────────────────────┘
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask secret key (required) | - |
| `FLASK_ENV` | Environment mode | `production` |
| `POSTGRES_USER` | Database user | `openmonitor` |
| `POSTGRES_PASSWORD` | Database password (required) | - |
| `NVD_API_KEY` | NVD API key (optional) | - |
| `REDIS_PASSWORD` | Redis password | - |
| `LOG_LEVEL` | Logging level | `INFO` |

See `.env.example` for complete configuration options.

### NVD API Key

While optional, an NVD API key significantly improves sync performance:
- **Without key**: 5 requests per 30 seconds
- **With key**: 50 requests per 30 seconds

Request a free API key at: https://nvd.nist.gov/developers/request-an-api-key

## API Reference

### Authentication

All API requests require authentication via session cookie or API key:

```bash
# Using API key
curl -H "X-API-Key: your-api-key" https://your-domain/api/...

# Using session (after login)
curl -b cookies.txt https://your-domain/api/...
```

### Endpoints

#### Vulnerabilities

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/nvd/api/list` | List vulnerabilities with filters |
| GET | `/nvd/api/{cve_id}` | Get CVE details |
| GET | `/nvd/api/stats` | Get vulnerability statistics |
| GET | `/nvd/api/vendors` | List vendors/products |
| POST | `/nvd/api/sync/start` | Start NVD sync |
| GET | `/nvd/api/sync/status` | Get sync status |

#### Assets

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/inventory/api/list` | List assets |
| POST | `/inventory/api/create` | Create asset |
| GET | `/inventory/api/{id}` | Get asset details |
| PUT | `/inventory/api/{id}` | Update asset |
| DELETE | `/inventory/api/{id}` | Delete asset |
| POST | `/inventory/api/scan` | Scan asset for vulnerabilities |

#### Monitoring Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/monitoring/api/rules` | List rules |
| POST | `/monitoring/api/rules` | Create rule |
| PUT | `/monitoring/api/rules/{id}` | Update rule |
| DELETE | `/monitoring/api/rules/{id}` | Delete rule |
| POST | `/monitoring/api/rules/{id}/test` | Test rule |

#### Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/reports/api/list` | List reports |
| POST | `/reports/api/generate` | Generate report |
| GET | `/reports/api/{id}/download` | Download report |

## Development

### Local Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export FLASK_APP=app:create_app
export FLASK_ENV=development

# Initialize database
flask init-db

# Create admin user
flask create-admin

# Run development server
flask run --reload
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_nvd_service.py -v
```

### Code Quality

```bash
# Format code
black app/

# Check linting
flake8 app/

# Type checking
mypy app/
```

## Deployment

### Production Checklist

- [ ] Generate strong `SECRET_KEY`
- [ ] Set secure database passwords
- [ ] Configure SSL certificates
- [ ] Enable `SESSION_COOKIE_SECURE=true`
- [ ] Set up log rotation
- [ ] Configure backup strategy
- [ ] Set up monitoring/alerting
- [ ] Review rate limiting settings
- [ ] Configure email for notifications

### SSL Configuration

1. Place your certificates in `infra/docker/nginx/ssl/`:
   - `fullchain.pem` - Certificate chain
   - `privkey.pem` - Private key

2. Configure the HTTPS server in `infra/docker/nginx/conf.d/openmonitor.conf`.

3. Restart NGINX: `docker compose --project-directory . -f infra/compose/docker-compose.yml restart nginx`

### Scaling

```bash
# Scale application workers
docker compose --project-directory . -f infra/compose/docker-compose.yml up -d --scale app=3

# Scale Celery workers
docker compose --project-directory . -f infra/compose/docker-compose.yml up -d --scale celery-worker=4
```

## Troubleshooting

### Common Issues

**Database connection errors**
```bash
# Check database logs
docker compose --project-directory . -f infra/compose/docker-compose.yml logs db-core db-public

# Verify connections
docker compose --project-directory . -f infra/compose/docker-compose.yml exec app flask shell
>>> from app.extensions.db import db
>>> db.engine.execute('SELECT 1')
```

**NVD sync failures**
```bash
# Check sync status
curl http://localhost/nvd/api/sync/status

# View sync logs
docker compose --project-directory . -f infra/compose/docker-compose.yml logs -f celery-worker
```

**Redis connection issues**
```bash
# Test Redis connection
docker compose --project-directory . -f infra/compose/docker-compose.yml exec redis redis-cli ping
```

### Logs

```bash
# Application logs
docker compose --project-directory . -f infra/compose/docker-compose.yml logs -f app

# All services
docker compose --project-directory . -f infra/compose/docker-compose.yml logs -f

# Specific service
docker compose --project-directory . -f infra/compose/docker-compose.yml logs -f celery-worker
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [NIST National Vulnerability Database](https://nvd.nist.gov/)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Flask](https://flask.palletsprojects.com/)
- [Chart.js](https://www.chartjs.org/)

---

<div align="center">
Built with ❤️ for the cybersecurity community
</div>
