# Open-Monitor - Windows Deployment Guide

## Quick Start

```powershell
# 1. Clone and navigate to the project
cd e:\open-cve-report

# 2. Run the deployment script
.\scripts\deploy-windows.ps1 start
```

The script will:
- Check Docker installation
- Create `.env` file from template
- Generate secure secrets
- Build Docker images
- Start all services

Access the application at `http://localhost`

## Prerequisites

1. **Docker Desktop for Windows**
   - Download from: https://www.docker.com/products/docker-desktop
   - Enable WSL 2 backend (recommended)
   - Allocate at least 4GB RAM to Docker

2. **PowerShell 5.1 or higher**
   - Windows PowerShell or PowerShell Core

## Deployment Commands

```powershell
# Start all services (default)
.\scripts\deploy-windows.ps1 start

# Stop all services
.\scripts\deploy-windows.ps1 stop

# Restart services
.\scripts\deploy-windows.ps1 restart

# View logs
.\scripts\deploy-windows.ps1 logs          # All services
.\scripts\deploy-windows.ps1 logs app      # Specific service
.\scripts\deploy-windows.ps1 logs nginx

# Check status
.\scripts\deploy-windows.ps1 status

# Rebuild all images (no cache)
.\scripts\deploy-windows.ps1 rebuild

# Clean everything (WARNING: removes all data)
.\scripts\deploy-windows.ps1 clean

# Show help
.\scripts\deploy-windows.ps1 help
```

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

```powershell
# Required
SECRET_KEY=your-secret-key-here  # Generate with: python -c "import secrets; print(secrets.token_hex(32))"

# Optional - External APIs
NVD_API_KEY=your-nvd-api-key
OPENAI_API_KEY=your-openai-api-key

# Optional - Email
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email
MAIL_PASSWORD=your-password
```

### Services Configuration

The Windows deployment uses `infra/compose/docker-compose.windows.yml` which is optimized for Windows:

- **Ollama disabled by default** - Enable in compose file if needed
- **SQLite instead of PostgreSQL** - Easier setup for Windows
- **Local volumes** - Better performance on Windows

To use the standard compose file instead:

```powershell
$env:COMPOSE_FILE="infra/compose/docker-compose.yml"
.\scripts\deploy-windows.ps1 start
```

## Services

| Service | URL | Description |
|---------|-----|-------------|
| Main App | http://localhost | Flask application |
| Airflow | http://localhost:8080 | Workflow scheduler |
| Ollama | http://localhost:11434 | AI/LLM (if enabled) |

Default credentials for Airflow:
- Username: `admin`
- Password: `admin`

## Troubleshooting

### Docker not running
```powershell
# Start Docker Desktop
# Wait for the whale icon to stop animating
# Then retry deployment
```

### Port already in use
```powershell
# Check what's using port 80
netstat -ano | findstr :80

# Stop the service or change ports in .env:
HTTP_PORT=8080
HTTPS_PORT=8443
```

### Build fails
```powershell
# Clean and rebuild
.\scripts\deploy-windows.ps1 clean
.\scripts\deploy-windows.ps1 rebuild
```

### Permission issues
Run PowerShell as Administrator if you encounter permission errors.

### Slow performance
- Increase Docker memory limit to 8GB+
- Disable Ollama if not needed
- Use SSD for Docker volumes

## Windows-Specific Notes

1. **Line endings**: Git may convert line endings. Ensure scripts use CRLF for Windows:
   ```powershell
   git config core.autocrlf true
   ```

2. **Path separators**: The script handles both `/` and `\` automatically.

3. **Volume permissions**: Windows handles volume permissions differently. The compose file uses named volumes to avoid issues.

4. **Antivirus**: Some antivirus software may block Docker. Add Docker to exclusions if needed.

## Production Deployment

For production on Windows Server:

1. Use Windows Server 2019/2022 with Containers feature
2. Configure SSL certificates in `infra/docker/nginx/ssl/`
3. Set strong passwords in `.env`
4. Enable firewall rules for required ports
5. Set up automated backups

```powershell
# Enable Windows Containers (Windows Server)
Install-WindowsFeature -Name Containers
Restart-Computer
```

## Support

For issues specific to Windows deployment:
1. Check Docker Desktop logs: `%LOCALAPPDATA%\Docker\log\`
2. View container logs: `.\scripts\deploy-windows.ps1 logs`
3. Check Windows Event Viewer for Docker errors