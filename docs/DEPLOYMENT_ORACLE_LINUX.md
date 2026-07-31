# Open-Monitor - Oracle Linux 9 Deployment Guide

## Quick Start

```bash
# 1. Clone and navigate to the project
cd /path/to/open-cve-report

# 2. Run the deployment script (auto-detects OL9)
./scripts/deploy-linux.sh start
```

The script automatically detects Oracle Linux 9 and uses optimized configurations.

## Prerequisites

### 1. Install Docker on Oracle Linux 9

```bash
# Add Docker repository
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# Install Docker
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Start and enable Docker
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group (logout/login required)
sudo usermod -aG docker $USER
newgrp docker
```

### 2. Install Git (if needed)
```bash
sudo dnf install -y git
```

## Deployment Commands

```bash
# Start all services (default)
./scripts/deploy-linux.sh start

# Stop all services
./scripts/deploy-linux.sh stop

# Restart services
./scripts/deploy-linux.sh restart

# View logs
./scripts/deploy-linux.sh logs          # All services
./scripts/deploy-linux.sh logs app      # Specific service
./scripts/deploy-linux.sh logs nginx

# Check status
./scripts/deploy-linux.sh status

# Rebuild all images (no cache)
./scripts/deploy-linux.sh rebuild

# Update base images
./scripts/deploy-linux.sh update

# Clean everything (WARNING: removes all data)
./scripts/deploy-linux.sh clean

# Show help
./scripts/deploy-linux.sh help
```

## Oracle Linux 9 Optimizations

The deployment automatically uses Oracle Linux 9 optimized images when running on OL9:

| Feature | Standard | OL9 Optimized |
|---------|----------|---------------|
| Base Image | python:3.11-slim | oraclelinux:9 |
| Python | 3.11 | 3.11 (system) |
| Package Manager | apt | microdnf |
| Ollama Backend | Generic | CPU-AVX2 |
| Security | Standard | **Rootless Containers** |
| Memory Usage | Standard | Optimized |

### CPU AVX2 Support

Oracle Linux 9 deployment enables AVX2 instructions for better AI/LLM performance:

```bash
# Check if CPU supports AVX2
grep -o 'avx2' /proc/cpuinfo | head -1

# Expected output: avx2
```

### Rootless Security (No Root Required)

All containers run as non-root users with minimal capabilities:

```yaml
# Security configuration in infra/compose/docker-compose.ol9.yml
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
cap_add:
  - SETGID
  - SETUID  # Only where needed
```

Benefits:
- **No root access required** during container execution
- **Reduced attack surface** with dropped capabilities
- **No-new-privileges** prevents privilege escalation
- **User namespaces** isolation

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
# Required
SECRET_KEY=$(openssl rand -hex 32)

# Optional - External APIs
NVD_API_KEY=your-nvd-api-key
OPENAI_API_KEY=your-openai-api-key

# Optional - Ollama Model
OLLAMA_MODEL=llama3.2:24b
OLLAMA_NUM_THREADS=8
```

### Resource Limits

OL9 deployment uses higher resource limits by default:

```yaml
# infra/compose/docker-compose.ol9.yml
app:
  deploy:
    resources:
      limits:
        cpus: '4'
        memory: 4G

ollama:
  deploy:
    resources:
      limits:
        cpus: '8'
        memory: 32G
```

Adjust based on your hardware:
```bash
# .env file
CPU_LIMIT=4
MEMORY_LIMIT=16G
CPU_RESERVE=2
MEMORY_RESERVE=8G
```

## Services

| Service | URL | Description |
|---------|-----|-------------|
| Main App | http://localhost | Flask application |
| Airflow | http://localhost:8080 | Workflow scheduler |
| Ollama | http://localhost:11434 | AI/LLM (CPU-AVX2) |

Default credentials for Airflow:
- Username: `admin`
- Password: `admin`

## Ollama on Oracle Linux 9 (Rootless)

Ollama now runs as non-root user `ollama` (UID 1000):

```bash
# Check Ollama user
docker exec soc360-ollama id
# Output: uid=1000(ollama) gid=1000(ollama) groups=1000(ollama)

# Manual download
docker exec -it soc360-ollama ollama pull llama3.2:24b

# Or set in .env and restart
echo "OLLAMA_MODEL=llama3.2:24b" >> .env
./scripts/deploy-linux.sh restart
```

Models are stored in `/home/ollama/.ollama` (not `/root/.ollama`).

### Performance Tuning

```bash
# Check CPU cores
nproc

# Optimal threads = cores * 0.75
# Example: 8 cores → 6 threads
echo "OLLAMA_NUM_THREADS=6" >> .env
```

## Troubleshooting

### Docker daemon not running
```bash
sudo systemctl start docker
sudo systemctl status docker
```

### Permission denied
```bash
# Check docker group
groups

# Add to docker group
sudo usermod -aG docker $USER
newgrp docker
```

### Port already in use
```bash
# Check port usage
sudo ss -tlnp | grep :80

# Change ports in .env
HTTP_PORT=8080
HTTPS_PORT=8443
```

### SELinux issues

With rootless containers, SELinux issues are minimized:

```bash
# Check SELinux status
getenforce

# For rootless mode, SELinux usually works without changes
# If needed, add label to volumes:
:Z  # for private unshared label
:z  # for shared label

# Example in docker-compose:
# volumes:
#   - ./data:/app/data:Z
```

### Rootless Mode Verification

```bash
# Verify containers are running as non-root
docker exec soc360-app id
docker exec soc360-ollama id
docker exec soc360-airflow-webserver id

# Check capabilities (minimal/none for rootless)
docker exec soc360-app cat /proc/self/status | grep Cap

# All should show non-root UID and minimal capabilities
```

### Build fails on OL9
```bash
# Clean and rebuild
./scripts/deploy-linux.sh clean
./scripts/deploy-linux.sh rebuild

# Check Docker logs
sudo journalctl -u docker -n 100
```

### MicroDNF issues
```bash
# If microdnf fails, update system
sudo dnf update -y
sudo dnf clean all
```

## Production Deployment

### 1. SSL Certificates

```bash
# Place certificates in
sudo mkdir -p infra/docker/nginx/ssl
sudo cp /path/to/cert.pem infra/docker/nginx/ssl/fullchain.pem
sudo cp /path/to/key.pem infra/docker/nginx/ssl/privkey.pem
```

### 2. Firewall Configuration

```bash
# Open required ports
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --permanent --add-port=11434/tcp
sudo firewall-cmd --reload
```

### 3. Auto-start on Boot (Rootless Compatible)

```bash
# Enable Docker auto-start
sudo systemctl enable docker

# Create systemd service for the application
# Note: User service runs containers as non-root automatically
sudo tee /etc/systemd/system/openmonitor.service << EOF
[Unit]
Description=Open-Monitor Application
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/path/to/open-cve-report
ExecStart=/path/to/open-cve-report/scripts/deploy-linux.sh start
ExecStop=/path/to/open-cve-report/scripts/deploy-linux.sh stop
User=your-user
Group=docker

# Security hardening for service
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/path/to/open-cve-report

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable openmonitor
```

### Rootless Podman Alternative

For fully rootless deployment, you can use Podman:

```bash
# Install Podman
sudo dnf install -y podman podman-docker

# Deploy without root
./scripts/deploy-linux.sh start

# Or with podman-compose (run from repo root)
pip3 install podman-compose
podman-compose --project-directory . -f infra/compose/docker-compose.ol9.yml up -d
```

## Performance Monitoring

### Check Container Stats
```bash
docker stats --no-stream
```

### View Resource Usage
```bash
# App container
docker exec soc360-app ps aux

# Ollama performance
docker exec soc360-ollama ollama ps
```

### System Monitoring
```bash
# Install monitoring tools
sudo dnf install -y htop iotop

# Monitor in real-time
htop
```

## Upgrade Guide

```bash
# 1. Backup data
cp -r backups backups-$(date +%Y%m%d)

# 2. Pull latest code
git pull origin main

# 3. Update images
./scripts/deploy-linux.sh update

# 4. Rebuild
./scripts/deploy-linux.sh rebuild

# 5. Verify
./scripts/deploy-linux.sh status
```

## Support

For Oracle Linux specific issues:
1. Check `/var/log/messages` for system errors
2. Review Docker logs: `sudo journalctl -u docker`
3. Verify SELinux: `ausearch -m avc -ts recent`

For general issues:
```bash
# Full diagnostic
./scripts/deploy-linux.sh status
docker logs soc360-app
docker logs soc360-nginx