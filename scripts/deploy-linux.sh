#!/bin/bash
#
# Open-Monitor Deployment Script for Linux/Oracle Linux
# Usage: ./scripts/deploy-linux.sh [option] [--with-ollama] [--with-airflow]
# NOTE: Does NOT require root/sudo - runs as regular user in docker group
#
# Flags opcionais:
#   --with-ollama   Adiciona overlay infra/compose/docker-compose.ollama.yml (LLM local)
#   --with-airflow  Adiciona overlay infra/compose/docker-compose.airflow.yml (DAGs Airflow)
#
# CHANGELOG:
#   - Segurança: Permissões 600 em secrets, validação de SECRET_KEY
#   - Robustez: Retry em comandos de rede, backup automático
#   - Usabilidade: Timestamps nos logs, verificação de versão compose
#   - Arquitetura: Ollama e Airflow são overlays opcionais (não default)
#

set -euo pipefail

# ============================================
# CONFIGURATION
# ============================================
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_VERSION="3.2.0"

# Detect if running on Oracle Linux 9
IS_OL9=false
if [ -f /etc/oracle-release ]; then
    if grep -q "Oracle Linux Server release 9" /etc/oracle-release 2>/dev/null; then
        IS_OL9=true
    fi
fi

COMPOSE_DIR="infra/compose"

# Select base compose file
if [ "$IS_OL9" = true ] && [ -f "$PROJECT_ROOT/$COMPOSE_DIR/docker-compose.ol9.yml" ]; then
    BASE_COMPOSE="$COMPOSE_DIR/docker-compose.ol9.yml"
    OL9_MODE=true
elif [ -f "$PROJECT_ROOT/$COMPOSE_DIR/docker-compose.yml" ]; then
    BASE_COMPOSE="$COMPOSE_DIR/docker-compose.yml"
    OL9_MODE=false
else
    echo "ERROR: No docker-compose file found"
    exit 1
fi

# Parse optional overlay flags
WITH_OLLAMA=false
WITH_AIRFLOW=false
NON_INTERACTIVE=false
POSITIONAL_ARGS=()

# CI/CD detection — auto-enable non-interactive
if [ -n "${CI:-}" ] || [ -n "${NON_INTERACTIVE:-}" ] || [ ! -t 0 ]; then
    NON_INTERACTIVE=true
fi

for arg in "$@"; do
    case "$arg" in
        --with-ollama)     WITH_OLLAMA=true ;;
        --with-airflow)    WITH_AIRFLOW=true ;;
        --non-interactive|--yes|-y) NON_INTERACTIVE=true ;;
        *)                 POSITIONAL_ARGS+=("$arg") ;;
    esac
done

# Confirmation helper — auto-yes in non-interactive mode
confirm() {
    local prompt="$1"
    local default="${2:-n}"
    if [ "$NON_INTERACTIVE" = true ]; then
        log_info "$prompt → auto-yes (non-interactive)"
        return 0
    fi
    read -p "$prompt (y/N): " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

# Build compose command with overlays
build_compose_args() {
    local args="--project-directory $PROJECT_ROOT -f $BASE_COMPOSE"
    if [ "$WITH_OLLAMA" = true ] && [ -f "$PROJECT_ROOT/$COMPOSE_DIR/docker-compose.ollama.yml" ]; then
        args="$args -f $COMPOSE_DIR/docker-compose.ollama.yml"
    elif [ "$WITH_OLLAMA" = true ]; then
        log_warn "infra/compose/docker-compose.ollama.yml not found — ignoring --with-ollama"
    fi
    if [ "$WITH_AIRFLOW" = true ] && [ -f "$PROJECT_ROOT/$COMPOSE_DIR/docker-compose.airflow.yml" ]; then
        args="$args -f $COMPOSE_DIR/docker-compose.airflow.yml"
    elif [ "$WITH_AIRFLOW" = true ]; then
        log_warn "infra/compose/docker-compose.airflow.yml not found — ignoring --with-airflow"
    fi
    echo "$args"
}

# Legacy: keep COMPOSE_FILE for simple pass-through functions that use it directly
COMPOSE_FILE="$BASE_COMPOSE"
export COMPOSE_FILE

# Cores (pure bash - no external dependencies)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# ============================================
# FUNCTIONS
# ============================================

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════╗"
    if [ "$OL9_MODE" = true ]; then
        echo "║     Open-Monitor Oracle Linux 9 Deployment    ║"
        echo "║              v3.0.0 (OL9 Optimized)           ║"
    else
        echo "║     Open-Monitor Linux Deployment             ║"
        echo "║              v3.0.0                           ║"
    fi
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RED}[ERROR]${NC} $1"; }

check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker not installed. Install Docker first."
        if [ "$OL9_MODE" = true ]; then
            log_info "Oracle Linux 9: sudo dnf install docker-ce docker-ce-cli containerd.io"
        else
            log_info "General: sudo dnf install docker-ce OR sudo apt install docker.io"
        fi
        exit 1
    fi
    
    # Verificar se Docker daemon está rodando
    if ! docker info &> /dev/null; then
        log_error "Docker daemon not running or permission denied!"
        echo ""
        log_info "Possíveis soluções:"
        echo ""
        echo "  1. INICIAR DOCKER (requer sudo):"
        echo "     sudo systemctl start docker"
        echo "     sudo systemctl enable docker"
        echo ""
        echo "  2. CORRIGIR PERMISSÕES:"
        echo "     sudo usermod -aG docker \$USER"
        echo "     newgrp docker   # ou logout/login"
        echo ""
        echo "  3. EXECUTAR SCRIPT DE CORREÇÃO:"
        echo "     sudo ./scripts/apply-fix.sh"
        echo ""
        echo "  4. VERIFICAR STATUS:"
        echo "     sudo systemctl status docker"
        echo "     sudo journalctl -u docker -n 20"
        echo ""
        
        # Tentar oferecer correção automática
        if [ "$EUID" -eq 0 ]; then
            log_warn "Detectado root. Tentando iniciar Docker..."
            if systemctl start docker 2>/dev/null; then
                log_success "Docker iniciado com sucesso!"
                sleep 2
                if docker info &>/dev/null; then
                    return 0
                fi
            fi
        fi
        
        exit 1
    fi
    
    log_success "Docker is available"
}

check_compose() {
    if command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    elif command -v "docker" &> /dev/null && docker compose version &> /dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    else
        log_error "Docker Compose not installed"
        if [ "$OL9_MODE" = true ]; then
            log_info "Oracle Linux 9: Docker Compose plugin is included with docker-ce"
        fi
        exit 1
    fi
    
    # Verificar versão mínima
    local min_version="2.0.0"
    local current_version=$($COMPOSE_CMD version --short 2>/dev/null | head -1 | sed 's/^v//')
    
    if [ -n "$current_version" ]; then
        if [ "$(printf '%s\n' "$min_version" "$current_version" | sort -V | head -n1)" != "$min_version" ]; then
            log_warn "Docker Compose versão $current_version detectada. Recomendado: >= $min_version"
        else
            log_success "Docker Compose: $COMPOSE_CMD (v$current_version)"
        fi
    else
        log_success "Docker Compose: $COMPOSE_CMD"
    fi
}

check_disk_space() {
    log_info "Verificando espaço em disco..."
    local required_gb=10
    local available_gb=$(df -BG "$PROJECT_ROOT" 2>/dev/null | awk 'NR==2 {print $4}' | tr -d 'G')
    
    if [ -z "$available_gb" ]; then
        log_warn "Não foi possível verificar espaço em disco"
        return 0
    fi
    
    if [ "$available_gb" -lt "$required_gb" ]; then
        log_error "Espaço insuficiente: ${available_gb}GB disponível, ${required_gb}GB necessário"
        log_info "Libere espaço ou use um diretório com mais espaço disponível"
        exit 1
    fi
    
    log_success "Espaço em disco OK: ${available_gb}GB disponível"
}

check_ports() {
    log_info "Verificando portas necessárias..."
    # Core stack: 80 (HTTP) e 443 (HTTPS)
    local ports=(80 443)
    [ "$WITH_OLLAMA"  = true ] && ports+=(11434)
    [ "$WITH_AIRFLOW" = true ] && ports+=(8080)
    local port_in_use=false

    for port in "${ports[@]}"; do
        if command -v ss &> /dev/null && ss -tlnp 2>/dev/null | grep -q ":$port "; then
            log_warn "Porta $port já está em uso"
            port_in_use=true
        elif command -v netstat &> /dev/null && netstat -tlnp 2>/dev/null | grep -q ":$port "; then
            log_warn "Porta $port já está em uso"
            port_in_use=true
        fi
    done

    if [ "$port_in_use" = true ]; then
        log_warn "Algumas portas estão em uso. O deploy pode falhar se não houver mapeamento alternativo."
        if ! confirm "Continuar mesmo assim?"; then
            exit 1
        fi
    else
        log_success "Portas necessárias disponíveis"
    fi
}

check_env_file() {
    if [ ! -f "$PROJECT_ROOT/.env" ]; then
        log_warn ".env not found"
        if [ -f "$PROJECT_ROOT/.env.example" ]; then
            cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env" 2>/dev/null || {
                log_error "Cannot create .env - check permissions"
                exit 1
            }
            log_info ".env created from .env.example"
            log_warn "Edit .env with your production settings before running"
            log_warn "Required: Set SECRET_KEY (generate with: openssl rand -hex 32)"
        fi
    else
        log_success ".env file exists"
    fi
    
    # NOTA: o deploy containerizado lê SECRET_KEY do Docker secret
    # (secrets/secret_key.txt → /run/secrets/secret_key via SECRET_KEY_FILE),
    # NÃO do .env. init_secrets() cuida disso. Aqui só validamos vars de
    # runtime opcionais que realmente vêm do .env.
    if grep -qE '^OPENAI_API_KEY=.+' "$PROJECT_ROOT/.env" 2>/dev/null; then
        log_success "OPENAI_API_KEY configurada (.env) — IA com respostas reais"
    else
        log_info "OPENAI_API_KEY não definida — IA em modo demo (esperado se não usar OpenAI)"
    fi
}

# ============================================
# SECURITY & UTILITY FUNCTIONS
# ============================================

validate_secret_key() {
    local key_file="$1"
    local min_length=64  # 32 bytes hex = 64 chars
    if [ -f "$key_file" ]; then
        local key_length=$(wc -c < "$key_file" | tr -d ' ')
        # Remove newline if present
        key_length=$((key_length - 1))
        if [ "$key_length" -lt "$min_length" ]; then
            log_error "SECRET_KEY muito curta ($key_length bytes). Mínimo: $min_length bytes"
            rm -f "$key_file"
            return 1
        fi
    fi
    return 0
}

secure_secrets() {
    # Proteção em camadas: o diretório fica 700 (só root no host pode listar/abrir
    # os arquivos), mas os ARQUIVOS ficam 644. Motivo: docker compose (não-swarm)
    # faz bind-mount dos secrets em /run/secrets/ preservando dono/modo do host.
    # Os containers app/celery rodam como UID 1000 (openmonitor) e precisam LER
    # /run/secrets/secret_key — com 600 root:root o cat falha ("Permission denied"),
    # SECRET_KEY fica vazio e o container entra em restart loop (unhealthy).
    # O dir 700 mantém a proteção no host; 644 só vale dentro do bind-mount.
    if [ -d "$PROJECT_ROOT/secrets" ]; then
        chmod 700 "$PROJECT_ROOT/secrets" 2>/dev/null || true
        for secret_file in "$PROJECT_ROOT/secrets"/*.txt; do
            if [ -f "$secret_file" ]; then
                chmod 644 "$secret_file" 2>/dev/null || true
            fi
        done
        log_success "Secrets protegidos (dir 700 / arquivos 644 — legíveis pelo container UID 1000)"
    fi
}

retry_command() {
    local max_attempts=3
    local delay=5
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if "$@"; then
            return 0
        fi
        log_warn "Comando falhou (tentativa $attempt/$max_attempts). Retrying in ${delay}s..."
        sleep $delay
        attempt=$((attempt + 1))
        delay=$((delay * 2))
    done
    return 1
}

backup_before_update() {
    local backup_dir="$PROJECT_ROOT/backups/pre-deploy-$(date +%Y%m%d-%H%M%S)"
    log_info "Criando backup em $backup_dir..."
    
    mkdir -p "$backup_dir"
    
    # Backup de arquivos críticos
    cp "$PROJECT_ROOT/.env" "$backup_dir/" 2>/dev/null || true
    cp -r "$PROJECT_ROOT/secrets" "$backup_dir/" 2>/dev/null || true
    
    # Backup do docker-compose atual
    cp "$PROJECT_ROOT/$COMPOSE_FILE" "$backup_dir/$(basename "$COMPOSE_FILE")" 2>/dev/null || true
    
    # Criar symlink para latest
    rm -f "$PROJECT_ROOT/backups/latest"
    ln -s "$backup_dir" "$PROJECT_ROOT/backups/latest" 2>/dev/null || true
    
    log_success "Backup criado em $backup_dir"
    echo "$backup_dir" > "$PROJECT_ROOT/backups/.last_backup"
}

rollback() {
    local backup_dir="$PROJECT_ROOT/backups/latest"
    if [ ! -d "$backup_dir" ]; then
        log_error "Nenhum backup encontrado para rollback"
        log_info "Diretórios de backup disponíveis:"
        ls -la "$PROJECT_ROOT/backups/" 2>/dev/null || echo "  (nenhum backup encontrado)"
        exit 1
    fi
    
    log_warn "Executando rollback para: $backup_dir"
    log_info "Esta operação irá restaurar configurações anteriores e reiniciar os serviços."
    
    # Confirmação do usuário (skip em non-interactive)
    if [ "$NON_INTERACTIVE" != true ]; then
        read -p "Digite 'yes' para confirmar o rollback: " confirm_input
        if [ "$confirm_input" != "yes" ]; then
            log_info "Rollback cancelado pelo usuário"
            exit 0
        fi
    else
        log_info "Non-interactive: prosseguindo com rollback"
    fi
    
    log_info "Parando serviços atuais..."
    stop_services
    
    log_info "Restaurando arquivos de configuração..."
    if [ -f "$backup_dir/.env" ]; then
        cp "$backup_dir/.env" "$PROJECT_ROOT/" && log_success ".env restaurado" || log_warn "Falha ao restaurar .env"
    fi
    
    if [ -d "$backup_dir/secrets" ]; then
        cp -r "$backup_dir/secrets" "$PROJECT_ROOT/" && log_success "secrets restaurados" || log_warn "Falha ao restaurar secrets"
    fi
    
    # Restaurar compose file se existir
    if [ -f "$backup_dir/$(basename "$COMPOSE_FILE")" ]; then
        mkdir -p "$PROJECT_ROOT/$(dirname "$COMPOSE_FILE")"
        cp "$backup_dir/$(basename "$COMPOSE_FILE")" "$PROJECT_ROOT/$COMPOSE_FILE" && log_success "$COMPOSE_FILE restaurado" || log_warn "Falha ao restaurar compose"
    fi
    
    log_info "Reiniciando serviços..."
    start_services
    log_success "Rollback concluído"
}

configure_selinux() {
    if [ "$IS_OL9" != true ]; then
        return 0
    fi

    if ! command -v getenforce &> /dev/null || [ "$(getenforce)" = "Disabled" ]; then
        return 0
    fi

    log_info "SELinux detectado ($(getenforce)), configurando contextos..."

    # semanage/restorecon vêm de policycoreutils-python-utils — não estão no OL9 minimal.
    # Sem eles, os bind-mounts ficam sem container_file_t e os containers NÃO conseguem ler.
    if ! command -v semanage &> /dev/null || ! command -v restorecon &> /dev/null; then
        log_error "SELinux está ENFORCING mas 'semanage'/'restorecon' não estão instalados."
        log_error "Os containers NÃO conseguirão acessar os volumes bind-mount."
        log_info  "Instale: sudo dnf install -y policycoreutils-python-utils"
        log_info  "Ou desabilite temporariamente: sudo setenforce 0 (NÃO recomendado em prod)"
        if ! confirm "Continuar mesmo assim (containers podem falhar)?"; then
            exit 1
        fi
        return 0
    fi

    # Persistent context for secrets/
    sudo semanage fcontext -a -t container_file_t "$PROJECT_ROOT/secrets(/.*)?" 2>/dev/null || true

    # Persistent context for ALL bind-mounted directories used by containers
    local bind_dirs=(logs uploads reports instance data)
    for d in "${bind_dirs[@]}"; do
        if [ -d "$PROJECT_ROOT/$d" ]; then
            sudo semanage fcontext -a -t container_file_t "$PROJECT_ROOT/$d(/.*)?" 2>/dev/null || true
        fi
    done

    # Apply contexts now
    sudo restorecon -Rv "$PROJECT_ROOT/secrets" "$PROJECT_ROOT/logs" "$PROJECT_ROOT/uploads" \
        "$PROJECT_ROOT/reports" "$PROJECT_ROOT/instance" "$PROJECT_ROOT/data" 2>/dev/null | tail -3 || true

    log_success "SELinux contextos configurados (container_file_t)"
}

configure_firewalld() {
    if [ "$IS_OL9" != true ]; then
        return 0
    fi
    
    if systemctl is-active firewalld &>/dev/null; then
        log_info "Configurando firewalld..."
        sudo firewall-cmd --permanent --add-service=http 2>/dev/null || true
        sudo firewall-cmd --permanent --add-service=https 2>/dev/null || true
        sudo firewall-cmd --reload 2>/dev/null || true
        log_success "FirewallD configurado (HTTP/HTTPS liberados)"
    fi
}

init_secrets() {
    log_info "Initializing secrets..."
    
    if [ ! -d "$PROJECT_ROOT/secrets" ]; then
        mkdir -p "$PROJECT_ROOT/secrets" 2>/dev/null || {
            log_error "Cannot create secrets directory"
            exit 1
        }
    fi
    
    # Generate secret_key.txt if not exists
    if [ ! -f "$PROJECT_ROOT/secrets/secret_key.txt" ]; then
        log_info "Generating secret_key.txt..."
        if command -v openssl &> /dev/null; then
            openssl rand -hex 32 > "$PROJECT_ROOT/secrets/secret_key.txt"
        else
            # Fallback using /dev/urandom
            head -c 64 /dev/urandom | xxd -p -c 64 > "$PROJECT_ROOT/secrets/secret_key.txt" 2>/dev/null || \
            head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$PROJECT_ROOT/secrets/secret_key.txt"
        fi
        
        # Validar e proteger
        validate_secret_key "$PROJECT_ROOT/secrets/secret_key.txt" || exit 1
        log_success "Generated secret_key.txt"
    else
        log_success "secret_key.txt already exists"
    fi
    
    # Generate redis_password.txt if not exists
    if [ ! -f "$PROJECT_ROOT/secrets/redis_password.txt" ]; then
        log_info "Generating redis_password.txt..."
        if command -v openssl &> /dev/null; then
            openssl rand -hex 24 > "$PROJECT_ROOT/secrets/redis_password.txt"
        else
            head -c 48 /dev/urandom | xxd -p -c 48 > "$PROJECT_ROOT/secrets/redis_password.txt" 2>/dev/null || \
            head -c 48 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$PROJECT_ROOT/secrets/redis_password.txt"
        fi
        log_success "Generated redis_password.txt"
    else
        log_success "redis_password.txt already exists"
    fi
    
    # Aplicar permissões restritas
    secure_secrets
}

build_container() {
    log_info "Building Docker images (this may take a while)..."
    log_info "Using compose file: $COMPOSE_FILE"
    
    if [ "$OL9_MODE" = true ]; then
        log_info "Oracle Linux 9 mode - Building with OL9 Dockerfiles"
    fi
    
    # Detectar CPUs disponíveis para paralelismo
    local cpus=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "2")
    local parallel_jobs=$((cpus / 2))
    [ "$parallel_jobs" -lt 1 ] && parallel_jobs=1
    log_info "Usando $parallel_jobs jobs paralelos (detectado $cpus CPUs)"
    
    log_info "Starting build at $(date '+%H:%M:%S')..."
    local start_time=$(date +%s)

    # Build com tratamento de erro melhorado
    local build_log="/tmp/docker-build-$$.log"
    local compose_args
    compose_args=$(build_compose_args)

    log_info "Executando build (pode levar vários minutos)..."

    # Captura o exit code REAL do docker build (PIPESTATUS[0]), não o do 'tee'
    # nem o da negação do 'if'. set +e temporário para não abortar via set -e.
    set +e
    $COMPOSE_CMD $compose_args build --parallel 2>&1 | tee "$build_log"
    local exit_code=${PIPESTATUS[0]}
    set -e

    if [ "$exit_code" -ne 0 ]; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        local minutes=$((duration / 60))
        local seconds=$((duration % 60))
        
        log_error "Build failed with exit code $exit_code after ${minutes}m ${seconds}s"

        # Mostrar últimos erros do log
        if [ -f "$build_log" ]; then
            log_error "Últimos erros do build:"
            tail -50 "$build_log" | grep -i "error\|failed\|cannot\|no match\|unable to find" | tail -8 || tail -10 "$build_log"

            # Diagnóstico específico para erros conhecidos do OL9
            if grep -qi "no match for argument.*\(liberation-fonts\|dejavu-fonts-ttf\)" "$build_log" 2>/dev/null; then
                echo ""
                log_error "ERRO CONHECIDO OL9: pacotes 'liberation-fonts' / 'dejavu-fonts-ttf' não existem no Oracle Linux 9."
                log_info "Estes são nomes Debian. Os corretos no OL9 são:"
                log_info "  liberation-sans-fonts, dejavu-sans-fonts, etc."
                log_info "Atualize seu Dockerfile.ol9 ou puxe o fix mais recente do repositório."
            elif grep -qi "no match for argument.*python3.11" "$build_log" 2>/dev/null; then
                echo ""
                log_error "ERRO CONHECIDO OL9: python3.11 não disponível."
                log_info "Verifique se ol9_appstream está habilitado: sudo dnf repolist"
                log_info "Habilitar: sudo dnf config-manager --enable ol9_appstream"
            elif grep -qi "no match for argument" "$build_log" 2>/dev/null; then
                echo ""
                log_error "ERRO: pacote inexistente no microdnf. Veja o nome no log acima."
                log_info "Consulte: docker run --rm oraclelinux:9 microdnf repoquery <pacote>"
            elif grep -qi "could not resolve host\|temporary failure in name resolution" "$build_log" 2>/dev/null; then
                echo ""
                log_error "ERRO DE REDE: container não consegue resolver DNS."
                log_info "Verificar /etc/docker/daemon.json (dns: [\"8.8.8.8\"]) e reiniciar Docker."
            fi
            rm -f "$build_log"
        fi

        echo ""
        log_info "Sugestões gerais:"
        echo "  1. Docker daemon rodando: sudo systemctl status docker"
        echo "  2. Limpar cache: docker system prune -af"
        echo "  3. Build sem cache: $COMPOSE_CMD $compose_args build --no-cache"
        echo "  4. Verificar requirements.txt: cat requirements.txt | grep -v '^#'"
        echo "  5. Doctor: $0 doctor"
        echo ""

        exit 1
    fi
    
    rm -f "$build_log"
    
    # Calcular tempo decorrido
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    
    log_success "Build completed in ${minutes}m ${seconds}s"
}

start_services() {
    log_info "Starting services..."
    local compose_args
    compose_args=$(build_compose_args)
    $COMPOSE_CMD $compose_args up -d

    log_info "Waiting for services to be healthy..."
    sleep 15

    local max_wait=180
    local count=0
    while [ $count -lt $max_wait ]; do
        local status_output
        status_output=$($COMPOSE_CMD $compose_args ps 2>/dev/null) || true

        if echo "$status_output" | grep -q "healthy"; then
            log_success "All services are healthy"
            return 0
        elif echo "$status_output" | grep -q "Up"; then
            log_info "Services starting... (${count}s)"
        fi

        sleep 5
        count=$((count + 5))
    done

    log_warn "Some services may still be starting. Check with: $0 status"
}

verify_deployment() {
    log_info "Verifying deployment..."
    local compose_args
    compose_args=$(build_compose_args)
    local failed=0

    # ----- 1. All expected containers exist and are running -----
    local expected_containers=(soc360-nginx soc360-app soc360-celery-worker soc360-celery-beat soc360-redis)
    [ "$WITH_OLLAMA"  = true ] && expected_containers+=(soc360-ollama)
    [ "$WITH_AIRFLOW" = true ] && expected_containers+=(soc360-airflow-webserver soc360-airflow-scheduler)

    for c in "${expected_containers[@]}"; do
        if docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
            local status
            status=$(docker inspect -f '{{.State.Health.Status}}' "$c" 2>/dev/null || echo "no-healthcheck")
            case "$status" in
                healthy|no-healthcheck) log_success "Container $c: running ($status)" ;;
                starting)               log_warn   "Container $c: still starting" ;;
                unhealthy)              log_error  "Container $c: UNHEALTHY"; failed=1 ;;
            esac
        else
            log_error "Container $c: NOT RUNNING"
            failed=1
        fi
    done

    # ----- 2. HTTPS endpoint reachable (app servido apenas via TLS) -----
    local http_port="${HTTP_PORT:-80}"
    local https_port="${HTTPS_PORT:-443}"
    local max_attempts=12 attempt=1
    local https_ok=false
    while [ $attempt -le $max_attempts ]; do
        local https_code
        https_code=$(curl -sk -o /dev/null -w "%{http_code}" "https://localhost:${https_port}/health" 2>/dev/null || echo "000")
        case "$https_code" in
            200|301|302)
                log_success "HTTPS endpoint OK: https://localhost:${https_port}/health → ${https_code}"
                https_ok=true
                break
                ;;
            *)
                log_info "Waiting for endpoint ($attempt/$max_attempts, got HTTPS $https_code)..."
                sleep 5
                attempt=$((attempt + 1))
                ;;
        esac
    done
    if [ "$https_ok" = false ]; then
        log_error "HTTPS endpoint não respondeu após $((max_attempts * 5))s"
        failed=1
    fi

    # ----- 2b. HTTP deve redirecionar para HTTPS (301) -----
    local redir_code
    redir_code=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${http_port}/" 2>/dev/null || echo "000")
    if [ "$redir_code" = "301" ] || [ "$redir_code" = "308" ]; then
        log_success "HTTP redireciona para HTTPS (HTTP $redir_code)"
    else
        log_warn "HTTP / não retornou redirect 301 (got $redir_code) — verifique nginx"
    fi

    # ----- 3. App-internal sanity checks (catches missing libs) -----
    if docker exec soc360-app python -c "from weasyprint import HTML; import markdown; import pydyf" 2>/dev/null; then
        log_success "PDF libs OK (weasyprint + markdown + pydyf)"
    else
        log_error "PDF libs MISSING — reports won't generate. Run: $0 rebuild"
        failed=1
    fi

    # ----- 4. Redis reachable from app (usa lib redis do Python, que ESTÁ na imagem) -----
    # NOTA: `docker exec` NÃO executa o entrypoint.sh, então REDIS_PASSWORD
    # (exportado lá a partir de REDIS_PASSWORD_FILE) não existe neste processo.
    # Espelhamos a lógica do entrypoint: ler o secret file como fallback.
    if docker exec soc360-app python -c "
import os, sys
try:
    import redis
    pw = os.environ.get('REDIS_PASSWORD')
    if not pw:
        pw_file = os.environ.get('REDIS_PASSWORD_FILE')
        if pw_file and os.path.isfile(pw_file):
            with open(pw_file) as f:
                pw = f.read().strip()
    r = redis.Redis(host=os.environ.get('REDIS_HOST','redis'),
                     port=int(os.environ.get('REDIS_PORT','6379')),
                     password=pw or None,
                     socket_connect_timeout=5)
    sys.exit(0 if r.ping() else 1)
except Exception as e:
    print(e, file=sys.stderr); sys.exit(1)
" 2>/dev/null; then
        log_success "Redis reachable from app"
    else
        log_error "Redis NÃO acessível pelo app — verifique senha/secret e container redis"
        failed=1
    fi

    # ----- 5. DB writable -----
    if docker exec soc360-app sh -c 'test -w /app/instance' 2>/dev/null; then
        log_success "/app/instance is writable by app user"
    else
        log_error "/app/instance NOT writable — fix permissions: sudo chown -R 1000:1000 instance/"
        failed=1
    fi

    if [ $failed -eq 0 ]; then
        log_success "Deployment verification: ALL CHECKS PASSED"
        return 0
    else
        log_error "Deployment verification: SOME CHECKS FAILED — see above"
        return 1
    fi
}

doctor() {
    log_info "Running diagnostics..."
    echo ""

    # System info
    echo -e "${BOLD}=== SYSTEM ===${NC}"
    echo "  OS: $(uname -s -r)"
    [ -f /etc/os-release ] && echo "  Distro: $(. /etc/os-release && echo "$PRETTY_NAME")"
    echo "  User UID: $(id -u) (container expects UID 1000)"
    echo "  Docker: $(docker --version 2>/dev/null || echo 'NOT INSTALLED')"
    echo "  Compose: $($COMPOSE_CMD version --short 2>/dev/null || echo 'NOT INSTALLED')"
    command -v getenforce &>/dev/null && echo "  SELinux: $(getenforce)"
    echo ""

    # Files & dirs
    echo -e "${BOLD}=== FILES ===${NC}"
    for f in .env secrets/secret_key.txt secrets/redis_password.txt; do
        if [ -f "$PROJECT_ROOT/$f" ]; then
            local perms=$(stat -c '%a' "$PROJECT_ROOT/$f" 2>/dev/null || stat -f '%Mp%Lp' "$PROJECT_ROOT/$f" 2>/dev/null)
            echo "  ✓ $f (perms: $perms)"
        else
            echo "  ✗ $f MISSING"
        fi
    done
    echo ""

    # Bind dirs ownership
    echo -e "${BOLD}=== BIND-MOUNT DIRS ===${NC}"
    for d in logs uploads reports instance data/redis; do
        if [ -d "$PROJECT_ROOT/$d" ]; then
            local own=$(stat -c '%u:%g' "$PROJECT_ROOT/$d" 2>/dev/null || stat -f '%u:%g' "$PROJECT_ROOT/$d" 2>/dev/null)
            local expected="1000:1000"
            [ "$d" = "data/redis" ] && expected="999:999"
            if [ "$own" = "$expected" ]; then
                echo "  ✓ $d ($own)"
            else
                echo "  ⚠ $d owner=$own (expected $expected) — run: sudo chown -R $expected $PROJECT_ROOT/$d"
            fi
        else
            echo "  ✗ $d MISSING"
        fi
    done
    echo ""

    # Containers
    echo -e "${BOLD}=== CONTAINERS ===${NC}"
    docker ps -a --filter "name=soc360-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "  (Docker not running)"
    echo ""

    # Run full verification
    echo -e "${BOLD}=== VERIFICATION ===${NC}"
    verify_deployment || true
}

stop_services() {
    log_info "Stopping services..."
    local compose_args
    compose_args=$(build_compose_args)
    $COMPOSE_CMD $compose_args down
    log_success "Services stopped"
}

show_status() {
    echo ""
    print_banner
    echo ""
    local compose_args
    compose_args=$(build_compose_args)
    $COMPOSE_CMD $compose_args ps
    echo ""
    echo -e "${BOLD}Services:${NC}"
    echo "  App:    https://localhost  (HTTP redireciona para HTTPS)"
    [ "$WITH_AIRFLOW" = true ] && echo "  Airflow: http://localhost:${AIRFLOW_PORT:-8080}"
    if [ "$WITH_OLLAMA" = true ]; then
        if [ "$OL9_MODE" = true ]; then
            echo "  Ollama:  http://localhost:${OLLAMA_PORT:-11434} (OL9 CPU-AVX2)"
        else
            echo "  Ollama:  http://localhost:${OLLAMA_PORT:-11434}"
        fi
    fi
    echo ""
    echo -e "${BOLD}Useful commands:${NC}"
    echo "  $0 logs           - View app logs"
    echo "  $0 logs nginx     - View nginx logs"
    echo "  $0 status         - Show status"
    echo ""
}

show_logs() {
    local service="${1:-app}"
    local compose_args
    compose_args=$(build_compose_args)
    $COMPOSE_CMD $compose_args logs -f "$service"
}

setup_directories() {
    log_info "Setting up directories..."

    # Core directories (always required for bind-mount volumes on OL9)
    local core_dirs=(
        "logs"
        "uploads"
        "reports"
        "instance"
        "data/redis"
        "backups"
    )

    # Optional service directories
    [ "$WITH_OLLAMA"  = true ] && core_dirs+=("data/ollama")
    [ "$WITH_AIRFLOW" = true ] && core_dirs+=("data/airflow" "data/airflow/logs")

    for dir in "${core_dirs[@]}"; do
        if [ ! -d "$PROJECT_ROOT/$dir" ]; then
            mkdir -p "$PROJECT_ROOT/$dir" 2>/dev/null || {
                log_warn "Cannot create $dir - will use Docker volumes"
            }
        fi
    done
    
    # Ensure nginx directories exist
    for dir in infra/docker/nginx/ssl infra/docker/nginx/html; do
        if [ ! -d "$PROJECT_ROOT/$dir" ]; then
            mkdir -p "$PROJECT_ROOT/$dir" 2>/dev/null || true
        fi
    done
    
    # Set appropriate permissions for non-root containers (UID 1000 = openmonitor)
    log_info "Setting permissions for rootless containers (UID 1000)..."

    # Detect if current user can chown to UID 1000 without sudo
    local need_sudo=false
    local current_uid
    current_uid=$(id -u)
    if [ "$current_uid" -ne 1000 ] && [ "$current_uid" -ne 0 ]; then
        need_sudo=true
        log_info "Current UID=$current_uid != 1000 — will use sudo for chown"
    fi

    # App directories must be writable by container's UID 1000
    for dir in logs uploads reports instance; do
        local target="$PROJECT_ROOT/$dir"
        if [ -d "$target" ]; then
            chmod 755 "$target" 2>/dev/null || true
            if [ "$need_sudo" = true ]; then
                sudo chown -R 1000:1000 "$target" 2>/dev/null || \
                    log_warn "Cannot chown $dir to UID 1000 — container may fail to write"
            else
                chown -R 1000:1000 "$target" 2>/dev/null || true
            fi
        fi
    done

    # Redis data dir (Redis runs as UID 999 inside the official alpine image)
    if [ -d "$PROJECT_ROOT/data/redis" ]; then
        if [ "$need_sudo" = true ]; then
            sudo chown -R 999:999 "$PROJECT_ROOT/data/redis" 2>/dev/null || true
        else
            chown -R 999:999 "$PROJECT_ROOT/data/redis" 2>/dev/null || true
        fi
    fi

    # Other service data dirs (Ollama runs as root inside container)
    chmod -R 755 "$PROJECT_ROOT/data" 2>/dev/null || true

    log_success "Directories ready"
}

update_images() {
    log_info "Pulling latest base images..."
    backup_before_update
    local compose_args
    compose_args=$(build_compose_args)
    retry_command $COMPOSE_CMD $compose_args pull
    log_success "Base images updated. Run '$0 rebuild' to rebuild containers."
}

# ============================================
# MAIN
# ============================================

main() {
    # Acesso seguro a array possivelmente vazio sob 'set -u' (compat. bash <4.4)
    local command="start"
    [ "${#POSITIONAL_ARGS[@]}" -gt 0 ] && command="${POSITIONAL_ARGS[0]}"

    cd "$PROJECT_ROOT"
    print_banner

    # Docker/Compose são necessários para QUALQUER comando
    check_docker
    check_compose

    # Preflight pesado (secrets, chown via sudo, SELinux, firewalld) só faz
    # sentido para comandos que (re)criam a stack. Comandos somente-leitura
    # ou de parada NÃO devem mutar permissões/firewall do host.
    case "$command" in
        start|restart|rebuild|update|rollback)
            [ "$WITH_OLLAMA"  = true ] && log_info "Overlay: Ollama habilitado"
            [ "$WITH_AIRFLOW" = true ] && log_info "Overlay: Airflow habilitado"
            check_disk_space
            check_ports
            check_env_file
            init_secrets
            setup_directories
            configure_selinux
            configure_firewalld
            ;;
        *)
            # stop|logs|status|clean|init|doctor|verify — sem mutações no host
            ;;
    esac

    local compose_args
    compose_args=$(build_compose_args)

    case "$command" in
        start)
            build_container
            start_services
            verify_deployment || log_warn "Deploy completed with warnings"
            show_status
            ;;
        stop)
            stop_services
            ;;
        restart)
            stop_services
            sleep 2
            start_services
            verify_deployment || log_warn "Restart completed with warnings"
            show_status
            ;;
        rebuild)
            log_info "Rebuilding without cache..."
            $COMPOSE_CMD $compose_args build --no-cache
            start_services
            verify_deployment || log_warn "Rebuild completed with warnings"
            show_status
            ;;
        logs)
            local log_svc="app"
            [ "${#POSITIONAL_ARGS[@]}" -gt 1 ] && log_svc="${POSITIONAL_ARGS[1]}"
            show_logs "$log_svc"
            ;;
        status)
            show_status
            ;;
        clean)
            log_info "Cleaning up..."
            $COMPOSE_CMD $compose_args down -v 2>/dev/null || true

            if [ -d "$PROJECT_ROOT/backups" ] && [ "$(ls -A "$PROJECT_ROOT/backups" 2>/dev/null)" ]; then
                if confirm "Remover backups também?"; then
                    rm -rf "$PROJECT_ROOT/backups"/* 2>/dev/null || true
                    log_info "Backups removidos"
                fi
            fi

            if confirm "Remover imagens Docker não utilizadas?"; then
                docker system prune -f --volumes 2>/dev/null || true
                log_info "Imagens não utilizadas removidas"
            fi

            log_success "Cleanup complete"
            ;;
        update)
            update_images
            ;;
        rollback)
            rollback
            ;;
        init)
            log_info "Initializing permissions..."
            if groups | grep -q docker; then
                log_success "User is in docker group"
            else
                log_warn "User not in docker group"
                log_info "Run: sudo usermod -aG docker \$USER"
            fi
            log_success "Init complete"
            ;;
        doctor|diagnose|health)
            doctor
            ;;
        verify)
            verify_deployment
            ;;
        *)
            echo "Usage: $0 {start|stop|restart|rebuild|logs|status|clean|update|init|rollback|doctor|verify} [--with-ollama] [--with-airflow]"
            echo ""
            echo "Commands:"
            echo "  start     - Build and start all services"
            echo "  stop      - Stop all services"
            echo "  restart   - Restart all services"
            echo "  rebuild   - Rebuild images (no cache)"
            echo "  logs      - Show logs (optional: service name)"
            echo "  status    - Show service status"
            echo "  clean     - Stop and remove volumes"
            echo "  update    - Pull latest base images (with backup)"
            echo "  rollback  - Rollback to last backup"
            echo "  init      - Check docker group permissions"
            echo "  doctor    - Diagnose deployment (system, files, containers, health)"
            echo "  verify    - Run full deployment verification checks"
            echo ""
            echo "Optional overlays:"
            echo "  --with-ollama       Add Ollama local LLM (requires infra/compose/docker-compose.ollama.yml)"
            echo "  --with-airflow      Add Airflow DAG scheduler (requires infra/compose/docker-compose.airflow.yml)"
            echo ""
            echo "Modifiers:"
            echo "  --non-interactive   Skip all confirmation prompts (alias: --yes, -y)"
            echo "                      Auto-enabled when CI env var is set or stdin is not a TTY"
            echo ""
            echo "Environment variables:"
            echo "  ADMIN_INITIAL_PASSWORD  Set admin password on first deploy (auto-generated if unset)"
            echo "  ADMIN_EMAIL             Admin email (default: admin@soc360.local)"
            echo "  HTTP_PORT / HTTPS_PORT  Override default 80/443"
            exit 1
            ;;
    esac
}

main "$@"