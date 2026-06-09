#!/bin/sh
# Open-Monitor v3.0 - Docker Entrypoint Script (Simplified for Windows)
# Handles database initialization, migrations, and application startup

set -e

# Configuration
APP_HOME="${APP_HOME:-/app}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"

# Simple logging
log_info() {
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_success() {
    echo "[OK] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Load SECRET_KEY from file if provided, otherwise use environment variable.
# IMPORTANTE: verificar se o conteúdo foi REALMENTE lido. Se o arquivo existe
# mas não é legível pelo usuário do container (ex.: secret 600 root:root e
# container roda como UID 1000), o cat falha e SECRET_KEY fica vazio — não
# basta checar [ -f ]. Falhar aqui com a causa real evita "SECRET_KEY too short"
# enganoso e o restart loop silencioso.
if [ -n "$SECRET_KEY_FILE" ] && [ -f "$SECRET_KEY_FILE" ]; then
    if [ ! -r "$SECRET_KEY_FILE" ]; then
        log_error "SECRET_KEY_FILE existe mas não é legível: $SECRET_KEY_FILE"
        log_error "Permissão do secret no host impede leitura pelo UID $(id -u). Use 'chmod 644 secrets/*.txt'."
        exit 1
    fi
    export SECRET_KEY=$(cat "$SECRET_KEY_FILE")
    if [ -z "$SECRET_KEY" ]; then
        log_error "SECRET_KEY_FILE legível porém vazio ou cat falhou: $SECRET_KEY_FILE"
        exit 1
    fi
    log_success "SECRET_KEY loaded from file"
elif [ -z "$SECRET_KEY" ]; then
    log_error "SECRET_KEY not provided (use SECRET_KEY or SECRET_KEY_FILE)"
    exit 1
fi

# Load REDIS_PASSWORD from file if provided
if [ -n "$REDIS_PASSWORD_FILE" ] && [ -f "$REDIS_PASSWORD_FILE" ]; then
    if [ ! -r "$REDIS_PASSWORD_FILE" ]; then
        log_error "REDIS_PASSWORD_FILE existe mas não é legível: $REDIS_PASSWORD_FILE (verifique permissão do secret)"
        exit 1
    fi
    export REDIS_PASSWORD=$(cat "$REDIS_PASSWORD_FILE")
    log_success "REDIS_PASSWORD loaded from file"
fi

# Load POSTGRES_PASSWORD from file if provided
if [ -n "$POSTGRES_PASSWORD_FILE" ] && [ -f "$POSTGRES_PASSWORD_FILE" ]; then
    export POSTGRES_PASSWORD=$(cat "$POSTGRES_PASSWORD_FILE")
    log_success "POSTGRES_PASSWORD loaded from file"
fi

# Validate SECRET_KEY length
if [ ${#SECRET_KEY} -lt 32 ]; then
    log_error "SECRET_KEY too short (minimum 32 characters)"
    exit 1
fi

# -------------------------------------------------------------------------
# Database configuration
# PostgreSQL é o backend padrão no container. SQLite SÓ é usado quando nenhum
# host Postgres está configurado (DB_CORE_HOST vazio = modo local).
# -------------------------------------------------------------------------
if [ -n "$DB_CORE_HOST" ]; then
    # Propaga a senha do Postgres (secret) para as variáveis que o app consome
    if [ -n "$POSTGRES_PASSWORD" ]; then
        export DB_CORE_PASSWORD="${DB_CORE_PASSWORD:-$POSTGRES_PASSWORD}"
        export DB_PUBLIC_PASSWORD="${DB_PUBLIC_PASSWORD:-$POSTGRES_PASSWORD}"
    fi
    # Monta DATABASE_URL — usada na detecção de tipos (força JSONB/INET/GIN)
    if [ -z "$DATABASE_URL" ]; then
        export DATABASE_URL="postgresql://${DB_CORE_USER}:${DB_CORE_PASSWORD}@${DB_CORE_HOST}:${DB_CORE_PORT:-5432}/${DB_CORE_NAME}"
    fi
    log_info "Using PostgreSQL at ${DB_CORE_HOST}:${DB_CORE_PORT:-5432}/${DB_CORE_NAME}"

    # Espera ativa pelo Postgres antes de prosseguir (todos os papéis)
    log_info "Waiting for PostgreSQL to become available..."
    python - <<'PYWAIT'
import os, sys, time
import psycopg2
params = dict(
    host=os.environ.get('DB_CORE_HOST'),
    port=int(os.environ.get('DB_CORE_PORT', '5432')),
    dbname=os.environ.get('DB_CORE_NAME', 'soc360'),
    user=os.environ.get('DB_CORE_USER', 'soc360'),
    password=os.environ.get('DB_CORE_PASSWORD', ''),
    connect_timeout=3,
)
for attempt in range(1, 61):
    try:
        psycopg2.connect(**params).close()
        print(f"[OK] PostgreSQL reachable after {attempt} attempt(s)")
        sys.exit(0)
    except Exception as exc:
        print(f"[wait] {attempt}/60 PostgreSQL not ready: {exc.__class__.__name__}")
        time.sleep(2)
print("[ERROR] PostgreSQL not reachable after 120s timeout")
sys.exit(1)
PYWAIT
    if [ $? -ne 0 ]; then
        log_error "PostgreSQL indisponível — abortando. SQLite só é permitido em modo local."
        exit 1
    fi
    log_success "PostgreSQL is available"
elif [ -z "$DATABASE_URL" ]; then
    # Modo local sem Postgres configurado → SQLite
    export DATABASE_URL="sqlite:///app/instance/app.db"
    log_info "No PostgreSQL host configured — using local SQLite database"
fi

log_success "Environment validation passed"

# Ensure writable directories (Docker volumes may be mounted as root)
for dir in "${APP_HOME}/logs" "${APP_HOME}/uploads" "${APP_HOME}/reports" "${APP_HOME}/instance"; do
    mkdir -p "$dir" 2>/dev/null || true
    chmod 775 "$dir" 2>/dev/null || true
done

# -------------------------------------------------------------------------
# Sync static files from image seed into the soc360-static volume.
# This ensures every image rebuild propagates CSS/JS/template updates
# without requiring a manual `docker volume rm`.
# Uses find+cp per-file so a single unwritable file never aborts startup.
# -------------------------------------------------------------------------
STATIC_SEED="${APP_HOME}/app/static_seed"
STATIC_DIR="${APP_HOME}/app/static"
if [ -d "$STATIC_SEED" ]; then
    log_info "Syncing static files from image seed..."

    # Recreate directory tree
    find "$STATIC_SEED" -mindepth 1 -type d | while read -r src_dir; do
        dst_dir="${STATIC_DIR}${src_dir#$STATIC_SEED}"
        mkdir -p "$dst_dir" 2>/dev/null || true
    done

    # Copy each file individually — permission errors on pre-existing files
    # are non-fatal; the file already has the correct content from a prior run.
    COPIED=0; SKIPPED=0
    find "$STATIC_SEED" -type f | while read -r src_file; do
        dst_file="${STATIC_DIR}${src_file#$STATIC_SEED}"
        if cp -p "$src_file" "$dst_file" 2>/dev/null; then
            COPIED=$((COPIED + 1))
        else
            # Fallback: try without preserving ownership (only preserve mode)
            if cp "$src_file" "$dst_file" 2>/dev/null; then
                COPIED=$((COPIED + 1))
            else
                SKIPPED=$((SKIPPED + 1))
                log_info "Skipped (already up-to-date): ${dst_file##*/app/static/}"
            fi
        fi
    done

    FILE_COUNT=$(find "$STATIC_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')
    log_success "Static files synced (${FILE_COUNT} files in volume)"
else
    log_info "No static seed found — skipping sync (${STATIC_DIR} used as-is)"
fi

# -------------------------------------------------------------------------
# Database migrations (only on web/app container, not Celery workers).
# Detect role: if first arg contains "gunicorn" → app container.
# Workers/beat skip migrations (app already applied them).
# -------------------------------------------------------------------------
case "$1" in
    gunicorn|flask)
        if [ -d "${APP_HOME}/migrations" ]; then
            log_info "Running database migrations..."
            cd "${APP_HOME}" && flask db upgrade 2>&1 | tail -20 || \
                log_error "Migration failed (continuing — DB may already be current)"
            log_success "Migrations applied"
        fi

        # Bootstrap admin user on first run (idempotent)
        if [ -f "${APP_HOME}/scripts/bootstrap_admin.py" ]; then
            log_info "Bootstrapping admin user (idempotent)..."
            cd "${APP_HOME}" && python scripts/bootstrap_admin.py 2>&1 | tail -5 || \
                log_info "Admin bootstrap skipped or already exists"
        fi
        ;;
    *)
        log_info "Skipping migrations (role: $1)"
        ;;
esac

log_info "Starting application..."

# Execute the main command
exec "$@"