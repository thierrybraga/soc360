#!/bin/bash
# entrypoint.sh - Inicialização do Ollama
# Modelo deve ser baixado manualmente ou pré-carregado via volume

set -e

echo "=============================================="
echo "Ollama Starting - CPU Mode"
echo "=============================================="

# Detectar núcleos CPU disponíveis
CORES=$(nproc --all 2>/dev/null || echo 4)
OPTIMAL_THREADS=$(( CORES * 3 / 4 ))
[ "$OPTIMAL_THREADS" -lt 1 ] && OPTIMAL_THREADS=1
export OLLAMA_NUM_THREADS=${OLLAMA_NUM_THREADS:-$OPTIMAL_THREADS}

echo "CPU cores available: $CORES"
echo "Threads configured: $OLLAMA_NUM_THREADS"

# Criar diretório de modelos (usuário não-root)
MODELS_DIR="${HOME}/.ollama/models"
mkdir -p "$MODELS_DIR"
echo "Models directory: $MODELS_DIR"

# Validar se Ollama está instalado
if ! command -v ollama &> /dev/null; then
    echo "ERROR: Ollama not found in PATH"
    exit 1
fi

echo "Ollama version: $(ollama --version 2>&1 | head -1)"
echo "Running as user: $(whoami)"
echo "Home directory: $HOME"

# Iniciar Ollama em background
echo "Starting Ollama server..."
ollama serve &
OLLAMA_PID=$!

# Aguardar Ollama ficar disponível
echo "Waiting for Ollama API..."
max_attempts=60
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
        echo "Ollama API is ready!"
        break
    fi
    attempt=$((attempt + 1))
    sleep 2
    echo -n "."
done
echo ""

if [ $attempt -ge $max_attempts ]; then
    echo "WARNING: Ollama API not responding after ${max_attempts}s"
    echo "Server may still be starting..."
fi

# Listar modelos disponíveis
echo ""
echo "Available models:"
ollama list 2>/dev/null || echo "  (no models loaded)"

# Baixar modelo padrão gemma4:e4b se não especificado
if [ -z "$OLLAMA_MODEL" ] || [ "$OLLAMA_MODEL" = "" ]; then
    export OLLAMA_MODEL="gemma4:e4b"
    echo ""
    echo "Using default model: $OLLAMA_MODEL"
fi

# Verificar e baixar modelo
if [ -n "$OLLAMA_MODEL" ] && [ "$OLLAMA_MODEL" != "" ]; then
    echo ""
    echo "Model to load: $OLLAMA_MODEL"
    if ! ollama list 2>/dev/null | grep -q "$OLLAMA_MODEL"; then
        echo "Downloading model $OLLAMA_MODEL..."
        echo "This may take several minutes depending on model size and internet speed."
        echo "Starting download at $(date '+%Y-%m-%d %H:%M:%S')"
        
        # Download com timeout de 2 horas (modelos grandes podem demorar)
        if timeout 7200 ollama pull "$OLLAMA_MODEL"; then
            echo ""
            echo "Model $OLLAMA_MODEL downloaded successfully!"
            echo "Download completed at $(date '+%Y-%m-%d %H:%M:%S')"
        else
            echo ""
            echo "ERROR: Failed to download model $OLLAMA_MODEL"
            echo "Exit code: $?"
            echo "You can try downloading manually with: ollama pull $OLLAMA_MODEL"
        fi
    else
        echo "Model already available"
    fi
fi

echo ""
echo "=============================================="
echo "Ollama ready at http://localhost:11434"
echo "=============================================="

# Configurar graceful shutdown
cleanup() {
    echo ""
    echo "Received shutdown signal, stopping Ollama gracefully..."
    kill -TERM "$OLLAMA_PID" 2>/dev/null || true
    wait "$OLLAMA_PID" 2>/dev/null || true
    echo "Ollama stopped"
    exit 0
}

# Capturar sinais de término
trap cleanup SIGTERM SIGINT

# Manter container ativo e aguardar Ollama
wait $OLLAMA_PID
