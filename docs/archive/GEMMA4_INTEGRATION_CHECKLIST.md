# Verificação de Integração - Modelo Gemma4:e4b

## Checklist de Configuração Completa

### ✅ 1. Configuração do Docker Compose

**Arquivos atualizados:**
- [x] `docker-compose.yml` - `OLLAMA_MODEL=${OLLAMA_MODEL:-gemma4:e4b}`
- [x] `docker-compose.ol9.yml` - `OLLAMA_MODEL=${OLLAMA_MODEL:-gemma4:e4b}`

### ✅ 2. Configuração da Aplicação Python

**Arquivos atualizados:**
- [x] `app/settings/base.py` - `OLLAMA_MODEL = os.environ.get('OLLAMA_MODEL', 'gemma4:e4b')`
- [x] `app/services/core/ollama_service.py` - `self.model = current_app.config.get('OLLAMA_MODEL', 'gemma4:e4b')`

### ✅ 3. Script de Inicialização do Ollama

**Arquivo atualizado:**
- [x] `ollama/endpoint.sh` - Download automático com fallback para gemma4:e4b

### ✅ 4. Dockerfile do Ollama

**Arquivo atualizado:**
- [x] `ollama/dockerfile` - Instalação via release GitHub com verificação

## 🧪 Testes de Verificação

### Teste 1: Verificar Configuração
```bash
# Verificar variável no compose
grep -n "OLLAMA_MODEL" docker-compose.yml docker-compose.ol9.yml

# Esperado:
# docker-compose.yml:      - OLLAMA_MODEL=${OLLAMA_MODEL:-gemma4:e4b}
# docker-compose.ol9.yml:      - OLLAMA_MODEL=${OLLAMA_MODEL:-gemma4:e4b}
```

### Teste 2: Verificar Settings Python
```bash
# Verificar configuração Python
grep -n "OLLAMA_MODEL" app/settings/base.py

# Esperado:
# OLLAMA_MODEL      = os.environ.get('OLLAMA_MODEL', 'gemma4:e4b')
```

### Teste 3: Verificar Serviço Ollama
```bash
# Verificar serviço
grep -n "OLLAMA_MODEL" app/services/core/ollama_service.py

# Esperado:
# self.model     = current_app.config.get('OLLAMA_MODEL', 'gemma4:e4b')
```

### Teste 4: Deploy e Download
```bash
# Iniciar serviços
./scripts/deploy-linux.sh start

# Verificar logs do Ollama
docker-compose logs -f ollama

# Esperado:
# "Using default model: gemma4:e4b"
# "Downloading model gemma4:e4b..."
# "Model gemma4:e4b downloaded successfully!"
```

### Teste 5: Verificar Modelo Carregado
```bash
# Listar modelos
docker-compose exec ollama ollama list

# Esperado:
# NAME            ID           SIZE      MODIFIED
# gemma4:e4b      xxx...       2.5GB     2 minutes ago
```

### Teste 6: Testar API do Chatbot
```bash
# Verificar health do chatbot
curl http://localhost:5000/chatbot/api/health

# Esperado:
# {"status":"ok","provider":"ollama","model":"gemma4:e4b"}
```

### Teste 7: Testar Geração de Resposta
```bash
# Testar chat
curl -X POST http://localhost:5000/chatbot/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message":"O que é uma CVE?"}'

# Esperado: Resposta em português explicando CVE
```

## 📋 Resumo das Alterações

| Componente | Valor Anterior | Valor Novo | Status |
|------------|---------------|------------|--------|
| docker-compose.yml | `llama3.2:latest` | `gemma4:e4b` | ✅ |
| docker-compose.ol9.yml | `llama3.2:latest` | `gemma4:e4b` | ✅ |
| app/settings/base.py | `llama3.2:latest` | `gemma4:e4b` | ✅ |
| ollama_service.py | `llama3.2:latest` | `gemma4:e4b` | ✅ |
| ollama/endpoint.sh | genérico | gemma4:e4b default | ✅ |

## 🚀 Comandos de Deploy

```bash
# Deploy completo com novo modelo
./scripts/deploy-linux.sh start

# Verificar status
./scripts/deploy-linux.sh status

# Logs específicos do Ollama
docker-compose logs -f ollama

# Testar chatbot
curl -X POST http://localhost:5000/chatbot/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message":"Explique o que é o SOC360"}'
```

## 🔧 Troubleshooting

### Problema: Modelo não baixa
```bash
# Verificar conectividade
docker-compose exec ollama curl -I https://ollama.com

# Download manual
docker-compose exec ollama ollama pull gemma4:e4b
```

### Problema: Aplicação usa modelo antigo
```bash
# Reiniciar app para pegar nova config
docker-compose restart app

# Verificar variável de ambiente
docker-compose exec app env | grep OLLAMA
```

### Problema: Chatbot não responde
```bash
# Verificar health
curl http://localhost:5000/chatbot/api/health

# Verificar logs
docker-compose logs app | tail -50