# secrets/

Este diretório contém os arquivos de secret para o Docker secrets (Linux/OL9).

**Os arquivos `.txt` são excluídos do git via `.gitignore`. NUNCA os commite.**

## Arquivos necessários

| Arquivo | Descrição |
|---------|-----------|
| `secret_key.txt` | Chave Flask `SECRET_KEY` (≥ 64 chars hex) |
| `redis_password.txt` | Senha do Redis (≥ 48 chars hex) |
| `postgres_password.txt` | Senha do PostgreSQL (usada pelo serviço `postgres` e pelo app) |

## Geração automática

```bash
# Gera ambos os arquivos com valores seguros
python scripts/generate-secrets.py
```

## Geração manual

```bash
# secret_key.txt
openssl rand -hex 32 > secrets/secret_key.txt

# redis_password.txt
openssl rand -hex 24 > secrets/redis_password.txt

# postgres_password.txt (sem newline final)
printf '%s' "$(openssl rand -hex 24)" > secrets/postgres_password.txt

# Permissões restritas (obrigatório em produção)
chmod 600 secrets/*.txt
chmod 700 secrets/
```

## Atenção

- Em produção Linux/OL9, os secrets são montados via Docker secrets em `/run/secrets/`
- No Windows (Docker Desktop), use variáveis de ambiente no `.env` em vez de arquivos
- Rotacionar secrets periodicamente com `scripts/rotate-secrets.sh`
- Nunca expor o conteúdo destes arquivos em logs, commits ou issues
