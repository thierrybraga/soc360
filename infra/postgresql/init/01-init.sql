-- O container cria o banco e o usuário definidos por POSTGRES_DB/POSTGRES_USER.
-- Roles adicionais devem ser provisionadas externamente com credenciais próprias;
-- este script não mantém senhas ou nomes de bancos duplicados.

-- Extensões necessárias no banco ativo.
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
