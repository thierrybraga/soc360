"""
SOC360 Database Utilities
Funções para inicialização e manutenção do banco de dados.
"""
import os
import logging
from flask import Flask
from app.extensions import db
from app.models.auth import User, Role
from app.models.system import SyncMetadata
from sqlalchemy import inspect, text

logger = logging.getLogger(__name__)


def _sqlite_col_type(column) -> str:
    """Converte o tipo SQLAlchemy de uma coluna para um tipo SQLite válido."""
    type_str = str(column.type).upper()
    base = type_str.split('(')[0].strip()

    # Inteiros
    if base in ('INTEGER', 'INT', 'BIGINT', 'SMALLINT', 'TINYINT'):
        return 'INTEGER'
    # Booleano (SQLite armazena como INTEGER 0/1)
    if base in ('BOOLEAN', 'BOOL'):
        return 'INTEGER'
    # Ponto flutuante
    if base in ('FLOAT', 'REAL', 'DOUBLE', 'DOUBLE_PRECISION', 'NUMERIC', 'DECIMAL'):
        return 'REAL'
    # Data/hora
    if base in ('DATETIME', 'TIMESTAMP'):
        return 'DATETIME'
    if base == 'DATE':
        return 'DATE'
    # Strings de tamanho fixo
    if base in ('VARCHAR', 'CHAR', 'NVARCHAR', 'NCHAR'):
        return 'TEXT'
    # Tudo o mais (TEXT, JSON, JSONB, INET, ARRAY, BLOB, etc.) → TEXT
    return 'TEXT'


def _render_col_type(column, engine) -> str:
    """Renderiza o tipo DDL de uma coluna para o dialeto realmente conectado.

    Usa o compilador do próprio dialeto (correto para Postgres E SQLite —
    JSONB/INET/TIMESTAMP no PG, JSON/DATETIME no SQLite). Cai para o mapeador
    SQLite manual apenas se a compilação falhar.
    """
    try:
        return column.type.compile(dialect=engine.dialect)
    except Exception:
        return _sqlite_col_type(column)


def _render_default_clause(column, is_sqlite: bool) -> str:
    """Monta a cláusula DEFAULT para um ALTER ADD COLUMN, segura por dialeto."""
    if column.default is None or not hasattr(column.default, 'arg'):
        return ""
    arg = column.default.arg
    # callables (ex.: datetime.utcnow) não têm valor literal — sem DEFAULT
    if callable(arg):
        return ""
    if isinstance(arg, bool):
        # Postgres exige TRUE/FALSE em colunas boolean; SQLite aceita 1/0
        literal = ('1' if arg else '0') if is_sqlite else ('TRUE' if arg else 'FALSE')
        return f" DEFAULT {literal}"
    if isinstance(arg, (int, float)):
        return f" DEFAULT {arg}"
    if isinstance(arg, str):
        safe = arg.replace("'", "''")  # escapa aspas simples
        return f" DEFAULT '{safe}'"
    return ""


def ensure_schema_up_to_date(app: Flask):
    """Garante que o schema acompanhe os models, em todos os binds.

    ``create_all`` só cria tabelas ausentes; aqui adicionamos (apenas ADD —
    nunca DROP) colunas que passaram a existir nos models. Funciona tanto em
    SQLite quanto em PostgreSQL e respeita o multi-bind: cada tabela é
    inspecionada/alterada no engine do seu próprio bind (essencial quando
    core e public são bancos físicos distintos).
    """
    with app.app_context():
        # 1. Criar tabelas que ainda não existem (todos os binds)
        db.create_all()

        # 2. Mapear bind_key -> engine (FSA3 expõe db.engines; fallback p/ default)
        engines = dict(getattr(db, 'engines', None) or {})
        if not engines:
            engines = {None: db.engine}

        # Cache de inspector + nomes de tabela por engine (evita reinspeção)
        inspectors = {}
        table_names_by_engine = {}
        for key, eng in engines.items():
            try:
                insp = inspect(eng)
                inspectors[key] = insp
                table_names_by_engine[key] = set(insp.get_table_names())
            except Exception as e:
                logger.error("Falha ao inspecionar engine do bind %r: %s", key, e)

        def _engine_for(bind_key):
            if bind_key in engines:
                return bind_key, engines[bind_key]
            # Tabelas sem bind explícito usam o engine default (None)
            return None, engines.get(None, db.engine)

        for mapper in db.Model.registry.mappers:
            model = mapper.class_
            table = getattr(model, '__table__', None)
            if table is None:
                continue

            bind_key = getattr(model, '__bind_key__', None) or table.info.get('bind_key')
            eng_key, engine = _engine_for(bind_key)
            insp = inspectors.get(eng_key)
            if insp is None:
                continue

            table_name = table.name
            if table_name not in table_names_by_engine.get(eng_key, set()):
                continue

            try:
                existing_columns = {c['name'] for c in insp.get_columns(table_name)}
            except Exception:
                continue

            is_sqlite = engine.dialect.name == 'sqlite'
            for column in table.columns:
                if column.name in existing_columns:
                    continue

                col_type = _render_col_type(column, engine)
                default_val = _render_default_clause(column, is_sqlite)
                ddl = f"ALTER TABLE {table_name} ADD COLUMN {column.name} {col_type}{default_val}"
                logger.info("Adicionando coluna '%s' em '%s' (bind=%r)...",
                            column.name, table_name, bind_key)
                try:
                    # Executa no engine do bind correto (não na db.session, que é
                    # ligada ao engine default/core).
                    with engine.begin() as conn:
                        conn.execute(text(ddl))
                    logger.info("Coluna '%s' adicionada com sucesso.", column.name)
                except Exception as e:
                    logger.error("Erro ao adicionar coluna '%s' em '%s': %s",
                                 column.name, table_name, e)

def initialize_database(app: Flask):
    """
    Inicializa o banco de dados, cria tabelas e dados iniciais.
    
    1. Cria todas as tabelas se não existirem.
    2. Cria as roles padrão (ADMIN, ANALYST, VIEWER, API_USER).
    3. Cria o usuário administrador padrão (admin/admin).
    4. Marca o sistema como inicializado.
    5. Dispara gatilhos de sincronização inicial.
    """
    with app.app_context():
        # 1. Criar tabelas
        logger.info("Criando tabelas no banco de dados...")
        db.create_all()
        
        # 2. Criar roles padrão
        logger.info("Inicializando roles padrão...")
        roles_created = Role.create_default_roles()
        if roles_created:
            logger.info(f"Roles criadas: {', '.join(roles_created)}")
        else:
            logger.info("Roles já existem.")
            
        # 3. Criar usuário admin padrão
        create_default_admin()
        
        # 4. Marcar sistema como inicializado
        SyncMetadata.set_value('system_initialized', 'true')
        logger.info("Sistema marcado como inicializado.")
        
        # 5. Aviso de Sincronização
        logger.warning(
            "As sincronizações base (NVD, EUVD, MITRE) não são mais disparadas automaticamente no start da aplicação "
            "para evitar problemas de Threads inseguras no servidor WSGI (Gunicorn/uWSGI). "
            "Por favor, proceda com o Sync manualmente através da Interface UI (Assistente admin) ou via DAGs do Airflow."
        )

def create_default_admin():
    """Cria o usuário administrador padrão (admin/admin)."""
    admin_username = 'admin'
    admin_email = 'admin@soc360.local'
    admin_password = 'admin' # Senha solicitada pelo usuário
    
    admin_user = User.query.filter_by(username=admin_username).first()
    if not admin_user:
        logger.info(f"Criando usuário administrador: {admin_username}")
        # Criar admin usando o novo construtor que lida com is_admin
        admin_user = User(
            username=admin_username,
            email=admin_email,
            password=admin_password,
            is_admin=True,
            is_active=True,
            email_confirmed=True,
            force_password_reset=True
        )
        db.session.add(admin_user)
        db.session.commit()
        logger.info("Usuário administrador criado com sucesso.")
    else:
        logger.info("Usuário administrador já existe.")
        # Garantir que tenha a role ADMIN
        admin_role = Role.query.filter_by(name='ADMIN').first()
        if admin_role and admin_role not in admin_user.roles:
            admin_user.roles.append(admin_role)
            db.session.commit()
            logger.info("Role ADMIN associada ao usuário administrador existente.")



def check_and_init_db(app: Flask):
    """Verifica se o banco precisa ser inicializado e o faz se necessário."""
    basedir = os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    db_path = os.path.join(basedir, 'instance', 'app.db')

    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')

    if db_uri.startswith('sqlite:///'):
        if not os.path.exists(db_path):
            logger.info(f"Banco de dados SQLite não encontrado em {db_path}. Iniciando inicialização...")
            initialize_database(app)
        else:
            # Mesmo se o arquivo existe, garante que o schema está atualizado
            ensure_schema_up_to_date(app)

            # Verifica se o sistema foi marcado como inicializado
            with app.app_context():
                try:
                    if not SyncMetadata.get('system_initialized'):
                        logger.info("Banco existe mas sistema não está inicializado. Rodando inicialização...")
                        initialize_database(app)
                except Exception:
                    # Se der erro (ex: tabela SyncMetadata não existe), inicializa
                    logger.info("Erro ao verificar status. Rodando inicialização completa...")
                    initialize_database(app)
    else:
        # Modo PostgreSQL: na primeira subida cria todo o schema + seed (roles,
        # admin, flag de inicialização); nas subsequentes apenas sincroniza o
        # schema (create_all cria tabelas novas; ensure_schema_up_to_date aplica
        # colunas adicionadas posteriormente — nunca dropa).
        logger.info('Usando PostgreSQL: %s', db_uri)
        try:
            with app.app_context():
                try:
                    initialized = bool(SyncMetadata.get('system_initialized'))
                except Exception:
                    # Tabela ainda não existe → primeira subida
                    initialized = False
            if initialized:
                ensure_schema_up_to_date(app)
            else:
                logger.info('PostgreSQL sem schema inicializado — criando tabelas e dados base...')
                initialize_database(app)
        except Exception as e:
            logger.error('Falha ao inicializar/sincronizar schema no Postgres: %s', e, exc_info=True)

    # Coerência tipo-de-coluna × dialeto realmente conectado (pós-fallback).
    try:
        from app.extensions.db_types import assert_dialect_coherence
        with app.app_context():
            assert_dialect_coherence(db.engine, logger)
    except Exception as e:
        logger.debug('Verificação de coerência de dialeto ignorada: %s', e)
