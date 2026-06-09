"""
SOC360 Database Types
Database type definitions and utilities.
"""
import json
import os
from sqlalchemy import JSON, String, Text
from sqlalchemy.dialects.postgresql import JSONB as PG_JSONB, INET as PG_INET, ARRAY as PG_ARRAY
from sqlalchemy.types import TypeDecorator

# Determine SQLite usage from environment and known fallback path
basedir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
db_path = os.path.join(basedir, 'instance', 'app.db')

def _resolve_use_sqlite() -> bool:
    """Decide the column-type dialect from the SAME signals that configure the
    actual connection in ``app/settings/base.py`` — so the types layer never
    silently diverges from the engine.

    Historically this read only ``DATABASE_URL``; a Postgres deployment
    configured via ``DB_CORE_*`` (the documented way) but without
    ``DATABASE_URL`` would get SQLite types (JSON instead of JSONB, String
    instead of INET) and skip every GIN/partial index — degrading silently.

    Priority:
      1. Explicit URL override (``DATABASE_URL`` / ``CORE_DATABASE_URL``):
         a ``postgres(ql)://`` prefix means Postgres, anything else SQLite.
      2. Presence of ``DB_CORE_HOST``: settings builds a ``postgresql://`` URI
         from ``DB_CORE_*`` whenever it is set, so use Postgres types.
      3. Default: SQLite-compatible types (safe for local dev and for the
         runtime Postgres→SQLite fallback).
    """
    for var in ('DATABASE_URL', 'CORE_DATABASE_URL'):
        url = os.getenv(var, '').strip()
        if url:
            return not url.startswith(('postgresql', 'postgres'))
    if os.getenv('DB_CORE_HOST', '').strip():
        return False
    return True


USE_SQLITE = _resolve_use_sqlite()


def assert_dialect_coherence(engine, logger=None) -> bool:
    """Compare the column-type dialect chosen at import time with the dialect of
    the engine actually connected, logging a clear ERROR on divergence.

    Returns True when coherent. Call this once at startup (after any
    Postgres→SQLite fallback has been resolved) so a mismatch surfaces as an
    actionable message instead of an obscure ``can't render element of type
    JSONB`` / missing-GIN-index degradation.
    """
    import logging as _logging

    log = logger or _logging.getLogger(__name__)
    connected_sqlite = engine.dialect.name == 'sqlite'
    if connected_sqlite == USE_SQLITE:
        return True

    if USE_SQLITE and not connected_sqlite:
        log.error(
            'DB type/connection mismatch: connected to %r but column types are '
            'SQLite-flavored (JSON/String, no JSONB/INET, GIN & partial indexes '
            'skipped). Set DATABASE_URL=postgresql://... (or DB_CORE_HOST) so '
            'JSONB/INET/GIN are used. Correlation and JSON queries will be '
            'degraded until fixed.', engine.dialect.name,
        )
    else:
        log.error(
            'DB type/connection mismatch: column types are Postgres-flavored '
            '(JSONB/INET) but the engine connected is SQLite. This will fail on '
            'create_all/queries. Unset DATABASE_URL/DB_CORE_HOST for pure SQLite '
            'use, or make Postgres reachable so the app does not fall back.',
        )
    return False

# JSON type - use JSONB for PostgreSQL, JSON for SQLite
JSONB = JSON if USE_SQLITE else PG_JSONB

# INET type - use String for SQLite
INET = String(43) if USE_SQLITE else PG_INET

# ARRAY type - proper TypeDecorator for SQLite, stores arrays as JSON text
if USE_SQLITE:
    class JSONEncodedArray(TypeDecorator):
        """Stores a Python list as a JSON-encoded TEXT string for SQLite compatibility.

        Accepts an optional ``item_type`` argument (like PostgreSQL ARRAY) so it can
        be used as a drop-in replacement: ``ARRAY(String(255))``.
        """
        impl = Text
        cache_ok = True

        def __init__(self, item_type=None, **kwargs):
            # item_type is ignored; all values serialised as JSON text
            super().__init__()

        def process_bind_param(self, value, dialect):
            if value is None:
                return None
            if isinstance(value, list):
                return json.dumps(value)
            return value  # pass-through if already a string (e.g. during migrations)

        def process_result_value(self, value, dialect):
            if value is None:
                return None
            if isinstance(value, str):
                try:
                    return json.loads(value)
                except (TypeError, ValueError):
                    return value
            return value  # already a list (shouldn't happen in SQLite, but safe)

    ARRAY = JSONEncodedArray
else:
    ARRAY = PG_ARRAY