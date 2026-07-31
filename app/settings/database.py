"""Single source of truth for database connection configuration."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import quote_plus


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SQLITE_PATH = PROJECT_ROOT / "instance" / "app.db"


def _postgres_url(scope: str, *, default_host: str, default_name: str) -> str:
    """Build one PostgreSQL URL, honoring an explicit URL override first."""
    scope = scope.upper()
    explicit = os.getenv(f"{scope}_DATABASE_URL")
    if scope == "CORE":
        explicit = explicit or os.getenv("DATABASE_URL")
    if explicit:
        return explicit

    user = quote_plus(os.getenv(f"DB_{scope}_USER", "soc360"))
    password = quote_plus(os.getenv(f"DB_{scope}_PASSWORD", "change_me"))
    host = os.getenv(f"DB_{scope}_HOST", default_host)
    port = os.getenv(f"DB_{scope}_PORT", "5432")
    name = os.getenv(f"DB_{scope}_NAME", default_name)
    return f"postgresql://{user}:{password}@{host}:{port}/{name}"


def postgres_database_config() -> tuple[str, dict[str, str]]:
    """Return the default/core URI and the single named public bind."""
    core = _postgres_url("CORE", default_host="postgres_core", default_name="soc360_core")
    public = _postgres_url("PUBLIC", default_host="postgres_public", default_name="soc360_public")
    return core, {"public": public}


def sqlite_database_config(path: str | Path | None = None) -> tuple[str, dict[str, str]]:
    """Return co-located core/public SQLite URIs for local or test use."""
    if path == ":memory:":
        uri = "sqlite:///:memory:"
    else:
        sqlite_path = Path(path or DEFAULT_SQLITE_PATH).resolve()
        sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        uri = f"sqlite:///{sqlite_path.as_posix()}"
    return uri, {"public": uri}


def apply_sqlite_config(app, path: str | Path | None = None) -> None:
    """Apply the canonical SQLite configuration before SQLAlchemy init_app."""
    from sqlalchemy.pool import StaticPool

    uri, binds = sqlite_database_config(path)
    app.config.update(
        SQLALCHEMY_DATABASE_URI=uri,
        SQLALCHEMY_BINDS=binds,
        SQLALCHEMY_ENGINE_OPTIONS={
            "connect_args": {"check_same_thread": False},
            "poolclass": StaticPool,
        },
    )
