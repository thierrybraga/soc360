"""Contracts for the centralized database configuration."""

from app.settings.database import postgres_database_config, sqlite_database_config


def test_sqlite_core_and_public_share_one_repository(tmp_path):
    core_uri, binds = sqlite_database_config(tmp_path / "soc360.db")

    assert binds == {"public": core_uri}
    assert core_uri.endswith("/soc360.db")


def test_explicit_database_urls_take_precedence(monkeypatch):
    monkeypatch.setenv("CORE_DATABASE_URL", "postgresql://core.example/core")
    monkeypatch.setenv("PUBLIC_DATABASE_URL", "postgresql://public.example/public")

    core_uri, binds = postgres_database_config()

    assert core_uri == "postgresql://core.example/core"
    assert binds == {"public": "postgresql://public.example/public"}


def test_database_credentials_are_url_encoded(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("CORE_DATABASE_URL", raising=False)
    monkeypatch.setenv("DB_CORE_USER", "soc user")
    monkeypatch.setenv("DB_CORE_PASSWORD", "p@ss/word")

    core_uri, _ = postgres_database_config()

    assert "soc+user" in core_uri
    assert "p%40ss%2Fword" in core_uri
