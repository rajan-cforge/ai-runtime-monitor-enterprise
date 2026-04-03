import os
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

_engine = None
_SessionLocal = None


def get_engine():
    """Return a singleton SQLAlchemy engine."""
    global _engine
    if _engine is None:
        database_url = os.environ.get(
            "DATABASE_URL",
            "postgresql://monitor:changeme@localhost:5432/fleet_monitor",
        )
        _engine = create_engine(database_url, pool_size=10, max_overflow=20)
    return _engine


def _get_session_factory():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(), autoflush=False)
    return _SessionLocal


def get_db():
    """FastAPI dependency: yields a SQLAlchemy session, closes on exit."""
    session = _get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def run_migrations():
    """Execute the 001_initial_schema.sql migration file."""
    migration_path = Path(__file__).parent.parent / "migrations" / "001_initial_schema.sql"
    if not migration_path.exists():
        raise FileNotFoundError(f"Migration file not found: {migration_path}")

    sql = migration_path.read_text()
    engine = get_engine()
    with engine.begin() as conn:
        # Split on semicolons and execute each statement individually,
        # skipping empty statements.
        for statement in sql.split(";"):
            stmt = statement.strip()
            if stmt:
                conn.execute(text(stmt))
