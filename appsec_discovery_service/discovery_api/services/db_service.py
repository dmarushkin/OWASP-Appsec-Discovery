"""API DB access through the shared engine/session handling (P2-5). The schema is owned by
the Alembic migrations (``discovery_common/migrations``), the API never creates tables."""

from discovery_common import db
from config import get_settings
from logger import get_logger

logger = get_logger(__name__)


def init_db(wait_timeout: float = 60.0) -> None:
    """Point the shared engine at DATABASE_URL, wait for the database and check that it
    is migrated (the one-shot discovery_migrate service runs before the API)."""
    db.configure(url_factory=lambda: get_settings().database_url)
    db.wait_for_db(timeout=wait_timeout)
    revision = db.schema_revision()
    if revision is None:
        raise RuntimeError("Database schema is not migrated: run `python -m discovery_common.migrate` first")
    logger.info(f"Database schema revision {revision}")


def get_db_session():
    """FastAPI dependency."""
    yield from db.get_session()


def health() -> dict:
    with db.get_engine().connect() as conn:
        return {"revision": db.schema_revision(conn), "tables": db.table_stats(conn)}
