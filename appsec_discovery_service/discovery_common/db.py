"""Engine and session handling shared by the scanner and the API (P2-5).

* One engine per process (``pool_pre_ping``): connection pools must not be shared across the
  scanner's forked workers, so the engine is re-created when the pid changes.
* ``unit_of_work()``: one transaction, committed on success and rolled back on error.
  Sessions use ``expire_on_commit=False`` so rows returned from a unit of work stay usable
  (the old scanner closed its only session in every helper and handed out detached rows).
* ``get_session()``: FastAPI dependency.
* ``wait_for_db()``: replaces the fixed ``sleep(15)`` before startup.
"""

import os
import time
from contextlib import contextmanager
from typing import Callable, Iterator, Optional

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from discovery_common.log import get_logger

logger = get_logger(__name__)

_url: Optional[str] = None
_url_factory: Optional[Callable[[], str]] = None
_engine: Optional[Engine] = None
_engine_pid: Optional[int] = None
_sessionmaker: Optional[sessionmaker] = None


def configure(url: Optional[str] = None, url_factory: Optional[Callable[[], str]] = None) -> None:
    """Set the database URL (or a callable returning it, resolved lazily). Resets the engine."""
    global _url, _url_factory, _engine, _engine_pid, _sessionmaker
    _url, _url_factory = url, url_factory
    if _engine is not None and _engine_pid == os.getpid():
        _engine.dispose()
    _engine = _engine_pid = _sessionmaker = None


def _database_url() -> str:
    if _url:
        return _url
    if _url_factory is not None:
        return _url_factory()
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not configured")
    return url


def get_engine() -> Engine:
    global _engine, _engine_pid, _sessionmaker
    if _engine is None or _engine_pid != os.getpid():
        _engine = create_engine(_database_url(), pool_pre_ping=True)
        _engine_pid = os.getpid()
        _sessionmaker = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def session_factory() -> sessionmaker:
    get_engine()
    return _sessionmaker


@contextmanager
def unit_of_work() -> Iterator[Session]:
    """``with unit_of_work() as session:`` - one transaction (commit on success)."""
    with session_factory().begin() as session:
        yield session


def get_session() -> Iterator[Session]:
    """FastAPI dependency: a session closed after the request."""
    session = session_factory()()
    try:
        yield session
    finally:
        session.close()


def wait_for_db(timeout: float = 60.0, interval: float = 2.0) -> None:
    """Block until the database accepts connections (or raise after ``timeout`` seconds)."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except OperationalError as e:
            if time.monotonic() >= deadline:
                raise
            logger.info(f"Database is not ready yet ({e.__class__.__name__}), retrying in {interval}s")
            time.sleep(interval)


def schema_revision(conn: Optional[Connection] = None) -> Optional[str]:
    """Current Alembic revision of the database (None when it was never migrated)."""
    def _read(c):
        if not c.execute(text("SELECT to_regclass('alembic_version') IS NOT NULL")).scalar():
            return None
        return c.execute(text("SELECT version_num FROM alembic_version")).scalar()

    if conn is not None:
        return _read(conn)
    with get_engine().connect() as c:
        return _read(c)


TABLE_STATS_SQL = text("""
    SELECT relname, n_live_tup, n_dead_tup, last_autovacuum, last_vacuum
    FROM pg_stat_user_tables
    ORDER BY relname
""")


def table_stats(conn: Optional[Connection] = None) -> dict:
    """Row counts and dead tuples per table (``pg_stat_user_tables``) for health checks."""
    def _read(c):
        return {
            row.relname: {
                "rows": row.n_live_tup,
                "dead": row.n_dead_tup,
                "last_vacuum": str(row.last_autovacuum or row.last_vacuum) if (row.last_autovacuum or row.last_vacuum) else None,
            }
            for row in c.execute(TABLE_STATS_SQL)
        }

    if conn is not None:
        return _read(conn)
    with get_engine().connect() as c:
        return _read(c)
