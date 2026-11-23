"""Test helpers: throwaway Postgres databases and reference readers of the storage.

Integration tests run when ``TEST_DATABASE_URL`` points to a Postgres server (any database
on it; the user must be allowed to CREATE DATABASE), for example a container started with
``docker run --rm -d -p 127.0.0.1::5432 -e POSTGRES_PASSWORD=pw postgres:16``. Each test
module gets a fresh database that is dropped afterwards.

With ``TEST_PG_DOCKER=1`` (and no TEST_DATABASE_URL) the discovery_common / scanner test
sessions start such a throwaway ``postgres:16`` container themselves (unique name, removed
at the end of the session, see ``docker_postgres``).
"""

import os
import shutil
import socket
import subprocess
import time
import uuid
from contextlib import contextmanager
from typing import Iterator, Optional

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from discovery_common.queries import DELTA_OWNER_COND

ENV = "TEST_DATABASE_URL"
DOCKER_ENV = "TEST_PG_DOCKER"


def admin_url() -> Optional[str]:
    return os.environ.get(ENV) or None


def docker_requested() -> bool:
    return os.environ.get(DOCKER_ENV, "").strip().lower() in ("1", "true", "yes")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_server(url: str, timeout: float = 60.0) -> None:
    engine = create_engine(url)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                with engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                return
            except Exception:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.5)
    finally:
        engine.dispose()


@contextmanager
def docker_postgres(image: str = "postgres:16", prefix: str = "discovery-test") -> Iterator[str]:
    """A throwaway Postgres container (unique name, published on 127.0.0.1 only, removed on
    exit): yields its admin URL. Raises RuntimeError when docker cannot start it."""
    if shutil.which("docker") is None:
        raise RuntimeError("docker is not available")
    name = f"{prefix}-{uuid.uuid4().hex[:10]}"
    port = _free_port()
    started = subprocess.run(
        ["docker", "run", "--rm", "-d", "--name", name, "-p", f"127.0.0.1:{port}:5432",
         "-e", "POSTGRES_PASSWORD=pw", image],
        capture_output=True, text=True,
    )
    if started.returncode != 0:
        raise RuntimeError(f"cannot start a {image} container: {started.stderr.strip()[:200]}")
    try:
        url = f"postgresql://postgres:pw@127.0.0.1:{port}/postgres"
        wait_for_server(url)
        yield url
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


@contextmanager
def server_url() -> Iterator[Optional[str]]:
    """TEST_DATABASE_URL, else (TEST_PG_DOCKER=1) a throwaway container, else None. While
    a container is used, TEST_DATABASE_URL points at it (``admin_url()`` sees it)."""
    url = admin_url()
    if url or not docker_requested():
        yield url
        return
    with docker_postgres() as url:
        os.environ[ENV] = url
        try:
            yield url
        finally:
            os.environ.pop(ENV, None)


@contextmanager
def fresh_database(prefix: str = "t") -> Iterator[str]:
    """Create an empty database on the TEST_DATABASE_URL server, yield its URL, drop it."""
    base = make_url(admin_url())
    name = f"{prefix}_{uuid.uuid4().hex[:12]}"
    admin = create_engine(base, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            conn.execute(text(f'CREATE DATABASE "{name}"'))
        yield base.set(database=name).render_as_string(hide_password=False)
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def migrate(url: str, revision: str = "head") -> None:
    """Run the Alembic migrations against ``url`` (no waiting, no global engine)."""
    from alembic import command

    from discovery_common.migrate import alembic_config

    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            config = alembic_config()
            config.attributes["connection"] = connection
            command.upgrade(config, revision)
    finally:
        engine.dispose()


# ---- reference readers ------------------------------------------------------------------------
# "Main only" / "open (unmerged) MRs only" selections over the storage (see discovery_common.queries
# for the indexes that serve them): tests/test_common_query_plans checks their plans, the scanner's
# storage tests read the stored snapshots / deltas with them.

# Fields present in some main branch, all projects, field name ILIKE (trigram index).
MAIN_FIELDS_SQL = text("""
    SELECT o.project_id, o.name AS object_name, o.type AS object_type, o.file,
           f.field_name, f.field_type, f.field_key
    FROM object_fields f
    JOIN objects o ON o.content_hash = f.content_hash
    WHERE f.field_name ILIKE :name_like
      AND EXISTS (SELECT 1 FROM branch_objects b WHERE b.content_hash = f.content_hash AND b.is_main)
    ORDER BY o.project_id, o.name, f.field_name
    LIMIT :limit
""")

# Fields present in the main branch of one project: exact name and/or pattern. The pattern
# is matched with lower() LIKE on purpose: inside one project fields_proj_name is selective,
# while the trigram index would return every matching field of every project.
MAIN_PROJECT_FIELDS_SQL = text("""
    SELECT o.project_id, o.name AS object_name, o.type AS object_type, o.file,
           f.field_name, f.field_type, f.field_key
    FROM object_fields f
    JOIN objects o ON o.content_hash = f.content_hash
    WHERE f.project_id = :project_id
      AND (CAST(:name_eq AS text) IS NULL OR f.field_name = :name_eq)
      AND (CAST(:name_like AS text) IS NULL OR lower(f.field_name) LIKE lower(:name_like))
      AND EXISTS (SELECT 1 FROM branch_objects b WHERE b.content_hash = f.content_hash AND b.is_main)
    ORDER BY o.name, f.field_name
    LIMIT :limit
""")

# Fields of new/changed objects in open (unmerged) MRs, all projects, field name ILIKE.
OPEN_MR_FIELDS_SQL = text("""
    SELECT m.project_id, m.mr_id, b.change, o.name AS object_name, o.type AS object_type, o.file,
           f.field_name, f.field_type, f.field_key
    FROM object_fields f
    JOIN branch_objects b ON b.content_hash = f.content_hash AND NOT b.is_main
    JOIN gitlab_mrs m ON m.source_branch_id = b.branch_id AND m.state = 'opened'
    JOIN objects o ON o.content_hash = f.content_hash
    WHERE f.field_name ILIKE :name_like AND """ + DELTA_OWNER_COND + """
    ORDER BY m.project_id, m.mr_id, o.name, f.field_name
    LIMIT :limit
""")

# Fields of new/changed objects in the open MRs of one project.
OPEN_MR_PROJECT_FIELDS_SQL = text("""
    SELECT m.project_id, m.mr_id, b.change, o.name AS object_name, o.type AS object_type, o.file,
           f.field_name, f.field_type, f.field_key
    FROM gitlab_mrs m
    JOIN branch_objects b ON b.branch_id = m.source_branch_id AND NOT b.is_main
    JOIN objects o ON o.content_hash = b.content_hash
    JOIN object_fields f ON f.content_hash = b.content_hash
    WHERE m.project_id = :project_id AND m.state = 'opened' AND """ + DELTA_OWNER_COND + """
      AND (CAST(:name_eq AS text) IS NULL OR f.field_name = :name_eq)
      AND (CAST(:name_like AS text) IS NULL OR lower(f.field_name) LIKE lower(:name_like))
    ORDER BY m.mr_id, o.name, f.field_name
    LIMIT :limit
""")

# All delta rows (incl. removed objects) of the open MRs of one project.
OPEN_MR_DELTA_SQL = text("""
    SELECT m.mr_id, b.object_key, b.change, b.content_hash
    FROM gitlab_mrs m
    JOIN branch_objects b ON b.branch_id = m.source_branch_id AND NOT b.is_main
    WHERE m.project_id = :project_id AND m.state = 'opened' AND """ + DELTA_OWNER_COND + """
    ORDER BY m.mr_id, b.change
""")

# Review queue of a project: pending hits whose field is present in main.
REVIEW_QUEUE_SQL = text("""
    SELECT h.* FROM rule_hits h
    WHERE h.project_id = :project_id AND h.status = :status
      AND EXISTS (SELECT 1 FROM object_fields f
                  JOIN branch_objects b ON b.content_hash = f.content_hash AND b.is_main
                  WHERE f.field_key = h.subject_key)
    ORDER BY h.first_seen_at
    LIMIT :limit
""")


def _like(pattern: Optional[str]) -> Optional[str]:
    if pattern is None:
        return None
    return pattern if any(ch in pattern for ch in "%_") else f"%{pattern}%"


def _field_params(project_id, name, exact, limit):
    if project_id is None and (name is None or exact):
        raise ValueError("a query over all projects needs a name pattern (exact=False)")
    return {
        "project_id": project_id, "limit": limit,
        "name_eq": name if exact else None,
        "name_like": None if exact else _like(name),
    }


def main_fields(conn, project_id: Optional[int] = None, name: Optional[str] = None, exact: bool = False,
                limit: int = 100):
    """Fields in main branches: one project (optionally filtered by ``name``), or all projects
    by a name pattern (``name`` without ``%``/``_`` means "contains")."""
    params = _field_params(project_id, name, exact, limit)
    sql = MAIN_FIELDS_SQL if project_id is None else MAIN_PROJECT_FIELDS_SQL
    return conn.execute(sql, params).mappings().all()


def open_mr_fields(conn, project_id: Optional[int] = None, name: Optional[str] = None, exact: bool = False,
                   limit: int = 100):
    """Fields of new/changed objects in open (unmerged) MRs only."""
    params = _field_params(project_id, name, exact, limit)
    sql = OPEN_MR_FIELDS_SQL if project_id is None else OPEN_MR_PROJECT_FIELDS_SQL
    return conn.execute(sql, params).mappings().all()


def open_mr_delta(conn, project_id: int):
    return conn.execute(OPEN_MR_DELTA_SQL, {"project_id": project_id}).mappings().all()
