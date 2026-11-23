"""Fixtures of the discovery_api tests (REST + MCP against a real Postgres).

The API runs on pydantic v2 + FastAPI + mcp, which are not in the core dev env (pydantic
1.10): run these tests in their own environment, e.g. from ``appsec_discovery_service/``::

    uv run --no-project --with-requirements discovery_api/requirements-dev.txt \\
        pytest discovery_api/tests

Postgres: ``TEST_DATABASE_URL`` (see ``discovery_common/testing.py``), or else a throwaway
``postgres:16`` docker container (unique name, removed after the session) when docker is
available; otherwise the DB tests are skipped. Test modules ``importorskip`` the API deps,
so under the core env (``uv run pytest`` at the repo root) they are skipped.
"""

import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

API_DIR = Path(__file__).resolve().parents[1]
SERVICE_DIR = API_DIR.parent

ADMIN = "reviewer@example.com"
PASSWORD = "s3cret-Test-Passw0rd"
JWT_KEY = "test-jwt-key-" + "x" * 32


def fast_hash(password: str) -> str:
    """bcrypt with 4 rounds: fast tests, still a real bcrypt hash."""
    from passlib.hash import bcrypt
    return bcrypt.using(rounds=4).hash(password)


def _add_paths():
    for path in (str(SERVICE_DIR), str(API_DIR)):
        if path not in sys.path:
            sys.path.insert(0, path)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_pg(url: str, timeout: float = 60.0) -> None:
    from sqlalchemy import create_engine, text
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


@pytest.fixture(scope="session")
def pg_admin_url():
    """A Postgres server URL: TEST_DATABASE_URL or a throwaway postgres:16 container."""
    _add_paths()
    url = os.environ.get("TEST_DATABASE_URL")
    if url:
        yield url
        return
    if shutil.which("docker") is None:
        pytest.skip("TEST_DATABASE_URL is not set and docker is not available")
    name = f"discovery-api-test-{uuid.uuid4().hex[:10]}"
    port = _free_port()
    started = subprocess.run(
        ["docker", "run", "--rm", "-d", "--name", name, "-p", f"127.0.0.1:{port}:5432",
         "-e", "POSTGRES_PASSWORD=pw", "postgres:16"],
        capture_output=True, text=True,
    )
    if started.returncode != 0:
        pytest.skip(f"cannot start a postgres:16 container: {started.stderr.strip()[:200]}")
    try:
        url = f"postgresql://postgres:pw@127.0.0.1:{port}/postgres"
        _wait_pg(url)
        yield url
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


@pytest.fixture
def db_url(pg_admin_url, monkeypatch):
    """A fresh, migrated database."""
    from discovery_common import testing
    monkeypatch.setenv(testing.ENV, pg_admin_url)
    with testing.fresh_database("api") as url:
        testing.migrate(url)
        yield url


@pytest.fixture
def api_settings(db_url):
    import auth
    import config
    from discovery_common import db

    config.set_settings(config.ApiSettings(
        database_url=db_url, ui_admin_email=ADMIN, ui_jwt_key=JWT_KEY,
        ui_admin_password_hash=fast_hash(PASSWORD),
    ))
    try:
        yield config.get_settings()
    finally:
        config.set_settings(None)
        db.configure(None)


@pytest.fixture
def api(api_settings):
    """A TestClient of a fresh app (lifespan run), logged in (``client.token``)."""
    from fastapi.testclient import TestClient

    import main

    with TestClient(main.create_app()) as client:
        response = client.post("/token", data={"username": ADMIN, "password": PASSWORD})
        assert response.status_code == 200, response.text
        client.token = response.json()["access_token"]
        client.headers["Authorization"] = f"Bearer {client.token}"
        yield client


@pytest.fixture
def live_api(api_settings):
    """A fresh app served over HTTP by uvicorn (for the MCP SDK client): its base URL."""
    import uvicorn

    import main

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(main.create_app(), host="127.0.0.1", port=port, log_level="warning",
                                           lifespan="on"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 30
    while not server.started:
        if time.monotonic() > deadline or not thread.is_alive():
            raise RuntimeError("uvicorn did not start")
        time.sleep(0.05)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(10)


SEED_SQL = """
INSERT INTO gitlab_projects (id, gitlab_id, project_name, full_path, visibility, created_at, updated_at) VALUES
  (1, 101, 'proj', 'grp/proj', 'private', now(), now()), (2, 102, 'other', 'grp/other', 'private', now(), now());
INSERT INTO gitlab_branches (id, branch_name, is_main, commit, scanned_commit, project_id, project_path, created_at, updated_at) VALUES
  (1, 'main', true, 'c1', 'c1', 1, 'grp/proj', now(), now()),
  (2, 'feature', false, 'f1', 'f1', 1, 'grp/proj', now(), now());
INSERT INTO gitlab_mrs (project_id, project_path, source_branch_id, source_branch, source_branch_commit,
                        target_branch_id, target_branch, target_branch_commit, mr_id, title, state, created_at, updated_at)
VALUES (1, 'grp/proj', 2, 'feature', 'f1', 1, 'main', 'c1', 7, 'Add cards', 'opened', now(), now());
INSERT INTO objects (content_hash, object_key, project_id, parser, type, name, file, props) VALUES
  (:user_hash, :user_key, 1, 'go', 'dto', 'User', '/user.go', '{"package": "users"}'),
  (:card_hash, :card_key, 1, 'go', 'dto', 'Card', '/card.go', NULL),
  (:gone_hash, :gone_key, 1, 'go', 'dto', 'Gone', '/gone.go', NULL);
INSERT INTO object_fields (content_hash, field_name, field_type, field_key, project_id) VALUES
  (:user_hash, 'email', 'string', :user_email, 1), (:user_hash, 'id', 'int', :user_id, 1),
  (:card_hash, 'card_number', 'string', :card_number, 1), (:gone_hash, 'ssn', 'string', :gone_ssn, 1);
INSERT INTO branch_objects (branch_id, object_key, content_hash, is_main, change, line, field_lines) VALUES
  (1, :user_key, :user_hash, true, NULL, 3, '{"email": 5, "id": 4}'),
  (2, :card_key, :card_hash, false, 'added', 1, '{"card_number": 2}');
INSERT INTO rules (kind, name, category, severity, target, mode, scope, version, enabled, updated_at) VALUES
  ('keyword', 'user-objects', 'identity', 'low', 'object', 'review', '{"object_re": "User", "action": "score"}', 1, true, now()),
  ('llm', 'llm', NULL, 'medium', 'field', 'review', '{}', 1, true, now());
-- the built-in keyword scoring is opt-in on a new install (migration 0028): on for these tests
UPDATE rules SET enabled = true WHERE scope ->> 'source' = 'core';
INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version, model, category, severity,
                       status, reason, first_seen_at, last_seen_at) VALUES
  ((SELECT id FROM rules WHERE name = 'llm' AND deleted_at IS NULL), :user_email, 1, :user_key, 'email', 1, 'm', 'pii', 'medium',
   'pending_review', 'an e-mail address', now() - interval '3 days', now()),
  ((SELECT id FROM rules WHERE name = 'llm' AND deleted_at IS NULL), :card_number, 1, :card_key, 'card_number', 1, 'm', 'finance', 'medium',
   'pending_review', 'a card number', now() - interval '2 days', now()),
  ((SELECT id FROM rules WHERE name = 'kw-fields'), :user_email, 1, :user_key, 'email', 1, NULL, 'pii', 'high',
   'match', NULL, now() - interval '3 days', now()),
  ((SELECT id FROM rules WHERE name = 'llm' AND deleted_at IS NULL), :gone_ssn, 1, :gone_key, 'ssn', 1, 'm', 'pii', 'high',
   'pending_review', NULL, now() - interval '30 days', now() - interval '20 days'),
  ((SELECT id FROM rules WHERE name = 'user-objects'), :user_key, 1, :user_key, NULL, 1, NULL, 'identity', 'low',
   'pending_review', NULL, now() - interval '1 day', now());
"""


@pytest.fixture
def seed(db_url):
    """Project grp/proj: User (main; fields email, id), Card (only in open MR !7; card_number),
    Gone (no branch has it any more; ssn) and five hits (presence flags set). Returns ids and keys."""
    from sqlalchemy import create_engine, text

    from discovery_common import keys

    k = {name: keys.object_key(1, "go", name) for name in ("User", "Card", "Gone")}
    params = {
        "user_key": k["User"], "card_key": k["Card"], "gone_key": k["Gone"],
        "user_hash": keys.content_hash(k["User"], {"email": "string", "id": "int"}, {"package": "users"}),
        "card_hash": keys.content_hash(k["Card"], {"card_number": "string"}, {}),
        "gone_hash": keys.content_hash(k["Gone"], {"ssn": "string"}, {}),
        "user_email": keys.field_key(k["User"], "email"), "user_id": keys.field_key(k["User"], "id"),
        "card_number": keys.field_key(k["Card"], "card_number"), "gone_ssn": keys.field_key(k["Gone"], "ssn"),
    }
    engine = create_engine(db_url)
    try:
        with engine.begin() as conn:
            conn.execute(text(SEED_SQL), params)
            rules = dict(conn.execute(text("SELECT name, id FROM rules WHERE deleted_at IS NULL")).all())
            # the scanner sets in_main / in_open_mr on every write (migration 0030); seeded rows get them here
            from discovery_common import presence
            presence.refresh(conn, project_id=1)
    finally:
        engine.dispose()

    from discovery_common.models import CORE_FIELD_RULE
    rules["core:score_tags:field"] = rules[CORE_FIELD_RULE]        # the name before migration 0028, for old tests
    llm, core, user_rule = rules["llm"], rules[CORE_FIELD_RULE], rules["user-objects"]
    return {
        "rules": rules,
        "email_llm": f"{llm}:{params['user_email']}",
        "card_llm": f"{llm}:{params['card_number']}",
        "email_core": f"{core}:{params['user_email']}",
        "ssn_llm": f"{llm}:{params['gone_ssn']}",
        "user_obj": f"{user_rule}:{params['user_key']}",
        **params,
    }


@pytest.fixture
def sql(db_url):
    """``sql("SELECT ...", **params)`` -> rows, on the test database."""
    from sqlalchemy import create_engine, text
    engine = create_engine(db_url)

    def run(statement, **params):
        with engine.begin() as conn:
            result = conn.execute(text(statement), params)
            return result.all() if result.returns_rows else result.rowcount

    yield run
    engine.dispose()
