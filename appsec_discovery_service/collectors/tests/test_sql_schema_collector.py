"""The SQL schema collector example: rows -> objects, push modes, a real information_schema."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sql_schema  # noqa: E402

ROWS = [
    {"table_schema": "public", "table_name": "clients", "column_name": "id", "data_type": "integer",
     "character_maximum_length": None, "is_nullable": "NO", "ordinal_position": 1, "table_type": "BASE TABLE"},
    {"table_schema": "public", "table_name": "clients", "column_name": "last_name", "data_type": "character varying",
     "character_maximum_length": 100, "is_nullable": "YES", "ordinal_position": 2, "table_type": "BASE TABLE"},
    {"table_schema": "public", "table_name": "v_clients", "column_name": "phone", "data_type": "text",
     "character_maximum_length": None, "is_nullable": "YES", "ordinal_position": 1, "table_type": "VIEW"},
    {"table_schema": "pg_catalog", "table_name": "pg_class", "column_name": "oid", "data_type": "oid",
     "character_maximum_length": None, "is_nullable": "NO", "ordinal_position": 1, "table_type": "BASE TABLE"},
]


def test_build_objects():
    objects = sql_schema.build_objects(ROWS, "db01", "billing")
    assert [(o["name"], o["type"], o["file"]) for o in objects] == [
        ("public.clients", "table", "db01/billing"), ("public.v_clients", "view", "db01/billing")]
    assert objects[0]["fields"] == [{"name": "id", "type": "integer", "line": 1},
                                    {"name": "last_name", "type": "character varying(100)", "line": 2}]
    assert objects[0]["props"]["nullable_columns"] == 1


def test_push_single_and_session(monkeypatch):
    calls = []

    def call(method, path, body=None):
        calls.append((method, path, len((body or {}).get("objects") or [])))
        return {"session_id": 9} if path == "/ingest/sessions" else {"ok": True}

    sql_schema.push(call, "external/t/db", "postgres", [{"name": "a"}] * 3)
    assert calls == [("POST", "/ingest", 3)]
    calls.clear()
    monkeypatch.setattr(sql_schema, "SINGLE_PUSH_MAX", 2)
    monkeypatch.setattr(sql_schema, "CHUNK", 2)
    sql_schema.push(call, "external/t/db", "postgres", [{"name": "a"}] * 5)
    assert calls == [("POST", "/ingest/sessions", 0), ("PUT", "/ingest/sessions/9/chunks/0", 2),
                     ("PUT", "/ingest/sessions/9/chunks/1", 2), ("PUT", "/ingest/sessions/9/chunks/2", 1),
                     ("POST", "/ingest/sessions/9/commit", 0)]


def test_collect_from_a_real_postgres():
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL is not set")
    from sqlalchemy import create_engine, text
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE IF NOT EXISTS collector_probe (id int, passport_number varchar(20))"))
    try:
        objects = {o["name"]: o for o in sql_schema.collect(url)}
        probe = objects["public.collector_probe"]
        assert [f["name"] for f in probe["fields"]] == ["id", "passport_number"]
        assert probe["fields"][1]["type"] == "character varying(20)"
    finally:
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE collector_probe"))
        engine.dispose()


def test_push_splits_wide_schemas_by_fields(monkeypatch):
    """20000 tables x 26 columns = 520000 fields: over the API's 500000 per request, so an
    upload session, chunks bounded by fields too (P5)."""
    calls = []

    def call(method, path, body=None):
        objects = (body or {}).get("objects") or []
        calls.append((method, path, len(objects), sum(len(o["fields"]) for o in objects)))
        return {"session_id": 9} if path == "/ingest/sessions" else {"ok": True}

    wide = [{"name": f"t{i}", "fields": [{"name": f"c{j}"} for j in range(26)]} for i in range(20_000)]
    sql_schema.push(call, "external/t/db", "postgres", wide)
    assert calls[0][:2] == ("POST", "/ingest/sessions") and calls[-1][:2] == ("POST", "/ingest/sessions/9/commit")
    chunks = calls[1:-1]
    assert sum(c[2] for c in chunks) == 20_000
    assert all(c[2] <= sql_schema.CHUNK and c[3] <= sql_schema.CHUNK_FIELDS for c in chunks)

    calls.clear()
    very_wide = [{"name": f"w{i}", "fields": [{"name": f"c{j}"} for j in range(1000)]} for i in range(450)]
    sql_schema.push(call, "external/t/db", "postgres", very_wide)       # 450 objects, 450000 fields
    assert calls[0][:2] == ("POST", "/ingest/sessions")
    assert max(c[3] for c in calls[1:-1]) <= sql_schema.CHUNK_FIELDS

    assert list(sql_schema.chunks([{"fields": [1] * 10}] * 3, 5, 15)) == [[{"fields": [1] * 10}]] * 3
    assert len(list(sql_schema.chunks([{"fields": [1] * 50}], 5, 15))) == 1            # too wide: alone


def test_database_url_prefers_env_or_file_and_warns_about_argv(tmp_path, capsys, monkeypatch):
    import argparse

    def args(**kw):
        return argparse.Namespace(**{"url": None, "url_file": None, **kw})

    env = {"DISCOVERY_DB_URL": "postgresql://reader:pw@db01/billing"}
    assert sql_schema.database_url(args(), env) == env["DISCOVERY_DB_URL"]
    assert capsys.readouterr().err == ""
    secret = tmp_path / "dsn"
    secret.write_text("postgresql://reader:pw@db02/billing\n")
    assert sql_schema.database_url(args(url_file=str(secret)), env) == "postgresql://reader:pw@db02/billing"
    assert sql_schema.database_url(args(url="postgresql://reader@db03/billing"), {}) == "postgresql://reader@db03/billing"
    assert capsys.readouterr().err == ""                                   # no password: no warning
    sql_schema.database_url(args(url="postgresql://reader:pw@db03/billing"), {})
    err = capsys.readouterr().err
    assert "DISCOVERY_DB_URL" in err and ":pw@" not in err                # the secret is never echoed
    assert sql_schema.database_url(args(), {}) is None
    monkeypatch.delenv("DISCOVERY_DB_URL", raising=False)
    assert sql_schema.main(["--api", "http://x/api", "--project", "external/t/db", "--parser", "pg"]) == 2
