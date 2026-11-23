"""Collector example: tables / views and their columns of a SQL server -> AppSec Discovery.

Reads ``information_schema`` (PostgreSQL, MS SQL Server, MySQL, ...) through SQLAlchemy and
pushes one external project state: ``POST /ingest`` for small schemas, an upload session in
chunks for large ones. Run it on a schedule with a service token (``POST /tokens``, scope
``ingest`` on ``external/<team>``); an unchanged schema is a no-op on the server.

    export DISCOVERY_TOKEN=adt_...                                   # or from a secret store
    export DISCOVERY_DB_URL='postgresql://reader:...@db01:5432/billing'
    python sql_schema.py --api http://discovery.local/api \\
        --project external/payments/db01-billing --parser postgres

The database URL (with its password) comes from ``DISCOVERY_DB_URL`` or ``--url-file`` (a
file readable only by the collector's user); ``--url`` on the command line is visible to
every user of the host (``ps``, ``/proc/<pid>/cmdline``) and in shell / cron history, so
give it there only without a password (e.g. a ``.pgpass`` / Kerberos login).

Object identity is (parser, file, type, name): ``file`` = ``<host>/<database>``, ``name`` =
``<schema>.<table>``; keep the URL host / database spelling stable between runs.
"""

import argparse
import json
import os
import sys
import urllib.request
from collections import OrderedDict
from typing import Callable, Dict, Iterable, List, Optional

COLUMNS_SQL = """
    SELECT c.table_schema, c.table_name, c.column_name, c.data_type, c.character_maximum_length,
           c.is_nullable, c.ordinal_position, t.table_type
    FROM information_schema.columns c
    JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name
    ORDER BY c.table_schema, c.table_name, c.ordinal_position
"""
SYSTEM_SCHEMAS = {"information_schema", "pg_catalog", "pg_toast", "sys", "mysql", "performance_schema"}
# The API takes at most 50000 objects / 500000 fields (and a 64 MB body) per request; stay
# well below: a single POST /ingest only when both counts are small, else an upload session
# in chunks bounded by objects AND fields (wide schemas).
SINGLE_PUSH_MAX = 20_000        # objects; above: an upload session
SINGLE_PUSH_MAX_FIELDS = 200_000
CHUNK = 5_000                   # objects per chunk
CHUNK_FIELDS = 200_000          # fields per chunk


def column_type(data_type: Optional[str], max_length) -> str:
    if data_type and max_length not in (None, -1) and str(max_length) != "-1":
        return f"{data_type}({max_length})"
    return data_type or ""


def build_objects(rows: Iterable[Dict], host: str, database: str, exclude_schemas=SYSTEM_SCHEMAS) -> List[Dict]:
    """``information_schema`` rows -> ingest objects (one per table / view, columns as fields)."""
    tables: "OrderedDict[tuple, Dict]" = OrderedDict()
    for r in rows:
        schema, table = r["table_schema"], r["table_name"]
        if schema in exclude_schemas or schema.startswith("pg_temp"):
            continue
        obj = tables.get((schema, table))
        if obj is None:
            kind = "view" if "VIEW" in str(r.get("table_type") or "").upper() else "table"
            obj = tables[(schema, table)] = {
                "name": f"{schema}.{table}", "type": kind, "file": f"{host}/{database}",
                "props": {"server": host, "database": database, "schema": schema, "table_type": r.get("table_type")},
                "fields": [],
            }
        obj["fields"].append({"name": r["column_name"], "type": column_type(r["data_type"], r["character_maximum_length"]),
                              "line": int(r["ordinal_position"] or 0)})
        obj["props"].setdefault("nullable_columns", 0)
        if str(r.get("is_nullable")).upper() == "YES":
            obj["props"]["nullable_columns"] += 1
    return list(tables.values())


def collect(url: str) -> List[Dict]:
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url
    parsed = make_url(url)
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            rows = [dict(r._mapping) for r in conn.execute(text(COLUMNS_SQL))]
    finally:
        engine.dispose()
    return build_objects(rows, parsed.host or "localhost", parsed.database or "")


def http_client(api: str, token: str) -> Callable[[str, str, Optional[Dict]], Dict]:
    def call(method: str, path: str, body: Optional[Dict] = None) -> Dict:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(api.rstrip("/") + path, data=data, method=method, headers={
            "Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=300) as response:
            return json.loads(response.read() or b"{}")
    return call


def _fields(obj: Dict) -> int:
    return len(obj.get("fields") or [])


def chunks(objects: List[Dict], max_objects: int, max_fields: int) -> Iterable[List[Dict]]:
    """Consecutive slices with at most ``max_objects`` objects and ``max_fields`` fields (an
    object wider than ``max_fields`` goes alone: the API caps one object's fields itself)."""
    chunk: List[Dict] = []
    fields = 0
    for obj in objects:
        n = _fields(obj)
        if chunk and (len(chunk) >= max_objects or fields + n > max_fields):
            yield chunk
            chunk, fields = [], 0
        chunk.append(obj)
        fields += n
    if chunk:
        yield chunk


def push(call, project: str, parser: str, objects: List[Dict], snapshot: Optional[str] = None,
         llm: bool = False) -> Dict:
    """One request for a small state, an upload session for a large one (many objects or
    many fields)."""
    target = {"project": project, "parser": parser, "llm": llm, **({"snapshot": snapshot} if snapshot else {})}
    if len(objects) <= SINGLE_PUSH_MAX and sum(_fields(o) for o in objects) <= SINGLE_PUSH_MAX_FIELDS:
        return call("POST", "/ingest", {**target, "objects": objects})
    session = call("POST", "/ingest/sessions", target)
    sid = session["session_id"]
    try:
        for seq, chunk in enumerate(chunks(objects, CHUNK, CHUNK_FIELDS)):
            call("PUT", f"/ingest/sessions/{sid}/chunks/{seq}", {"objects": chunk})
        return call("POST", f"/ingest/sessions/{sid}/commit")
    except Exception:
        call("DELETE", f"/ingest/sessions/{sid}")
        raise


URL_ENV = "DISCOVERY_DB_URL"


def database_url(args, environ=os.environ) -> Optional[str]:
    """The database URL: ``--url-file``, else ``--url`` (warned about when it carries a
    password: argv is public on the host), else ``DISCOVERY_DB_URL``."""
    if args.url_file:
        with open(args.url_file, encoding="utf-8") as f:
            return f.read().strip() or None
    if args.url:
        from sqlalchemy.engine import make_url
        try:
            has_password = make_url(args.url).password is not None
        except Exception:       # let collect() report a malformed URL
            has_password = False
        if has_password:
            print(f"warning: the --url password is visible to other users of this host (ps, /proc) and in shell "
                  f"history: pass the URL in {URL_ENV} or --url-file instead", file=sys.stderr)
        return args.url
    return (environ.get(URL_ENV) or "").strip() or None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--url", default=None,
                    help=f"SQLAlchemy URL of the database (read-only user) WITHOUT a password; "
                         f"with one use {URL_ENV} or --url-file")
    ap.add_argument("--url-file", default=None, help="file holding the SQLAlchemy URL (with its password)")
    ap.add_argument("--api", required=True, help="AppSec Discovery API base, e.g. http://host/api")
    ap.add_argument("--project", required=True, help="external/<team>/<source>")
    ap.add_argument("--parser", required=True, help="your parser name, e.g. postgres, mssql")
    ap.add_argument("--snapshot", default=None)
    ap.add_argument("--llm", action="store_true", help="also run the LLM rules after the push")
    ap.add_argument("--dry-run", action="store_true", help="print the objects instead of pushing")
    args = ap.parse_args(argv)
    url = database_url(args)
    if not url:
        print(f"set {URL_ENV} (or --url-file / --url): the SQLAlchemy URL of the database", file=sys.stderr)
        return 2
    objects = collect(url)
    if args.dry_run:
        json.dump({"objects": objects}, sys.stdout, indent=2, default=str)
        return 0
    token = os.environ.get("DISCOVERY_TOKEN")
    if not token:
        print("set DISCOVERY_TOKEN (a service token, POST /tokens)", file=sys.stderr)
        return 2
    result = push(http_client(args.api, token), args.project, args.parser, objects, args.snapshot, args.llm)
    print(json.dumps(result, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
