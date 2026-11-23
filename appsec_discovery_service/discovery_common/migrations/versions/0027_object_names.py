"""Object names without the object type: the parsers no longer prefix ``object_name`` with the type (``Rpc
/pkg.Svc/M`` -> ``/pkg.Svc/M``, ``Mutation X.f`` -> ``X.f``, ``Route /p (GET)`` -> ``GET /p``, ``Struct dto X`` ->
``X``, ``Table public.x`` -> ``public.x``, ``Resource t.n`` -> ``t.n``, ``Virtual machine vm`` -> ``vm``, python routes
``Fastapi route / calls Root handler (GET)`` -> ``GET / (root)``, JS ``JS GQL Resolver me in query Q`` -> ``Q.me``;
the identities - object keys, content hashes - are unchanged, ``tests/fixtures/identity_pins.json`` pins both forms).

``objects`` is keyed by the content hash, which does not contain the name: a stored version keeps its old name when
the next scan finds it again (``ON CONFLICT DO NOTHING``; the scanner now also updates the name of a stored version).
So the names are rewritten here, per parser and type, exactly as the parsers make them now (``new_name``). The LLM
hits record the object name in ``names_hash`` (object name + field names): it is recomputed with the new name where
it was the hash of the old one (``rule_hits`` and ``hit_verdicts``; the history triggers are off meanwhile), so the
rename asks nothing again - a hit that was stale stays stale.

Rules matching on the old names (keyword ``object_re``, LLM ``object_re``, legacy ``object`` patterns starting with a
type word: ``Route``, ``Struct dto``, ``Table``, ``Rpc``, ``Mutation``, ``Query``, ``Virtual machine``, ...) are NOT
rewritten: they are listed in the migration log (warning) to be fixed by hand (README changelog).

Downgrade: nothing is restored (the previous parsers write the old names for versions they store anew).

Revision ID: 0027_object_names
Revises: 0026_llm_rollouts
Create Date: 2026-11-22
"""
import logging
import re
from typing import Optional

import sqlalchemy as sa
from alembic import context, op

revision = "0027_object_names"
down_revision = "0026_llm_rollouts"
branch_labels = None
depends_on = None

logger = logging.getLogger("alembic.runtime.migration")

BATCH = 5000

PYTHON_ROUTE = re.compile(r"^\S+ route (?P<path>.*) calls (?P<func>.+) handler(?: \((?P<method>[A-Za-z]+)\))?$")
DTO = re.compile(r"^\S+ (?P<type>\S+) (?P<name>.+)$")
GQL = re.compile(r"^(?:Mutation|Query|Subscription) (?P<name>.+)$")
JS_GQL = re.compile(r"^JS GQL Resolver (?P<resolver>\S+) in \S+ (?P<request>.+)$")
RPC = re.compile(r"^Rpc (?P<name>.+)$")
SWAGGER = re.compile(r"^Route (?P<path>.+) \((?P<method>[A-Za-z]+)\)$")
TABLE = re.compile(r"^Table (?P<name>.+)$")
TERRAFORM = re.compile(r"^(?:Resource|Data|Module|Output|Provider|Variable|Virtual machine) (?P<name>.+)$")

# the old type words a rule pattern may still look for
OLD_WORDS = re.compile(r"(Struct dto|Javax dto|Route|Table |Rpc |Mutation|Query |Virtual machine|Resource |"
                       r"Data |Module |Variable |Output |Provider |JS GQL|\broute .* calls|handler| dto )",
                       re.IGNORECASE)


def new_name(parser: Optional[str], type_: Optional[str], name: Optional[str], props: Optional[dict]) -> Optional[str]:
    """The name the current parsers give an object stored under ``name`` (None: no change)."""
    if not name:
        return None
    props = props or {}
    m = None
    if parser == "python" and type_ == "route":
        m = PYTHON_ROUTE.match(name)
        if m:
            path = props.get("path") or m.group("path")
            func = props.get("func") or m.group("func").lower()
            method = props.get("method") or m.group("method")
            return f"{method.upper()} {path} ({func})" if method else f"{path} ({func})"
    elif parser in ("golang", "java", "python"):
        m = DTO.match(name)
        if m and m.group("type") == type_:
            return m.group("name")
    elif parser == "graphql":
        m = GQL.match(name)
        if m:
            return m.group("name")
    elif parser == "javascript":
        m = JS_GQL.match(name)
        if m:
            return f"{m.group('request')}.{m.group('resolver')}"
    elif parser == "protobuf":
        m = RPC.match(name)
        if m:
            return m.group("name")
    elif parser == "swagger":
        m = SWAGGER.match(name)
        if m:
            return f"{m.group('method').upper()} {m.group('path')}"
    elif parser in ("migrations", "db"):
        m = TABLE.match(name)
        if m:
            return m.group("name")
    elif parser == "terraform":
        m = TERRAFORM.match(name)
        if m:
            return m.group("name")
    return None


NAMES_SQL = """ARRAY(SELECT f.field_name FROM object_fields f WHERE f.content_hash = r.content_hash)"""


def _rehash(table: str) -> None:
    op.execute(f"""
        UPDATE {table} h SET names_hash = llm_names_hash(r.new_name, {NAMES_SQL})
        FROM renamed_objects r
        WHERE h.object_key = r.object_key AND h.field_name IS NULL AND h.names_hash IS NOT NULL
          AND h.names_hash = llm_names_hash(r.old_name, {NAMES_SQL})""")
    op.execute(f"""
        UPDATE {table} h SET names_hash = llm_names_hash(r.new_name, ARRAY[h.field_name])
        FROM renamed_objects r
        WHERE h.object_key = r.object_key AND h.field_name IS NOT NULL AND h.names_hash IS NOT NULL
          AND h.names_hash = llm_names_hash(r.old_name, ARRAY[h.field_name])""")


def upgrade() -> None:
    if context.is_offline_mode():           # the names are computed in Python from the stored rows
        op.execute("-- 0027_object_names: run this revision online (python -m discovery_common.migrate) to rename "
                   "the stored object versions")
        return
    conn = op.get_bind()
    renamed = []
    last = None
    while True:
        rows = conn.execute(sa.text(
            "SELECT content_hash, object_key, parser, type, name, props FROM objects "
            "WHERE (CAST(:last AS uuid) IS NULL OR content_hash > CAST(:last AS uuid)) ORDER BY content_hash LIMIT :n"),
            {"last": last, "n": BATCH}).all()
        if not rows:
            break
        last = str(rows[-1].content_hash)
        for r in rows:
            name = new_name(r.parser, r.type, r.name, r.props if isinstance(r.props, dict) else None)
            if name is not None and name != r.name:
                renamed.append({"h": str(r.content_hash), "k": str(r.object_key), "old": r.name, "new": name})
    op.execute("CREATE TEMP TABLE renamed_objects (content_hash uuid, object_key uuid, old_name text, new_name text) "
               "ON COMMIT DROP")
    for i in range(0, len(renamed), BATCH):
        conn.execute(sa.text("INSERT INTO renamed_objects VALUES (CAST(:h AS uuid), CAST(:k AS uuid), :old, :new)"),
                     renamed[i:i + BATCH])
    if renamed:
        op.execute("UPDATE objects o SET name = r.new_name FROM renamed_objects r WHERE o.content_hash = r.content_hash")
        op.execute("ALTER TABLE rule_hits DISABLE TRIGGER hit_verdicts_update")
        _rehash("rule_hits")
        _rehash("hit_verdicts")
        op.execute("ALTER TABLE rule_hits ENABLE TRIGGER hit_verdicts_update")
    op.execute("DROP TABLE IF EXISTS renamed_objects")
    logger.info(f"0027_object_names: {len(renamed)} stored object versions renamed (type prefix dropped)")

    for rule in conn.execute(sa.text(
            "SELECT id, kind, name, scope FROM rules WHERE deleted_at IS NULL AND kind IN ('keyword', 'llm') "
            "ORDER BY id")).all():
        scope = rule.scope or {}
        for key in ("object_re", "object"):
            value = scope.get(key)
            if isinstance(value, str) and OLD_WORDS.search(value):
                logger.warning(f"0027_object_names: {rule.kind} rule {rule.id} ({rule.name}) scope.{key} = {value!r} "
                               f"looks for an old object name with its type word: object names have no type prefix "
                               f"any more (use object_type_re) - fix the rule by hand")


def downgrade() -> None:
    """The old names are not restored (see the module doc)."""
