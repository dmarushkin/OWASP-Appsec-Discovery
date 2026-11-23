"""EXPLAIN checks on a synthetic inventory: "main only" and "open (unmerged) MRs only"
selections, the review queue, the scan-flow queries and GC are served by the intended
indexes, without sequential scans of the big tables.

Postgres only (TEST_DATABASE_URL). Size: PLAN_TEST_PROJECTS projects (default 100) x 600
objects x 8 fields (~480k fields) plus 2 open MRs per project. The same checks pass with
the 300-project data set of the storage design benchmark."""

import os
import re
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from discovery_common import testing

SEED = (Path(__file__).parent / "bench_seed.sql").read_text()
SCANNER_DIR = Path(__file__).resolve().parents[2] / "discovery_scanner"
BIG_TABLES = {"objects", "object_fields", "branch_objects", "rule_hits"}


@pytest.fixture(scope="module")
def plans_db():
    if not testing.admin_url():
        pytest.skip(f"{testing.ENV} is not set (Postgres integration test)")
    with testing.fresh_database("plans") as url:
        testing.migrate(url)
        engine = create_engine(url)
        with engine.begin() as conn:
            conn.execute(text(SEED), {"projects": int(os.environ.get("PLAN_TEST_PROJECTS", "100"))})
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("VACUUM ANALYZE"))
        try:
            yield engine
        finally:
            engine.dispose()


def _walk(node):
    yield node
    for child in node.get("Plans", []):
        yield from _walk(child)


def plan(engine, statement, params, enable_seqscan=True):
    sql = statement.text if hasattr(statement, "text") else statement
    with engine.connect() as conn:
        if not enable_seqscan:
            conn.execute(text("SET LOCAL enable_seqscan = off"))
        raw = conn.execute(text("EXPLAIN (FORMAT JSON) " + sql), params).scalar()
    nodes = list(_walk(raw[0]["Plan"]))
    indexes = {n["Index Name"] for n in nodes if "Index Name" in n}
    seq = {n["Relation Name"] for n in nodes if n["Node Type"] == "Seq Scan"}
    return indexes, seq


def ids(engine):
    with engine.connect() as conn:
        main = conn.execute(text("SELECT id FROM gitlab_branches WHERE project_id = 42 AND is_main")).scalar()
        feature = conn.execute(text("SELECT source_branch_id FROM gitlab_mrs WHERE project_id = 42 AND state = 'opened' "
                                    "ORDER BY mr_id LIMIT 1")).scalar()
    return main, feature


MAIN_ONLY = {"bo_content"}                       # semi-join "is this version in some main"
OPEN_MR_ONLY = {"bo_mr_rows", "mrs_open", "mrs_source", "mrs_target_open"}

# name: (sql, params, required indexes (all), scope indexes (at least one), small_table)
CASES = {
    # main only
    "main: field name ILIKE, all projects": (
        testing.MAIN_FIELDS_SQL, {"name_like": "%passport%", "limit": 100}, set(), MAIN_ONLY),
    "main: field name ILIKE, no match": (
        testing.MAIN_FIELDS_SQL, {"name_like": "%zzzq%", "limit": 100}, {"fields_name_trgm"}, MAIN_ONLY),
    "main: exact field name, one project": (
        testing.MAIN_PROJECT_FIELDS_SQL, {"project_id": 42, "name_eq": "email3", "name_like": None, "limit": 100},
        {"fields_proj_name"}, MAIN_ONLY),
    "main: field pattern, one project": (
        testing.MAIN_PROJECT_FIELDS_SQL, {"project_id": 42, "name_eq": None, "name_like": "%passport%", "limit": 100},
        {"fields_proj_name"}, MAIN_ONLY),
    # open (unmerged) MRs only
    "open MRs: field name ILIKE, all projects": (
        # common pattern + ORDER BY/LIMIT: the planner may walk the MRs in order instead
        testing.OPEN_MR_FIELDS_SQL, {"name_like": "%passport%", "limit": 100}, set(),
        OPEN_MR_ONLY | {"gitlab_mrs_project_id_mr_id_key"}),
    "open MRs: field name ILIKE, no match": (
        testing.OPEN_MR_FIELDS_SQL, {"name_like": "%zzzq%", "limit": 100}, {"fields_name_trgm"}, OPEN_MR_ONLY),
    "open MRs: fields of one project": (
        testing.OPEN_MR_PROJECT_FIELDS_SQL, {"project_id": 42, "name_eq": None, "name_like": None, "limit": 100},
        set(), OPEN_MR_ONLY),
    "open MRs: delta of one project": (
        testing.OPEN_MR_DELTA_SQL, {"project_id": 42}, {"branch_objects_pkey"}, OPEN_MR_ONLY),
    # review queue
    "review queue of a project": (
        testing.REVIEW_QUEUE_SQL, {"project_id": 42, "status": "pending_review", "limit": 100}, {"hits_queue"}, MAIN_ONLY),
}

# Small inventory tables: the planner rightly prefers a seq scan on a few hundred rows, so
# these only check that the (partial) index can serve the query.
SMALL_TABLE_CASES = {
    "the main branch of a project": (
        "SELECT id FROM gitlab_branches WHERE project_id = :p AND is_main", {"p": 42}, "branches_one_main"),
    "open MRs of a project": (
        "SELECT id FROM gitlab_mrs WHERE project_id = :p AND state = 'opened'", {"p": 42}, "mrs_open"),
    "open MRs targeting a branch (prune after a main scan)": (
        "SELECT id FROM gitlab_mrs WHERE target_branch_id = :t AND state = 'opened'", {"t": 42}, "mrs_target_open"),
    "MRs of a source branch (release on close)": (
        "SELECT id FROM gitlab_mrs WHERE source_branch_id = :s", {"s": 42}, "mrs_source"),
}


@pytest.mark.parametrize("name", list(CASES))
def test_query_plan_uses_indexes(plans_db, name):
    statement, params, required, scope = CASES[name]
    indexes, seq = plan(plans_db, statement, params)
    assert required <= indexes, f"{name}: indexes used {sorted(indexes)}"
    assert scope & indexes, f"{name}: no scope index ({sorted(scope)}) in {sorted(indexes)}"
    assert not (seq & BIG_TABLES), f"{name}: sequential scan on {sorted(seq & BIG_TABLES)}"


@pytest.mark.parametrize("name", list(SMALL_TABLE_CASES))
def test_small_table_index_is_usable(plans_db, name):
    statement, params, index = SMALL_TABLE_CASES[name]
    indexes, _ = plan(plans_db, statement, params, enable_seqscan=False)
    assert index in indexes, f"{name}: indexes used {sorted(indexes)}"


def test_gc_orphan_scan_uses_main_index_or_hash_anti_join(plans_db):
    indexes, seq = plan(plans_db, "SELECT o.content_hash FROM objects o WHERE NOT EXISTS "
                                  "(SELECT 1 FROM branch_objects b WHERE b.content_hash = o.content_hash) LIMIT 5000", {})
    # a whole-table anti join: either an index anti join on bo_content or one hash anti join
    assert "bo_content" in indexes or seq == {"objects", "branch_objects"}


def _scanner_sql(name):
    """Scan-flow SQL of the scanner's db_service, read from the source (importing it needs
    the scanner's settings)."""
    source = (SCANNER_DIR / "services" / "db_service.py").read_text()
    match = re.search(rf'{name} = text\("""(.*?)"""\)', source, re.S)
    assert match, name
    return match.group(1)


@pytest.mark.parametrize("name, expected", [
    ("LLM_CANDIDATES_SQL", {"branch_objects_pkey"}),
    ("LLM_OBJECT_CANDIDATES_SQL", {"branch_objects_pkey"}),
])
def test_scan_flow_plans(plans_db, name, expected):
    main, feature = ids(plans_db)
    with plans_db.connect() as conn:
        llm_rule = conn.execute(text("SELECT id FROM rules WHERE name = 'llm'")).scalar()
    params = {"rule_id": llm_rule, "rule_version": 1, "pinned_pv": "classifier3", "code_pv": "classifier3",
              "pinned_model": "m", "code_model": "m", "migration": True, "branch_id": feature, "source": feature,
              "target": main}
    indexes, seq = plan(plans_db, _scanner_sql(name), params)
    assert expected <= indexes, f"{name}: indexes used {sorted(indexes)}"
    assert not (seq & BIG_TABLES), f"{name}: sequential scan on {sorted(seq & BIG_TABLES)}"
