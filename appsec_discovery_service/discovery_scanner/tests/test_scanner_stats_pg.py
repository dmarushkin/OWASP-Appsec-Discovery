"""Statistics snapshots (``discovery_common.stats``, the ``stats_refresh`` job) against a real Postgres: every
snapshot is written with the shape the API functions return, is plain JSON, and the job health snapshot carries the
day's escalations and the scanner's throughput limits."""

import json
from datetime import datetime, timezone

from sqlalchemy import text

from test_scanner_llm_tiers_pg import setup


def q(sql, **params):
    from discovery_common import db
    with db.get_engine().begin() as conn:
        result = conn.execute(text(sql), params)
        return result.all() if result.returns_rows else result.rowcount


OVERVIEW_KEYS = {"project_id", "projects", "objects_by_type", "hits_by_status", "confirmed_by_category",
                 "matches_by_project", "filters", "pending_by_rule", "open_mrs", "stale_main_branches", "failed_jobs"}
JOB_HEALTH_KEYS = {"now", "kinds", "totals", "workers", "llm", "scans"}
KIND_KEYS = {"pending", "retrying", "running", "failed", "done_1h", "done_24h", "failed_24h", "skipped_24h",
             "oldest_pending_s", "oldest_pending_job", "longest_running_s", "longest_running_job", "scheduled",
             "last_done_at", "typical_run_s", "typical_wait_s", "eta_s"}
SCAN_PROGRESS_KEYS = {"main", "by_scan_mode", "mrs", "external", "queue", "last_projects_sync"}
LLM_PROGRESS_KEYS = {"prompt_version", "rules", "main", "mrs", "queue", "last_computed_at"}
QUALITY_KEYS = {"agreement_min", "min_samples", "totals", "backlog", "rules"}
QUALITY_RULE_KEYS = {"rule_id", "rule_name", "category", "target", "version", "enabled", "qa", "escalation_rate",
                     "service_verdicts", "service_unsure", "escalations_30d", "escalations_decided_30d", "asked_human_30d",
                     "questions_open", "oldest_question_s", "harness_decisions", "backlog", "escalation_pending",
                     "last_verified_at", "needs_improvement", "health"}


def test_stats_refresh_writes_every_snapshot_as_plain_json(pg_scanner, monkeypatch):
    from discovery_common import db, jobs, stats
    env = setup(pg_scanner, monkeypatch)                 # a project, a snapshot, two LLM rules with verdicts
    pg_scanner.setenv(LLM_RATE_PER_MIN="120", LLM_CONCURRENCY="3", STATS_REFRESH_S="60")
    stats_service = pg_scanner.load("services.stats_service")

    # a finished job with started_at: typical_run_s is computed from it (contract: job_health ETA / run times)
    job_id = jobs.enqueue("scan_branch", {"branch_id": env.branch.id}, "scan_branch:x")
    jobs.claim("scan-0", kinds=["scan_branch"], lease_seconds=None)
    q("UPDATE jobs SET started_at = now() - interval '42 seconds' WHERE id = :id", id=job_id)
    jobs.complete(job_id, "scan-0")

    timings = stats_service.refresh_all(pg_scanner.settings())
    assert set(timings) == set(stats.SNAPSHOT_NAMES) and all(t >= 0 for t in timings.values())
    rows = {name: (data, at) for name, data, at in q("SELECT name, data, computed_at FROM stats_snapshots")}
    assert set(rows) == set(stats.SNAPSHOT_NAMES)
    assert all(isinstance(at, datetime) for _, at in rows.values())
    json.dumps({name: data for name, (data, _) in rows.items()})          # plain JSON (jsonb round trip)

    overview = rows["overview"][0]
    assert set(overview) == OVERVIEW_KEYS and overview["project_id"] is None and overview["filters"] is None
    assert {r["status"] for r in overview["hits_by_status"]} >= {"match", "no_match", "need_more_info"}
    assert overview["matches_by_project"][0]["project_path"] == "grp/proj"

    health = rows["job_health"][0]
    assert set(health) == JOB_HEALTH_KEYS | {"escalations", "limits"}
    assert set(health["kinds"]["scan_branch"]) == KIND_KEYS
    assert health["kinds"]["scan_branch"]["typical_run_s"] == 42 and health["kinds"]["scan_branch"]["done_1h"] == 1
    assert isinstance(health["now"], str) and health["now"].startswith(str(datetime.now(timezone.utc).year))
    assert health["escalations"] == {"daily_max": 2000, "items_today": 0, "overflow_today": 0, "by_rule": {}}
    assert health["limits"]["llm_concurrency"] == 3 and health["limits"]["llm_rate_per_min"] == 120
    assert health["limits"]["sync_workers"] == 2 and health["limits"]["escalation_daily_max"] == 2000

    scan = rows["scan_progress"][0]
    assert set(scan) == SCAN_PROGRESS_KEYS and scan["main"]["projects"] == 1 and scan["main"]["scanned_current"] == 1
    assert set(scan["by_scan_mode"]) == {"rules", "inventory"}

    llm = rows["llm_progress"][0]
    assert set(llm) == LLM_PROGRESS_KEYS and llm["main"]["projects"] == 1
    assert {r["name"] for r in llm["rules"]} == {"person", "contacts"}

    quality = rows["llm_quality"][0]
    assert set(quality) == QUALITY_KEYS and quality["agreement_min"] == 0.9 and quality["min_samples"] == 30
    assert all(set(r) == QUALITY_RULE_KEYS for r in quality["rules"])
    assert {r["rule_name"] for r in quality["rules"]} >= {"person", "contacts"}       # every LLM rule, disabled ones too
    assert set(quality["backlog"]) == {"total", "pending", "leased", "answered", "by_sample"}
    assert set(quality["totals"]) == {"samples", "samples_30d", "questions_open", "harness_decisions", "escalations_30d",
                                      "needs_improvement", "oldest_question_s", "agreement", "agreement_30d"}

    aggregate = rows["hits_aggregate"][0]
    assert aggregate["by"] == list(stats.HITS_AGGREGATE_BY)
    assert sum(r["n"] for r in aggregate["rows"]) == q("SELECT count(*) FROM rule_hits")[0][0]
    marks = [r for r in aggregate["rows"] if r["field_mark"]]
    assert marks and all(r["rule_id"] == env.rules["person"] for r in marks)      # field marks of the object rule
    assert all(set(r) == set(stats.HITS_AGGREGATE_BY) | {"n"} for r in aggregate["rows"])

    # read back while fresh, not when stale
    with db.get_engine().connect() as conn:
        assert stats.read_snapshot(conn, "overview", max_age_s=120)["data"] == overview
        assert stats.read_snapshot(conn, "overview", max_age_s=0) is None
        assert stats.read_snapshot(conn, "nothing") is None

    # the job handler writes its timings into the progress
    handlers = pg_scanner.load("services.job_handlers")
    refresh_job = jobs.enqueue("stats_refresh", {}, "stats_refresh")
    handlers.stats_refresh_job(jobs.claim("control", kinds=["stats_refresh"], lease_seconds=None))
    assert q("SELECT progress ->> 'phase', (progress -> 'seconds') ? 'overview' FROM jobs WHERE id = :id",
             id=refresh_job) == [("done", True)]
