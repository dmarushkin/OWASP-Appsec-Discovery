"""Coverage of the LLM rules (table ``llm_coverage``, migration 0017; read by ``GET /llm_progress``).

Counting the candidates of every rule over every snapshot on each UI request is too expensive
(hundreds of thousands of fields), so the scanner records, per (branch, LLM rule), what the
rule has answered of the branch's snapshot (a main branch's full snapshot, an MR source
branch's delta) when it already looks at that snapshot:

* ``candidates_total``: the subjects the rule asks about when nothing is answered - the same
  selection as a run (``scan_service.llm_rule_batch`` + the model code): objects for object
  rules, fields in the rule's scope for field rules, and for the built-in classifier (a field
  rule without category) only the fields it sends to the model (``llm_eligible_field``). 0 when
  the rule's ``project_re`` does not match the project.
* ``answered``: those with a current verdict (neither ``lifecycle.FRESH_COND`` nor ``MIGRATION_COND``): a
  verdict of the rule's active version, its pinned (or the code's) core prompts and service model on the
  current content of the subject, or a human decision (object rules: on the current object name and field
  names). ``remaining`` = total - answered; of it, ``answered_stale`` have a verdict of an older version of the
  rule (kept and scoring until a rule rollout asks them again: the next normal run does not send them unless
  LLM_REASK_INLINE), the rest is what the next run would send.
* ``pending_external``: remaining subjects of objects an external run holds (open work items,
  ``RESERVED_SQL``); ``failed``: remaining subjects that got no usable answer - after a run of
  the rule, everything left that no external run holds and that is not only stale (the run asked about it: the
  call or the answer failed); otherwise subjects of objects whose external answer was refused (failed
  work items), and the previous count while the row stays fresh.

When: after every LLM run of rules on a branch (service runs, ``scan_mr`` deltas, the apply /
prepare of external runs), after every snapshot save (parse, MR delta, ingest), and by the
``llm_coverage`` job (``refresh_stale``): rows missing (a new / re-enabled rule, a branch never
counted), stale (``commit`` is not the branch's ``scanned_commit``, older rule version, other
core prompts) and rows with remaining subjects not recounted for ``RECHECK_H`` hours (verdicts
stored through another branch: hits are branch-agnostic) are recomputed in bounded slices. No
model is called; a recount is one grouped query over the branch's fields per rule, grouped only by
the columns the rule's patterns look at (``counts_sql``: one row for a rule without object / field
patterns, the field vocabulary of the branch for the classifier) and comparing the hashes stored
on the rows (``object_fields.llm_hash``, ``objects.names_hash``, migration 0030).
"""

import time
from collections import defaultdict
from types import SimpleNamespace
from typing import Dict, Iterable, List, Optional

from sqlalchemy import text

from discovery_common import db, jobs, lifecycle
from discovery_common.queries import DELTA_OWNER_COND
from config import get_settings
from logger import get_logger
from services.db_service import LLM_FIELD_SUBJECT, LLM_OBJECT_SUBJECT, RESERVED_SQL, candidate_params

logger = get_logger(__name__)

# One llm_coverage job (control worker) recounts at most SLICE_PAIRS (branch, rule) pairs or runs
# about SLICE_S seconds (at least one pair), then requeues itself behind the ready jobs while
# stale pairs are left. Rows with remaining subjects are recounted after RECHECK_H hours.
SLICE_PAIRS = 200
SLICE_S = 20.0
RECHECK_H = 6.0

_COUNTS = """
    SELECT {group} AS field_name, {group_type} AS field_type, {obj_name} AS name, {obj_type} AS type,
           count(*) AS total,
           count(*) FILTER (WHERE c.cand) AS remaining,
           count(*) FILTER (WHERE c.cand AND r.object_key IS NOT NULL) AS reserved,
           count(*) FILTER (WHERE c.cand AND r.object_key IS NULL AND x.object_key IS NOT NULL) AS ext_failed,
           count(*) FILTER (WHERE c.stale) AS stale,
           count(*) FILTER (WHERE c.stale AND r.object_key IS NULL) AS stale_unheld
    FROM branch_objects b
    JOIN objects o ON o.content_hash = b.content_hash
    {fields}
    LEFT JOIN rule_hits h ON h.rule_id = :rule_id AND h.subject_key = {subject}
    {current}
    CROSS JOIN LATERAL (SELECT """ + lifecycle.FRESH_COND + """ AS fresh,
                               """ + lifecycle.MIGRATION_COND + """ AS migr) k
    CROSS JOIN LATERAL (SELECT (k.fresh OR COALESCE(k.migr, false)) AS cand,
                               (NOT k.fresh AND COALESCE(k.migr, false)) AS stale) c
    LEFT JOIN (SELECT DISTINCT object_key FROM llm_work_items
               WHERE """ + RESERVED_SQL + """) r ON r.object_key = o.object_key
    LEFT JOIN (SELECT DISTINCT object_key FROM llm_work_items
               WHERE rule_id = :r AND rule_version = :v AND status = 'failed' AND purpose = 'score') x
              ON x.object_key = o.object_key
    WHERE b.branch_id = :branch_id AND b.content_hash IS NOT NULL
    GROUP BY 1, 2, 3, 4
"""

_FIELD_PARTS = dict(subject="f.field_key", fields="JOIN object_fields f ON f.content_hash = b.content_hash",
                    current=LLM_FIELD_SUBJECT)
_OBJECT_PARTS = dict(subject="o.object_key", fields="", current=LLM_OBJECT_SUBJECT)
_NO_GROUP = "NULL::text"

# the fully grouped forms (every field of every object its own group: the counts of any rule can be filtered
# from them in Python); ``counts_sql(rule)`` groups only by what the rule's matchers look at
FIELD_COUNTS_SQL = text(_COUNTS.format(group="f.field_name", group_type="f.field_type", obj_name="o.name",
                                       obj_type="o.type", **_FIELD_PARTS))
OBJECT_COUNTS_SQL = text(_COUNTS.format(group=_NO_GROUP, group_type=_NO_GROUP, obj_name="o.name", obj_type="o.type",
                                        **_OBJECT_PARTS))


def counts_sql(rule):
    """The counting query of ``rule``, grouped only by the columns its scope patterns (and, for the classifier,
    ``llm_eligible_field``) look at: a rule without object / field patterns is one aggregate row per branch, the
    classifier one row per distinct (field name, type) - the vocabulary of the branch, not one row per field of
    every object (millions of groups sorted on disk for a big branch)."""
    scope = rule.scope or {}
    by_object = any(scope.get(k) for k in ("object_re", "object_type_re"))
    obj_name, obj_type = ("o.name", "o.type") if by_object else (_NO_GROUP, _NO_GROUP)
    if rule.target == 'object':
        return text(_COUNTS.format(group=_NO_GROUP, group_type=_NO_GROUP, obj_name=obj_name, obj_type=obj_type,
                                   **_OBJECT_PARTS))
    by_field = _is_classifier(rule) or any(scope.get(k) for k in ("field_re", "field_type_re"))
    group, group_type = ("f.field_name", "f.field_type") if by_field else (_NO_GROUP, _NO_GROUP)
    return text(_COUNTS.format(group=group, group_type=group_type, obj_name=obj_name, obj_type=obj_type,
                               **_FIELD_PARTS))

BRANCH_SQL = text("""
    SELECT g.id, g.scanned_commit, g.project_id, p.full_path AS project_path, p.scan_mode
    FROM gitlab_branches g JOIN gitlab_projects p ON p.id = g.project_id WHERE g.id = :b
""")

OLD_SQL = text("SELECT rule_version, prompt_version, commit, failed FROM llm_coverage "
               "WHERE branch_id = :b AND rule_id = :r")

UPSERT_SQL = text("""
    INSERT INTO llm_coverage (branch_id, rule_id, rule_version, prompt_version, commit, candidates_total, answered,
                              pending_external, failed, answered_stale, computed_at)
    VALUES (:b, :r, :v, :pv, :commit, :total, :answered, :pending_external, :failed, :stale, now())
    ON CONFLICT (branch_id, rule_id) DO UPDATE SET
        rule_version = EXCLUDED.rule_version, prompt_version = EXCLUDED.prompt_version, commit = EXCLUDED.commit,
        candidates_total = EXCLUDED.candidates_total, answered = EXCLUDED.answered,
        pending_external = EXCLUDED.pending_external, failed = EXCLUDED.failed,
        answered_stale = EXCLUDED.answered_stale, computed_at = EXCLUDED.computed_at
    WHERE llm_coverage.computed_at <= EXCLUDED.computed_at
""")

# Branches whose snapshot the LLM rules run on: main branches and the source branches of the
# open MRs owning their delta, of projects in scan mode 'rules', with a snapshot.
TRACKED_BRANCHES = f"""
    SELECT g.id AS branch_id, g.scanned_commit FROM gitlab_branches g
    JOIN gitlab_projects p ON p.id = g.project_id
    WHERE g.is_main AND g.scanned_commit IS NOT NULL AND p.scan_mode = 'rules'
    UNION
    SELECT g.id, g.scanned_commit FROM gitlab_mrs m
    JOIN gitlab_projects p ON p.id = m.project_id AND p.scan_mode = 'rules'
    JOIN gitlab_branches g ON g.id = m.source_branch_id AND NOT g.is_main
    WHERE m.state = 'opened' AND g.scanned_commit IS NOT NULL AND {DELTA_OWNER_COND}
"""

# rank: 0 no row, 1 stale (snapshot / rule version / prompts), 2 remaining subjects not recounted lately
STALE_SQL = text(f"""
    WITH br AS ({TRACKED_BRANCHES}),
    lr AS (SELECT id, version, """ + lifecycle.pinned_core_sql("rules") + """ AS pv FROM rules
           WHERE id = ANY(:rule_ids)),
    pairs AS (
        SELECT br.branch_id, lr.id AS rule_id, c.computed_at,
               CASE WHEN c.rule_id IS NULL THEN 0
                    WHEN c.commit IS DISTINCT FROM br.scanned_commit OR c.rule_version <> lr.version
                         OR c.prompt_version IS DISTINCT FROM lr.pv THEN 1
                    WHEN c.answered < c.candidates_total
                         AND c.computed_at < now() - make_interval(secs => :recheck_s) THEN 2 END AS rank
        FROM br CROSS JOIN lr
        LEFT JOIN llm_coverage c ON c.branch_id = br.branch_id AND c.rule_id = lr.id
    )
    SELECT branch_id, rule_id, rank FROM pairs WHERE rank IS NOT NULL
    ORDER BY rank, computed_at NULLS FIRST, branch_id, rule_id
    LIMIT :limit
""")


def _is_classifier(rule) -> bool:
    """The built-in classifier (``llm_rule_object_verdicts``): a field rule without category."""
    return rule.target != 'object' and not rule.category


def _applies(rule) -> bool:
    return rule.enabled is not False and getattr(rule, 'deleted_at', None) is None


def count_subjects(session, branch_id: int, rule, project_path: str) -> Dict[str, int]:
    """``{total, answered, remaining, pending_external, ext_failed}`` of one rule on one branch
    (one grouped query; the rule's name / type patterns are applied to the groups here, as the
    run applies them to its candidates)."""
    from services.scan_service import _scope_matches
    from services.score_service import llm_eligible_field

    counts = dict.fromkeys(("total", "remaining", "pending_external", "ext_failed", "stale", "stale_unheld"), 0)
    if _scope_matches(rule.scope, project_path):
        sql = counts_sql(rule)
        classifier = _is_classifier(rule)
        params = {"rule_id": rule.id, "branch_id": branch_id, "r": rule.id, "v": rule.version,
                  "reserve_s": get_settings().llm_external_reserve_h * 3600, **candidate_params(rule, True)}
        for row in session.execute(sql, params):
            # groups carry only the columns the rule looks at (``counts_sql``): a NULL name / type means "not
            # grouped by it", which the patterns of this rule do not look at either
            field = SimpleNamespace(name=row.field_name, type=row.field_type) if row.field_name is not None else None
            if not _scope_matches(rule.scope, project_path, SimpleNamespace(name=row.name, type=row.type), field):
                continue
            if classifier and field is not None and not llm_eligible_field(field.name, field.type):
                continue
            counts["total"] += row.total
            counts["remaining"] += row.remaining
            counts["pending_external"] += row.reserved
            counts["ext_failed"] += row.ext_failed
            counts["stale"] += row.stale
            counts["stale_unheld"] += row.stale_unheld
    counts["answered"] = counts["total"] - counts["remaining"]
    return counts


def _record(session, branch, rule, after_run: bool) -> Dict[str, int]:
    counts = count_subjects(session, branch.id, rule, branch.project_path)
    # stale verdicts are not failures: they wait for a rule rollout
    unheld = counts["remaining"] - counts["pending_external"] - counts["stale_unheld"]
    pv = lifecycle.pinned_core_version(rule)
    if after_run:
        failed = unheld
    else:
        failed = counts["ext_failed"]
        old = session.execute(OLD_SQL, {"b": branch.id, "r": rule.id}).first()
        if old is not None and (old.commit, old.rule_version, old.prompt_version) == (
                branch.scanned_commit, rule.version, pv):
            failed = max(failed, min(old.failed, unheld))      # still fresh: what the last run left failed
    session.execute(UPSERT_SQL, {
        "b": branch.id, "r": rule.id, "v": rule.version, "pv": pv, "commit": branch.scanned_commit,
        "total": counts["total"], "answered": counts["answered"], "pending_external": counts["pending_external"],
        "failed": max(0, failed), "stale": counts["stale"]})
    return counts


def refresh(branch_id: int, rules: Optional[Iterable] = None, after_run: bool = False) -> int:
    """Recount the coverage rows of ``rules`` (default: the enabled LLM rules) on one branch, one
    transaction per rule; returns the rows written. Nothing for a branch that is gone, has no
    snapshot or belongs to a project in inventory mode. ``after_run``: right after a run of these
    rules on the branch (see the module doc for ``failed``)."""
    if rules is None:
        from services.db_service import get_rules
        rules = get_rules('llm')
    rules = [rule for rule in rules if _applies(rule)]
    written = 0
    for rule in rules:
        with db.unit_of_work() as s:
            branch = s.execute(BRANCH_SQL, {"b": branch_id}).first()
            if branch is None or branch.scanned_commit is None or branch.scan_mode == 'inventory':
                return written
            counts = _record(s, branch, rule, after_run)
        written += 1
        logger.debug(f"LLM coverage of rule {rule.name} v{rule.version} on branch {branch_id}: {counts}")
    return written


def stale_pairs(rules: List, limit: int = SLICE_PAIRS, recheck_h: float = RECHECK_H) -> List[tuple]:
    """``[(branch_id, rule_id, rank)]`` to recount, missing rows first, then stale ones, then rows
    with remaining subjects not recounted for ``recheck_h`` hours (oldest first)."""
    ids = [rule.id for rule in rules if _applies(rule)]
    if not ids:
        return []
    with db.unit_of_work() as s:
        return [tuple(r) for r in s.execute(STALE_SQL, {"rule_ids": ids, "recheck_s": recheck_h * 3600,
                                                        "limit": int(limit)})]


def refresh_stale(max_pairs: Optional[int] = None, max_seconds: Optional[float] = None,
                  clock=time.monotonic) -> Dict[str, int]:
    """One slice of the ``llm_coverage`` job: recount up to ``max_pairs`` stale (branch, rule)
    pairs, about ``max_seconds`` (at least one pair). ``more``: stale pairs are left and every
    recount of this slice succeeded (the handler requeues the job; a pair that fails is retried
    by the next scheduled job, so a broken pair never keeps the control worker busy)."""
    from services.scan_service import llm_rules
    max_pairs = SLICE_PAIRS if max_pairs is None else max_pairs
    max_seconds = SLICE_S if max_seconds is None else max_seconds
    rules = {rule.id: rule for rule in llm_rules()}
    pairs = stale_pairs(list(rules.values()), limit=max_pairs + 1)
    more = len(pairs) > max_pairs
    pairs = pairs[:max_pairs]
    by_branch: Dict[int, List] = defaultdict(list)
    for branch_id, rule_id, _ in pairs:
        by_branch[branch_id].append(rules[rule_id])
    deadline = clock() + max_seconds
    done = failed = 0
    for branch_id, branch_rules in by_branch.items():
        if done and (clock() >= deadline or jobs.stop_requested()):
            more = True
            break
        for rule in branch_rules:
            try:
                done += refresh(branch_id, [rule])
            except Exception as e:
                failed += 1
                logger.warning(f"LLM coverage of rule {rule.name} on branch {branch_id} not recounted: {e}")
    stats = {"pairs": len(pairs), "recounted": done, "failed": failed, "more": bool(more and not failed)}
    if pairs:
        logger.info(f"LLM coverage: {stats}")
    return stats
