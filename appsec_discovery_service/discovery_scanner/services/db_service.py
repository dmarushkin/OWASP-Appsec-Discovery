"""Scanner DB layer (P2-5 / P2-6 / P0-3, storage design "AGREED REVISIONS").

Every public function runs in its own ``unit_of_work()`` (one transaction) unless it takes
a ``session`` argument, in which case it is a step of the caller's transaction. Sessions do
not expire on commit, so returned rows stay usable after the transaction.

The schema is created by Alembic (``python -m discovery_common.migrate``), not here.
"""

import functools
import json
from contextlib import contextmanager
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import and_, bindparam, case, false, func, not_, or_, select, text, tuple_, update
from sqlalchemy.dialects.postgresql import ARRAY, UUID, insert as pg_insert
from sqlalchemy.exc import IntegrityError, OperationalError

from discovery_common import db, keys, lifecycle, presence
from discovery_common.queries import DELTA_OWNER_COND, DELTA_OWNER_SQL
from discovery_common.mapping import ObjectRecord, compute_delta, hit_row  # noqa: F401 (re-exported)
from discovery_common.models import (
    CORE_FIELD_RULE, CORE_OBJECT_RULE, MR, Branch, BranchObject, HitStatus, ObjectField, ObjectVersion, Project, Rule, RuleHit, Scan,
)
from config import get_settings
from logger import get_logger

logger = get_logger(__name__)

BATCH = 1000


def init_db(wait_timeout: float = 120.0) -> None:
    """Point the shared engine at DATABASE_URL and wait until the database is reachable.
    The schema itself is migrated by the one-shot ``discovery_migrate`` service."""
    db.configure(url_factory=lambda: get_settings().database_url.get_secret_value())
    db.wait_for_db(timeout=wait_timeout)
    revision = db.schema_revision()
    if revision is None:
        raise RuntimeError("Database schema is not migrated: run `python -m discovery_common.migrate` first")
    logger.info(f"Database schema revision {revision}")


def configure() -> None:
    """Configure the engine lazily from settings (used by worker processes)."""
    db.configure(url_factory=lambda: get_settings().database_url.get_secret_value())


def retry_on_exception(retries: int = 5, delay: float = 2.0, exceptions=(OperationalError,)):
    """Retry a whole unit of work (the transaction was rolled back, so this is safe)."""
    def decorator(func_):
        @functools.wraps(func_)
        def wrapper(*args, **kwargs):
            for attempt in range(retries):
                try:
                    return func_(*args, **kwargs)
                except exceptions as e:
                    if attempt < retries - 1:
                        logger.info(f"{func_.__name__}: attempt {attempt + 1} failed: {e}. Retrying in {delay} seconds...")
                        time.sleep(delay)
                    else:
                        logger.error(f"{func_.__name__}: all {retries} attempts failed")
                        raise
        return wrapper
    return decorator


def _now() -> datetime:
    return datetime.now()


def _processed_at(column, when: Optional[datetime]):
    """``processed_at`` never moves back (P2-4): jobs of the same subject can finish out of
    order (an older job finishing after a newer one must not re-open the newer activity).
    Postgres ``GREATEST`` ignores NULLs, so a first ``processed_at`` is simply set."""
    return func.greatest(column, when or _now())


SCAN_LOCK_CLASS = 0x5CA4    # pg advisory lock key space (classid) of per-branch scan locks


@contextmanager
def scan_lock(branch_id: int):
    """Serialise scans that write the snapshot of one branch (P2-4).

    Dedup keys of scan jobs contain the commit, so a push during a running scan queues a
    second job of the same branch that another worker may claim at once (the old loops kept
    one scan per project with ``mains_in_scan``). The second job waits here (its lease is
    kept by the heartbeat) until the first is done; a dead worker's connection releases it.
    Session-level lock on a dedicated connection, released explicitly before the
    connection goes back to the pool."""
    with db.get_engine().connect() as conn:
        conn.execute(text("SELECT pg_advisory_lock(:cls, :obj)"), {"cls": SCAN_LOCK_CLASS, "obj": int(branch_id)})
        conn.commit()
        try:
            yield
        finally:
            try:
                conn.execute(text("SELECT pg_advisory_unlock(:cls, :obj)"), {"cls": SCAN_LOCK_CLASS, "obj": int(branch_id)})
                conn.commit()
            except Exception as e:      # the connection is broken: the lock went with it
                logger.warning(f"Cannot release the scan lock of branch {branch_id}: {e}")
                conn.invalidate()


def gl_time(value: str) -> datetime:
    """GitLab ISO timestamp -> naive UTC (the inventory tables use timestamp without tz)."""
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).replace(tzinfo=None)


def _chunks(items: Sequence, size: int = BATCH):
    for i in range(0, len(items), size):
        yield items[i:i + size]


UUIDS = ARRAY(UUID(as_uuid=True))


####################################################
#   GitLab inventory                            ####
####################################################

@retry_on_exception()
def upsert_project(project_gl) -> Tuple[Project, str]:
    """Upsert by GitLab project id (P0-3; matching by name mixed up projects). Rows created
    before migration 0002 have no gitlab_id yet: they are adopted by full_path."""

    values = dict(
        gitlab_id=project_gl.id,
        project_name=project_gl.name,
        full_path=project_gl.path_with_namespace,
        description=project_gl.description,
        visibility=project_gl.visibility,
        default_branch=project_gl.default_branch,
        created_at=gl_time(project_gl.created_at),
        updated_at=gl_time(project_gl.last_activity_at),
    )

    with db.unit_of_work() as s:
        existing = s.scalars(select(Project).where(Project.gitlab_id == values["gitlab_id"])).first()
        if existing is None:
            existing = s.scalars(select(Project).where(
                Project.full_path == values["full_path"], Project.gitlab_id.is_(None),
                Project.source == "gitlab")).first()          # never adopt an external project

        if existing is None:
            logger.info(f"Inserting new project: {values['full_path']}")
            existing = Project(**values)
            s.add(existing)
            result = 'inserted'
        elif existing.gitlab_id is None or existing.updated_at < values["updated_at"]:
            logger.info(f"Updating existing project: {values['full_path']}")
            for key, value in values.items():
                setattr(existing, key, value)
            result = 'updated'
        else:
            result = 'checked'

        s.flush()
        return existing, result


@retry_on_exception()
def get_project(project_id) -> Optional[Project]:
    with db.unit_of_work() as s:
        return s.get(Project, project_id)


@retry_on_exception()
def set_project_processed(project_id: int, when: Optional[datetime] = None) -> None:
    with db.unit_of_work() as s:
        s.execute(update(Project).where(Project.id == project_id).values(
            processed_at=_processed_at(Project.processed_at, when)))


@retry_on_exception()
def upsert_branch(branch_gl, project_id, project_path, is_main) -> Tuple[Branch, str]:
    """Upsert a tracked branch by (project_id, branch_name).

    When the default branch changes, the previous main is demoted and its snapshot rows are
    dropped (a demoted branch is kept only while an open MR uses it)."""

    committed = gl_time(branch_gl.commit['committed_date'])
    values = dict(
        branch_name=branch_gl.name, is_main=is_main, commit=branch_gl.commit['id'],
        project_id=project_id, project_path=project_path, created_at=committed, updated_at=committed,
    )

    with db.unit_of_work() as s:
        if is_main:
            # row locks first (as save_main_scan): a main scan finishing meanwhile either commits
            # before the demotion (its rows are dropped here) or sees the branch demoted
            demoted = s.scalars(select(Branch.id).where(
                Branch.project_id == project_id, Branch.is_main, Branch.branch_name != branch_gl.name)
                .with_for_update()).all()
            if demoted:
                logger.info(f"Main branch of project {project_id} changed to {branch_gl.name}")
                gone = s.execute(text("DELETE FROM branch_objects WHERE branch_id = ANY(:ids) RETURNING object_key"),
                                 {"ids": list(demoted)}).scalars().all()
                s.execute(update(Branch).where(Branch.id.in_(demoted)).values(is_main=False, scanned_commit=None))
                presence.refresh(s, object_keys=gone)       # the hits of the old snapshot are not "in main" now

        existing = s.scalars(select(Branch).where(
            Branch.project_id == project_id, Branch.branch_name == branch_gl.name).with_for_update()).first()

        if existing is None:
            logger.info(f"Inserting new branch: {branch_gl.name}")
            existing = Branch(**values)
            s.add(existing)
            result = 'inserted'
        else:
            result = 'checked'
            if existing.is_main != is_main:
                # Snapshot rows of a former main / delta rows of a new main are not valid any more.
                gone = s.execute(text("DELETE FROM branch_objects WHERE branch_id = :b RETURNING object_key"),
                                 {"b": existing.id}).scalars().all()
                existing.is_main = is_main
                existing.scanned_commit = None
                presence.refresh(s, object_keys=gone)
                result = 'updated'
            if existing.updated_at < values["updated_at"] or existing.commit != values["commit"]:
                logger.info(f"Updating existing branch: {existing.branch_name}, p_id: {project_id}")
                updated = values["updated_at"]
                floor = max((d for d in (existing.updated_at, existing.processed_at) if d is not None), default=None)
                if existing.commit != values["commit"] and floor is not None and updated <= floor:
                    # reset to an older commit (force push): updated_at must still move past
                    # processed_at, else the new head is never queued for a scan
                    logger.info(f"Branch {existing.branch_name} of project {project_id} moved to an older commit "
                                f"{values['commit']}")
                    updated = floor + timedelta(microseconds=1)
                existing.commit = values["commit"]
                existing.updated_at = updated
                existing.project_path = project_path
                result = 'updated'

        s.flush()
        return existing, result


@retry_on_exception()
def set_branch_processed(branch_id: int, when: Optional[datetime] = None) -> None:
    with db.unit_of_work() as s:
        s.execute(update(Branch).where(Branch.id == branch_id).values(
            processed_at=_processed_at(Branch.processed_at, when)))


@retry_on_exception()
def get_branch(project_id, branch_name) -> Optional[Branch]:
    with db.unit_of_work() as s:
        return s.scalars(select(Branch).where(Branch.project_id == project_id, Branch.branch_name == branch_name)).first()


@retry_on_exception()
def get_branch_by_id(branch_id) -> Optional[Branch]:
    with db.unit_of_work() as s:
        return s.get(Branch, branch_id)


@retry_on_exception()
def get_mr(mr_id) -> Optional[MR]:
    with db.unit_of_work() as s:
        return s.get(MR, mr_id)


@retry_on_exception()
def upsert_mr(mr_gl, project_id, project_path, source_branch, target_branch) -> Tuple[MR, str]:

    values = dict(
        mr_id=mr_gl.iid, project_id=project_id, project_path=project_path,
        source_branch_id=source_branch.id, source_branch=source_branch.branch_name,
        source_branch_commit=source_branch.commit,
        target_branch_id=target_branch.id, target_branch=target_branch.branch_name,
        target_branch_commit=target_branch.commit,
        state=mr_gl.state, title=mr_gl.title, description=mr_gl.description,
        created_at=gl_time(mr_gl.created_at), updated_at=gl_time(mr_gl.updated_at),
    )

    with db.unit_of_work() as s:
        existing = s.scalars(select(MR).where(MR.project_id == project_id, MR.mr_id == mr_gl.iid)).first()

        # the presence of the hits of the source branch's delta changes when an MR opens again or moves to
        # another source branch (``discovery_common.presence``: in_open_mr follows the MR state)
        presence_branches = set()
        if existing is None:
            logger.info(f"Inserting new mr: {mr_gl.iid}, p_id: {project_id}")
            existing = MR(**values)
            s.add(existing)
            result = 'inserted'
            presence_branches.add(values["source_branch_id"])
        else:
            source_changed = existing.source_branch_commit != values["source_branch_commit"]
            if existing.state != values["state"] or existing.source_branch_id != values["source_branch_id"]:
                presence_branches |= {existing.source_branch_id, values["source_branch_id"]}
            for key, value in values.items():
                setattr(existing, key, value)
            if existing.state == 'opened':
                existing.closed_at = None
            result = 'updated' if source_changed else 'checked'

        s.flush()
        for branch_id in presence_branches - {None}:
            presence.refresh(s, object_keys=presence.branch_object_keys(s, branch_id))
        return existing, result


@retry_on_exception()
def set_mr_processed(mr_id: int, when: Optional[datetime] = None) -> None:
    with db.unit_of_work() as s:
        s.execute(update(MR).where(MR.id == mr_id).values(
            processed_at=_processed_at(MR.processed_at, when)))


@retry_on_exception()
def get_delta_owner(source_branch_id: int) -> Optional[int]:
    """Id of the open MR that owns the delta stored on ``source_branch_id`` (the oldest open MR
    of that source branch), None when there is none."""
    with db.unit_of_work() as s:
        return s.execute(DELTA_OWNER_SQL, {"source": source_branch_id}).scalar()


@retry_on_exception()
def set_mr_target_commit(mr_id: int, commit: str) -> None:
    with db.unit_of_work() as s:
        s.execute(update(MR).where(MR.id == mr_id).values(target_branch_commit=commit))


####################################################
#   Scans                                       ####
####################################################

def _sorted_parsers(parsers):
    return None if parsers is None else sorted(parsers)


def _scan_values(scan: Scan) -> dict:
    return dict(
        scanner=scan.scanner, rules_version=scan.rules_version, parsers=_sorted_parsers(scan.parsers),
        project_id=scan.project_id, branch_id=scan.branch_id, project_path=scan.project_path,
        branch_name=scan.branch_name, branch_commit=scan.branch_commit, scanned_at=scan.scanned_at,
    )


def record_scan(session, scan: Scan) -> None:
    """Insert the scan marker (all fields; parsers sorted; a duplicate is ignored)."""
    stmt = pg_insert(Scan.__table__).values(**_scan_values(scan)).on_conflict_do_nothing(constraint="uq_scan")
    session.execute(stmt)


# rules_version suffix of the marker of a partial main scan (a parser failed): the branch is
# still retried (``scan_branch`` looks for the complete marker), but MR scans of this target
# do not clone and scan the same commit again (``scan_service._partial_scan_of``)
PARTIAL_SUFFIX = "+partial"


def partial_marker(scan: Scan) -> Scan:
    return Scan(**{**_scan_values(scan), "rules_version": f"{scan.rules_version}{PARTIAL_SUFFIX}"})


@retry_on_exception()
def insert_scan(scan: Scan) -> None:
    with db.unit_of_work() as s:
        record_scan(s, scan)


@retry_on_exception()
def get_scan(scan: Scan) -> Optional[Scan]:
    with db.unit_of_work() as s:
        return s.scalars(select(Scan).where(
            Scan.scanner == scan.scanner,
            Scan.rules_version == scan.rules_version,
            Scan.branch_id == scan.branch_id,
            Scan.branch_commit == scan.branch_commit,
            Scan.parsers == _sorted_parsers(scan.parsers),
        )).first()


####################################################
#   Objects and branch rows                     ####
####################################################

def _insert_objects(session, records: Iterable[ObjectRecord]) -> None:
    """Content-addressed: an object version that already exists costs nothing (only a changed name is written)."""
    records = list(records)
    rows = list({r.content_hash: r.object_row() for r in records}.values())
    t = ObjectVersion.__table__
    for chunk in _chunks(rows):
        # the name is not part of the content hash: a version stored under an older name format gets the parser's
        # current one (migration 0027 renamed the stored ones) - and with it the names hash the LLM rules compare
        stmt = pg_insert(t)
        session.execute(stmt.on_conflict_do_update(
            index_elements=[t.c.content_hash],
            set_={"name": stmt.excluded.name, "names_hash": stmt.excluded.names_hash},
            where=t.c.name.is_distinct_from(stmt.excluded.name)), chunk)
    field_rows = list({(f["content_hash"], f["field_name"]): f for r in records for f in r.field_rows()}.values())
    for chunk in _chunks(field_rows):
        session.execute(pg_insert(ObjectField.__table__).on_conflict_do_nothing(), chunk)


# rows of objects found by one of the given parsers (the object key includes the parser, so
# any stored version of the key tells it; removed MR rows have no content_hash)
_PARSER_SCOPE_SQL = ("EXISTS (SELECT 1 FROM objects o WHERE o.object_key = {alias}.object_key "
                     "AND o.parser = ANY(:parsers))")


def _apply_branch_rows(session, branch_id: int, rows: List[dict], delete_missing: bool = True,
                       parsers: Optional[Sequence[str]] = None) -> Tuple[Dict[str, int], List[uuid.UUID]]:
    """Make the branch's rows equal ``rows`` with a diff: delete keys that are gone, upsert
    the rest, and write only rows that actually changed (``IS DISTINCT FROM``).
    ``delete_missing=False`` (partial scan: a parser failed) only upserts. ``parsers``: a scan
    by these parsers only (``parse`` with a parser subset) replaces only their objects; the
    rows of the other parsers are kept. Returns the counts and the keys of the rows deleted or
    written (the objects whose presence may have changed, ``discovery_common.presence``)."""
    t = BranchObject.__table__
    rows = list({r["object_key"]: r for r in rows}.values())      # one row per key (a multi-row upsert needs it)
    keys_ = [r["object_key"] for r in rows]
    changed: List[uuid.UUID] = []

    deleted = 0
    if delete_missing:
        scope = f" AND {_PARSER_SCOPE_SQL.format(alias='bo')}" if parsers else ""
        params = {"b": branch_id, "keys": keys_}
        if parsers:
            params["parsers"] = list(parsers)
        # an anti-join on unnest(keys): ``NOT (object_key = ANY(:keys))`` is a linear pass over the array for
        # every row, O(rows x keys) - quadratic in the branch size (tens of minutes for a 300k-object branch)
        gone = session.execute(
            text(f"DELETE FROM branch_objects bo WHERE bo.branch_id = :b "
                 f"AND NOT EXISTS (SELECT 1 FROM unnest(CAST(:keys AS uuid[])) k WHERE k = bo.object_key){scope} "
                 f"RETURNING bo.object_key")
            .bindparams(bindparam("keys", type_=UUIDS)),
            params,
        ).scalars().all()
        deleted = len(gone)
        changed.extend(gone)

    written = 0
    for chunk in _chunks(rows):
        stmt = pg_insert(t)
        ex = stmt.excluded
        cols = ("content_hash", "is_main", "change", "line", "field_lines")
        stmt = stmt.on_conflict_do_update(
            index_elements=[t.c.branch_id, t.c.object_key],
            set_={c: ex[c] for c in cols},
            where=tuple_(*(t.c[c] for c in cols)).is_distinct_from(tuple_(*(ex[c] for c in cols))),
        ).returning(t.c.object_key)
        touched = session.execute(stmt, chunk).scalars().all()      # inserted or really updated rows only
        written += len(touched)
        changed.extend(touched)

    return {"deleted": deleted, "written": written}, changed


def _main_rows(branch_id: int, records: Iterable[ObjectRecord]) -> List[dict]:
    return [
        {"branch_id": branch_id, "object_key": r.object_key, "content_hash": r.content_hash, "is_main": True,
         "change": None, "line": r.line, "field_lines": r.field_lines}
        for r in records
    ]


def _prune_mr_deltas(session, target_branch_id: int) -> List[uuid.UUID]:
    """After a main scan: drop delta rows of open MRs targeting it that now equal the target
    (only deltas owned by such an MR: a source branch of several MRs holds the delta of the
    oldest one, which may target another branch, see ``queries.DELTA_OWNER_COND``). Returns the
    keys of the dropped rows (their hits may leave ``in_open_mr``)."""
    return session.execute(text("""
        DELETE FROM branch_objects s
        USING gitlab_mrs m
        WHERE m.target_branch_id = :t AND m.state = 'opened' AND """ + DELTA_OWNER_COND + """
          AND s.branch_id = m.source_branch_id AND NOT s.is_main
          AND CASE WHEN s.change = 'removed'
                   THEN NOT EXISTS (SELECT 1 FROM branch_objects t
                                    WHERE t.branch_id = :t AND t.object_key = s.object_key)
                   ELSE EXISTS (SELECT 1 FROM branch_objects t
                                WHERE t.branch_id = :t AND t.object_key = s.object_key
                                  AND t.content_hash = s.content_hash)
              END
        RETURNING s.object_key"""), {"t": target_branch_id}).scalars().all()


@retry_on_exception()
def load_branch_snapshot(branch_id: int, parsers: Optional[Sequence[str]] = None) -> Dict[uuid.UUID, uuid.UUID]:
    """``{object_key: content_hash}`` of a main branch (the MR delta baseline); ``parsers``:
    only the objects of these parsers (an MR parsed by a parser subset)."""
    with db.unit_of_work() as s:
        if parsers:
            rows = s.execute(text(
                "SELECT b.object_key, b.content_hash FROM branch_objects b JOIN objects o ON o.content_hash = b.content_hash "
                "WHERE b.branch_id = :b AND o.parser = ANY(:parsers)"), {"b": branch_id, "parsers": list(parsers)})
        else:
            rows = s.execute(text(
                "SELECT object_key, content_hash FROM branch_objects WHERE branch_id = :b AND content_hash IS NOT NULL"),
                {"b": branch_id})
        return {row.object_key: row.content_hash for row in rows}


def load_snapshot_files(branch_id: int, object_keys: Iterable[uuid.UUID]) -> Dict[uuid.UUID, Optional[str]]:
    """``{object_key: file}`` of the given objects in a branch snapshot (``removed`` MR delta
    entries carry no record, their file comes from the target's stored version)."""
    keys = list(object_keys)
    if not keys:
        return {}
    files = {}
    with db.unit_of_work() as s:
        for chunk in _chunks(keys):
            rows = s.execute(text(
                "SELECT bo.object_key, o.file FROM branch_objects bo JOIN objects o USING (content_hash) "
                "WHERE bo.branch_id = :b AND bo.object_key = ANY(:keys)").bindparams(bindparam("keys", type_=UUIDS)),
                {"b": branch_id, "keys": list(chunk)})
            files.update({row.object_key: row.file for row in rows})
    return files


def _delta_rows(branch_id: int, delta) -> List[dict]:
    rows = []
    for change, object_key, record in delta:
        rows.append({
            "branch_id": branch_id, "object_key": object_key, "is_main": False, "change": change,
            "content_hash": record.content_hash if record else None,
            "line": record.line if record else None,
            "field_lines": record.field_lines if record else None,
        })
    return rows


####################################################
#   Rules and hits                              ####
####################################################

@retry_on_exception()
def get_rules(kind: Optional[str] = None, include_disabled: bool = False) -> List[Rule]:
    with db.unit_of_work() as s:
        stmt = select(Rule).where(Rule.deleted_at.is_(None)).order_by(Rule.id)
        if kind:
            stmt = stmt.where(Rule.kind == kind)
        if not include_disabled:
            stmt = stmt.where(or_(Rule.enabled.is_(None), Rule.enabled))
        return list(s.scalars(stmt).all())


# Rules are created by migration 0002 (renamed by 0028); recreated here if someone deleted them - disabled: the
# built-in keyword scoring is opt-in (enable kw-fields / kw-props in the UI)
_RULE_DEFAULTS = {
    CORE_FIELD_RULE: dict(kind="keyword", target="field", mode="auto", scope={"source": "core"}, enabled=False),
    CORE_OBJECT_RULE: dict(kind="keyword", target="object", mode="auto", scope={"source": "core"}, enabled=False),
}


@retry_on_exception()
def ensure_rule(name: str) -> Rule:
    with db.unit_of_work() as s:
        s.execute(text("SELECT pg_advisory_xact_lock(hashtext('discovery_rules'))"))
        # a soft-deleted built-in rule stays deleted (it is returned, disabled)
        rule = s.scalars(select(Rule).where(Rule.name == name)
                         .order_by(Rule.deleted_at.is_not(None), Rule.id)).first()
        if rule is None:
            rule = Rule(name=name, version=1, updated_at=datetime.now(timezone.utc), **_RULE_DEFAULTS[name])
            s.add(rule)
            s.flush()
        return rule


def _dedupe_hits(hits: Iterable[dict]) -> List[dict]:
    return list({(h["rule_id"], h["subject_key"]): h for h in hits}.values())


PROPOSAL = ("status", "category", "severity", "rule_version", "model", "prompt_version", "reason", "fields",
            "names_hash", "subject_hash")


def _upsert_hits(session, hits: Iterable[dict], *, is_main: bool, machine_verdicts_overwritable: bool) -> int:
    """Insert hits; on conflict update the proposal only where no human decided:

    * ``pending_review`` rows nobody reviewed;
    * ``pending_review`` rows a reviewer reopened, once the rule's version is newer;
    * machine-made ``match`` rows (mode auto, no reviewer) by the same or a newer rule version;
    * for LLM verdicts (``machine_verdicts_overwritable``) also machine-made ``no_match`` /
      ``need_more_info`` rows (no reviewer).

    Rows a human decided (match / no_match / need_more_info with a reviewer) are never
    touched. ``last_seen_at`` is bumped only by main scans and at most once a day.

    Presence (``discovery_common.presence``): the hits come from the snapshot being saved, so a main scan's rows
    are ``in_main`` and an MR scan's ``in_open_mr`` - set on insert, switched on (never off) on conflict; the
    callers refresh the flags of the objects the snapshot diff removed or changed."""
    t = RuleHit.__table__
    hits = _dedupe_hits(hits)
    total = 0
    flag = "in_main" if is_main else "in_open_mr"

    stmt = pg_insert(t)
    ex = stmt.excluded
    pending = and_(t.c.status == HitStatus.pending_review.value,
                   or_(t.c.reviewer.is_(None), ex.rule_version > t.c.rule_version))
    # a machine-made match (mode auto, nobody reviewed it) follows its rule: an edited rule
    # re-proposes it (a new version; severity / category / mode edits keep the version)
    machine_match = and_(t.c.status == HitStatus.match.value, t.c.reviewer.is_(None),
                         ex.rule_version >= t.c.rule_version)
    overwritable = or_(pending, machine_match)
    if machine_verdicts_overwritable:
        # LLM verdicts: any machine-made row (pending, match in mode auto, no_match,
        # need_more_info: no reviewer) takes the new answer; human decisions are kept, and so
        # are harness-tier decisions (a harness model verified the hit) unless the answer is about
        # other content of the subject (``subject_hash``): then the service answer replaces it
        # (tier service again; ``verified_at`` stays, so the verify job checks the hit again)
        service_or_changed = or_(t.c.decided_tier != "harness", t.c.subject_hash.is_distinct_from(ex.subject_hash))
        overwritable = or_(pending, and_(t.c.reviewer.is_(None), service_or_changed))
    stale_seen = or_(t.c.last_seen_at.is_(None), t.c.last_seen_at < func.now() - text("interval '1 day'"))
    refresh_seen = stale_seen if is_main else false()

    set_ = {c: case((overwritable, ex[c]), else_=t.c[c]) for c in PROPOSAL}
    set_["decided_tier"] = case((overwritable, case((t.c.reviewer.is_(None), "service"), else_=t.c.decided_tier)),
                                else_=t.c.decided_tier)
    set_["asked_by_model"] = case((overwritable, false()), else_=t.c.asked_by_model)
    set_["last_seen_at"] = case((refresh_seen, func.now()), else_=t.c.last_seen_at)
    set_[flag] = or_(t.c[flag], ex[flag])
    stmt = stmt.on_conflict_do_update(
        index_elements=[t.c.rule_id, t.c.subject_key],
        set_=set_,
        where=or_(
            and_(overwritable, tuple_(*(t.c[c] for c in PROPOSAL)).is_distinct_from(tuple_(*(ex[c] for c in PROPOSAL)))),
            refresh_seen,
            and_(ex[flag], not_(t.c[flag])),
        ),
    )
    for chunk in _chunks([{"reason": None, "fields": None, "names_hash": None, "subject_hash": None, flag: True, **h}
                          for h in hits]):
        total += session.execute(stmt, chunk).rowcount or 0
    return total


def _drop_stale_pending(session, branch_id: int, project_id: int, parsers: Optional[Sequence[str]] = None) -> int:
    """After a complete main scan: keyword hits nobody reviewed (``pending_review``, or
    ``match`` by a rule in mode auto) from an older version of their rule were not produced
    again by the current version, so the edited rule no longer matches: they are removed.
    Human decisions are kept. ``parsers``: only objects of these parsers were scanned again, so
    only their hits are judged."""
    scope = f" AND {_PARSER_SCOPE_SQL.format(alias='h')}" if parsers else ""
    params = {"p": project_id, "b": branch_id}
    if parsers:
        params["parsers"] = list(parsers)
    return session.execute(text(f"""
        DELETE FROM rule_hits h USING rules r
        WHERE h.rule_id = r.id AND r.kind = 'keyword' AND h.project_id = :p
          AND h.status IN ('pending_review', 'match') AND h.reviewer IS NULL AND h.rule_version < r.version
          AND h.object_key IN (SELECT object_key FROM branch_objects WHERE branch_id = :b){scope}
    """), params).rowcount or 0


def _carry_over_hits(session, branch_id: int, records: List[ObjectRecord],
                     parsers: Optional[Sequence[str]] = None) -> int:
    """Identity changes (e.g. the one-time hash change of P1-8, or a parser fix): when a main
    scan removes an object and adds one with the same (parser, type, name, file), copy the
    removed object's hits to the new keys, so human decisions survive. Unambiguous (1:1)
    matches only; the old rows are left for retention."""
    new_keys = {r.object_key for r in records}

    old = session.execute(text("""
        SELECT b.object_key, b.content_hash, o.parser, o.type, o.name, o.file
        FROM branch_objects b JOIN objects o ON o.content_hash = b.content_hash
        WHERE b.branch_id = :b"""), {"b": branch_id}).all()
    removed = [row for row in old if row.object_key not in new_keys and (not parsers or row.parser in parsers)]
    if not removed:
        return 0
    old_keys = {row.object_key for row in old}

    def ident(parser, type_, name, file):
        return (parser, type_, name, file)

    def unique_by_ident(items, key):
        groups = {}
        for item in items:
            groups.setdefault(key(item), []).append(item)
        return {k: v[0] for k, v in groups.items() if len(v) == 1}

    removed_by_ident = unique_by_ident(removed, lambda r: ident(r.parser, r.type, r.name, r.file))
    added_by_ident = unique_by_ident([r for r in records if r.object_key not in old_keys],
                                     lambda r: ident(r.parser, r.type, r.name, r.file))
    pairs = [(removed_by_ident[k], added_by_ident[k]) for k in removed_by_ident.keys() & added_by_ident.keys()]
    if not pairs:
        return 0

    subject_map = {}
    for old_row, new_record in pairs:
        subject_map[old_row.object_key] = (new_record, None)
        for name in new_record.fields:
            subject_map[keys.field_key(old_row.object_key, name)] = (new_record, name)

    old_hits = session.execute(
        text("SELECT * FROM rule_hits WHERE subject_key = ANY(:keys)").bindparams(bindparam("keys", type_=UUIDS)),
        {"keys": list(subject_map)},
    ).mappings().all()
    copies = []
    for hit in old_hits:
        new_record, field_name = subject_map[hit["subject_key"]]
        if (hit["field_name"] or None) != field_name:
            continue
        copy = dict(hit)
        copy["subject_key"] = keys.subject_key(new_record.object_key, field_name)
        copy["object_key"] = new_record.object_key
        copies.append(copy)
    for chunk in _chunks(copies):
        session.execute(pg_insert(RuleHit.__table__).on_conflict_do_nothing(), chunk)
    if copies:
        logger.info(f"Carried {len(copies)} rule hits over to {len(pairs)} re-keyed objects of branch {branch_id}")
    return len(copies)


####################################################
#   Transactional saves                         ####
####################################################

def _full_scan_values(commit: str, fingerprint: Optional[str], target_commit: Optional[str] = None) -> dict:
    """Branch columns of a complete scan by every parser: the snapshot's commit, and for the diff-based
    skip (migration 0029, ``services.diff_service``) its configuration fingerprint and time; an MR source
    branch also records the target commit its delta was computed against."""
    values = dict(scanned_commit=commit, full_scanned_at=func.now())
    if fingerprint is not None:
        values["scan_fingerprint"] = fingerprint
    if target_commit is not None:
        values["delta_target_commit"] = target_commit
    return values


@retry_on_exception(retries=3, delay=1.0, exceptions=(OperationalError, IntegrityError))
def skip_branch_scan(branch: Branch, commit: str, scan: Optional[Scan], target_commit: Optional[str] = None) -> bool:
    """Move the snapshot of ``branch`` to ``commit`` without a scan (``services.diff_service``: no file a
    parser reads changed): ``scanned_commit`` (an MR source branch: ``delta_target_commit`` too), the scan
    marker, and the LLM coverage rows follow the commit (the snapshot they count is the same). Objects, hits
    and verdicts are untouched; ``scan_fingerprint`` / ``full_scanned_at`` keep the last full scan's values.
    False when the branch stopped being a main branch meanwhile (nothing changed)."""
    with db.unit_of_work() as s:
        row = s.execute(text("SELECT is_main, scanned_commit FROM gitlab_branches WHERE id = :b FOR UPDATE"),
                        {"b": branch.id}).first()
        if row is None or (branch.is_main and not row.is_main):
            logger.warning(f"Branch {branch.id} is not a main branch any more: its snapshot is not moved to {commit}")
            return False
        values = dict(scanned_commit=commit)
        if target_commit is not None:
            values["delta_target_commit"] = target_commit
        s.execute(update(Branch).where(Branch.id == branch.id).values(**values))
        if row.scanned_commit:
            s.execute(text("UPDATE llm_coverage SET commit = :new WHERE branch_id = :b AND commit = :old"),
                      {"b": branch.id, "old": row.scanned_commit, "new": commit})
        if scan is not None:
            record_scan(s, scan)
    logger.info(f"Snapshot of branch {branch.id} moved from {row.scanned_commit} to {commit} without a scan")
    return True


@retry_on_exception(retries=3, delay=1.0, exceptions=(OperationalError, IntegrityError))
def save_main_scan(branch: Branch, commit: str, records: List[ObjectRecord], hits: List[dict],
                   scan: Optional[Scan], complete: bool = True, parsers: Optional[Sequence[str]] = None,
                   fingerprint: Optional[str] = None) -> dict:
    """One transaction for a main branch scan: objects + fields, snapshot diff-apply,
    carried-over decisions, keyword hits, ``scanned_commit``, pruned MR deltas, scan marker.
    ``fingerprint``: the scan configuration (``diff_service.scan_fingerprint``), recorded with
    ``full_scanned_at`` by a complete scan of every parser.

    A partial scan (``complete=False``: a parser failed) only adds/updates rows; it does not
    delete objects (so the failed parser's objects stay), set ``scanned_commit`` or record the
    scan, so the branch is retried; only a ``PARTIAL_SUFFIX`` marker is recorded.

    Retried on IntegrityError: the orphan GC may delete an object version between our
    ``ON CONFLICT DO NOTHING`` and the branch row that references it (FK is NO ACTION)."""
    with db.unit_of_work() as s:
        # the default branch may have changed while the scan ran (upsert_branch demotes the
        # old main without the scan lock): locked here, re-checked, nothing saved if demoted
        still_main = s.execute(text("SELECT is_main FROM gitlab_branches WHERE id = :b FOR UPDATE"),
                               {"b": branch.id}).scalar()
        if not still_main:
            logger.warning(f"Branch {branch.id} is not a main branch any more: its scan at {commit} is not saved")
            return {"skipped": "not main"}
        _insert_objects(s, records)
        carried = _carry_over_hits(s, branch.id, records, parsers) if complete else 0
        stats, changed = _apply_branch_rows(s, branch.id, _main_rows(branch.id, records), delete_missing=complete,
                                            parsers=parsers)
        stats["hits"] = _upsert_hits(s, hits, is_main=True, machine_verdicts_overwritable=False)
        stats["carried"] = carried
        if complete:
            if not parsers:     # a parser subset leaves the other parsers' objects at older commits
                s.execute(update(Branch).where(Branch.id == branch.id).values(**_full_scan_values(commit, fingerprint)))
            pruned = _prune_mr_deltas(s, branch.id)
            stats["pruned_mr_rows"] = len(pruned)
            changed.extend(pruned)
            stats["stale_pending"] = _drop_stale_pending(s, branch.id, branch.project_id, parsers)
            stats["deleted_field_hits"] = _drop_deleted_field_hits(s, branch.id, branch.project_id)
            if scan is not None:
                record_scan(s, scan)
        elif scan is not None:
            record_scan(s, partial_marker(scan))
        # the hits of the objects the diff removed / changed (and of pruned MR rows): in_main / in_open_mr follow
        stats["presence"] = presence.refresh(s, object_keys=changed)
    logger.info(f"Saved main scan of branch {branch.id} at {commit}: {len(records)} objects, {stats}")
    return stats


@retry_on_exception(retries=3, delay=1.0, exceptions=(OperationalError, IntegrityError))
def save_mr_delta(source_branch: Branch, commit: str, delta, hits: List[dict], scan: Optional[Scan],
                  complete: bool = True, parsers: Optional[Sequence[str]] = None,
                  fingerprint: Optional[str] = None, target_commit: Optional[str] = None) -> dict:
    """One transaction for an MR source branch: only the delta vs the target is stored.
    A partial scan only adds/updates delta rows and is not recorded. A complete one by every
    parser records ``fingerprint`` / ``full_scanned_at`` and ``target_commit`` (the target the
    delta is against) for the diff-based skip."""
    if source_branch.is_main:
        raise ValueError(f"branch {source_branch.id} is a main branch, it cannot hold MR delta rows")
    records = [record for _, _, record in delta if record is not None]
    with db.unit_of_work() as s:
        _insert_objects(s, records)
        stats, changed = _apply_branch_rows(s, source_branch.id, _delta_rows(source_branch.id, delta),
                                            delete_missing=complete, parsers=parsers)
        stats["hits"] = _upsert_hits(s, hits, is_main=False, machine_verdicts_overwritable=False)
        if complete:
            if not parsers:
                s.execute(update(Branch).where(Branch.id == source_branch.id)
                          .values(**_full_scan_values(commit, fingerprint, target_commit)))
            if scan is not None:
                record_scan(s, scan)
        stats["presence"] = presence.refresh(s, object_keys=changed)
    logger.info(f"Saved MR delta of branch {source_branch.id} at {commit}: {len(delta)} rows, {stats}")
    return stats


def _drop_stale_field_marks(session, rule_id: int, object_keys: Sequence[uuid.UUID], hits: Iterable[dict]) -> int:
    """LLM object rules (``mark_fields``): the objects in ``object_keys`` were just asked again, so
    the rule's field hits on them that the new verdict does not name any more (the model dropped a
    field, said no_match, or ``mark_fields`` was switched off) are removed. Machine-made rows only
    (``reviewer IS NULL``, not verified by a harness model): human and harness decisions are kept."""
    if not object_keys:
        return 0
    keep = [h["subject_key"] for h in hits if h.get("field_name") is not None and h["rule_id"] == rule_id]
    return session.execute(text("""
        DELETE FROM rule_hits
        WHERE rule_id = :r AND object_key = ANY(:objs) AND subject_key <> object_key AND reviewer IS NULL
          AND decided_tier <> 'harness'
          AND NOT EXISTS (SELECT 1 FROM unnest(CAST(:keep AS uuid[])) k WHERE k = subject_key)
    """).bindparams(bindparam("objs", type_=UUIDS), bindparam("keep", type_=UUIDS)),
        {"r": rule_id, "objs": list(dict.fromkeys(object_keys)), "keep": keep}).rowcount or 0


def _drop_deleted_field_hits(session, branch_id: int, project_id: int) -> int:
    """After a complete main scan: machine-made LLM field hits (``reviewer IS NULL``, field rules
    and the field marks of object rules) of objects in the snapshot whose field is in no stored
    version of any tracked branch any more (the field was deleted / renamed) are removed. Human
    decisions on such fields are kept (history; the retention of ``cleanup`` applies to them).
    Keyword hits are not touched (``_drop_stale_pending``)."""
    return session.execute(text("""
        DELETE FROM rule_hits h USING rules r
        WHERE h.rule_id = r.id AND r.kind = 'llm' AND h.project_id = :p AND h.reviewer IS NULL
          AND h.field_name IS NOT NULL
          AND h.object_key IN (SELECT object_key FROM branch_objects WHERE branch_id = :b AND content_hash IS NOT NULL)
          AND NOT EXISTS (SELECT 1 FROM object_fields f JOIN branch_objects bo ON bo.content_hash = f.content_hash
                          WHERE f.field_key = h.subject_key)
    """), {"p": project_id, "b": branch_id}).rowcount or 0


DECIDED_STATUSES = (HitStatus.match.value, HitStatus.no_match.value, HitStatus.need_more_info.value)
# the reviewer's verb of a decided status, for the notes ("was confirmed by alice")
DECISION_WORD = {HitStatus.match.value: "confirmed", HitStatus.no_match.value: "rejected"}

# a note line is added once (a hit asked again on two branches with other content would repeat it)
_APPEND_NOTE = ("CASE WHEN note IS NULL OR note = '' THEN CAST(:msg AS text) "
                "WHEN right(note, length(CAST(:msg AS text))) = CAST(:msg AS text) THEN note "
                "ELSE note || E'\\n' || CAST(:msg AS text) END")

_REVIEW_AGAIN_SQL = text(f"""
    UPDATE rule_hits SET status = 'pending_review', reviewer = NULL, reviewed_at = NULL, decided_via = NULL,
           rule_version = :rule_version, prompt_version = :prompt_version, model = :model, reason = :reason,
           fields = :fields, names_hash = :names_hash, subject_hash = :subject_hash, note = {_APPEND_NOTE}
    WHERE rule_id = :rule_id AND subject_key = :subject_key
""")

# carry-over: the human decision (status, reviewer, decided_via, category, severity) stays
_CARRY_OVER_SQL = text(f"""
    UPDATE rule_hits SET rule_version = :rule_version, prompt_version = :prompt_version, model = :model,
           reason = :reason, fields = :fields, names_hash = :names_hash, subject_hash = :subject_hash,
           note = CASE WHEN CAST(:msg AS text) IS NULL THEN note ELSE {_APPEND_NOTE} END
    WHERE rule_id = :rule_id AND subject_key = :subject_key
""")


def _reasked_human_hits(session, rule_id: int, hits: List[dict],
                        object_fields: Optional[Dict[uuid.UUID, set]]) -> Tuple[List[dict], Dict[str, int]]:
    """Object hits a human decided that were asked again because the object's name / set of field
    names changed (``names_hash``, see ``LLM_CANDIDATE_COND``). The fields confirmed before are
    those of an object hit a human set to ``match`` (``fields``) plus the fields whose field marks a human
    set to ``match`` (none when the object hit is ``no_match``).

    * The model names (match / need_more_info) a field not confirmed before: the object hit goes
      back to the review queue (pending_review, reviewer cleared, the old decision in the note:
      "re-review: new fields X, Y (was confirmed by alice)") and the field marks of the new fields
      are pending_review; the field hits a human confirmed stay ``match``.
    * Otherwise (also no_match): the decision is carried over to the new verdict (rule version,
      prompts, hashes, model, reason; fields = the confirmed ones and the named ones still in the
      object), with the note "confirmation carried over to the new version"; no review needed.

    A reopened pending hit (reviewer set) of the same rule version gets the new proposal and stays
    pending. Harness-tier decisions (migration 0020) are treated like human ones for the carry-over; when the
    model names new fields, the service answer replaces the harness decision instead of a re-review (the verify
    job asks the harness model again). Returns the hits left for ``_upsert_hits`` (field marks of new fields
    forced pending)."""
    objs = {h["subject_key"]: h for h in hits
            if h.get("field_name") is None and h["rule_id"] == rule_id and h.get("names_hash")}
    stats = {"review_again": 0, "carried_over": 0}
    if not objs:
        return hits, stats
    rows = session.execute(text("""
        SELECT subject_key, object_key, status, reviewer, rule_version, names_hash, fields, decided_tier,
               verifier_model FROM rule_hits
        WHERE rule_id = :r AND subject_key = ANY(:keys) AND names_hash IS NOT NULL
          AND (reviewer IS NOT NULL OR decided_tier = 'harness')
        FOR UPDATE
    """).bindparams(bindparam("keys", type_=UUIDS)), {"r": rule_id, "keys": list(objs)}).mappings().all()
    rows = [r for r in rows if r["names_hash"] != objs[r["subject_key"]]["names_hash"]]
    if not rows:
        return hits, stats
    confirmed_marks: Dict[uuid.UUID, set] = {}
    for r in session.execute(text("""
            SELECT object_key, field_name FROM rule_hits
            WHERE rule_id = :r AND object_key = ANY(:objs) AND subject_key <> object_key AND field_name IS NOT NULL
              AND reviewer IS NOT NULL AND status = 'match'
            """).bindparams(bindparam("objs", type_=UUIDS)), {"r": rule_id, "objs": [r["object_key"] for r in rows]}):
        confirmed_marks.setdefault(r.object_key, set()).add(r.field_name)

    handled, forced_pending = set(), set()
    for row in rows:
        hit = objs[row["subject_key"]]
        key = hit["object_key"]
        params = {"rule_id": rule_id, "subject_key": row["subject_key"], "rule_version": hit["rule_version"],
                  "prompt_version": hit.get("prompt_version"), "model": hit.get("model"), "reason": hit.get("reason"),
                  "names_hash": hit.get("names_hash"), "subject_hash": hit.get("subject_hash")}
        known = (object_fields or {}).get(key)
        if row["status"] not in DECIDED_STATUSES:           # reopened / edited pending hit
            if hit["rule_version"] > row["rule_version"]:
                continue                                    # _upsert_hits re-proposes it (as before)
            session.execute(_CARRY_OVER_SQL, {**params, "fields": hit.get("fields"), "msg": None})
            handled.add(row["subject_key"])
            continue
        named = [] if hit["status"] == HitStatus.no_match.value else [
            f for f in dict.fromkeys(hit.get("fields") or []) if known is None or f in known]
        before = set(row["fields"] or []) if row["status"] == HitStatus.match.value else set()
        if row["status"] != HitStatus.no_match.value:
            before |= confirmed_marks.get(key, set())
        new = [f for f in named if f not in before]
        if new and row["reviewer"] is None:
            # a harness-tier decision and the model names new fields: the service answer replaces it
            # (``_upsert_hits``: the content changed) and the verify job asks the harness model again
            stats["reverify"] = stats.get("reverify", 0) + 1
            continue
        if new:
            msg = (f"re-review: new fields {', '.join(new)} "
                   f"(was {DECISION_WORD.get(row['status'], row['status'])} by {row['reviewer']})")
            session.execute(_REVIEW_AGAIN_SQL, {**params, "fields": hit.get("fields"), "msg": msg})
            forced_pending |= {keys.field_key(key, f) for f in new}
            stats["review_again"] += 1
        else:
            label = {HitStatus.match.value: "confirmation", HitStatus.no_match.value: "rejection"}.get(row["status"], "decision (need_more_info)")
            fields = [f for f in dict.fromkeys(list(row["fields"] or []) + named) if known is None or f in known]
            by = f" (harness model {row['verifier_model']})" if row["reviewer"] is None else ""
            msg = f"{label}{by} carried over to the new version (rule v{hit['rule_version']}): no new fields"
            session.execute(_CARRY_OVER_SQL, {**params, "fields": fields or None, "msg": msg})
            stats["carried_over"] += 1
        handled.add(row["subject_key"])
    rest = [({**h, "status": HitStatus.pending_review.value} if h["subject_key"] in forced_pending else h)
            for h in hits if h["subject_key"] not in handled]
    return rest, stats


@retry_on_exception()
def upsert_llm_hits(hits: List[dict], is_main: bool, rule_id: Optional[int] = None,
                    asked_objects: Optional[Sequence[uuid.UUID]] = None,
                    object_fields: Optional[Dict[uuid.UUID, set]] = None, prompt_version: Optional[str] = None,
                    rollout_id: Optional[int] = None) -> int:
    """Store LLM verdicts. ``asked_objects`` (object rules): the objects this run asked about;
    their stale field marks are dropped in the same transaction (``_drop_stale_field_marks``).
    Object hits a human decided and that were asked again because the object's field names changed
    are carried over or sent back to review (``_reasked_human_hits``; ``object_fields``: the
    current field names of the asked objects). ``prompt_version``: the core prompts family version that made the
    verdicts (``lifecycle.code_core_version``); ``rollout_id``: a rollout slice (recorded in ``hit_verdicts``)."""
    with db.unit_of_work() as s:
        if rollout_id is not None:
            s.execute(text("SELECT set_config('discovery.rollout_id', :r, true)"), {"r": str(int(rollout_id))})
        if rule_id is not None and asked_objects:
            dropped = _drop_stale_field_marks(s, rule_id, asked_objects, hits)
            if dropped:
                logger.info(f"LLM rule {rule_id}: {dropped} field marks no longer named by the model removed")
        if prompt_version is None:
            ids = sorted({h["rule_id"] for h in hits if not h.get("prompt_version")})
            code = {r.id: lifecycle.code_core_version(r) for r in s.execute(
                text("SELECT id, target, category FROM rules WHERE id = ANY(:ids)"), {"ids": ids})} if ids else {}
            hits = [{**h, "prompt_version": h.get("prompt_version") or code.get(h["rule_id"])} for h in hits]
        else:
            hits = [{**h, "prompt_version": prompt_version} for h in hits]
        if rule_id is not None:
            hits, stats = _reasked_human_hits(s, rule_id, hits, object_fields)
            if any(stats.values()):
                logger.info(f"LLM rule {rule_id}: human decisions on renamed / changed objects: {stats}")
        written = _upsert_hits(s, hits, is_main=is_main, machine_verdicts_overwritable=True)
        # exact presence of the verdicts' objects (a run may finish after its MR closed or its branch moved)
        presence.refresh(s, object_keys=[h["object_key"] for h in hits])
        return written


####################################################
#   Queries                                     ####
####################################################

# Candidates of an LLM rule run (``discovery_common.lifecycle``): the FRESH class is asked by every run - no verdict,
# a machine verdict on other content of the subject (``subject_hash``: the object's content hash / the field's name,
# type, comment and samples), a pending hit a reviewer reopened once the rule version is newer and - object rules
# only - every hit whose object was renamed or got other field names (``names_hash``), even a human decision
# (``upsert_llm_hits`` then carries the decision over or asks for a re-review); the MIGRATION class (``:migration``:
# the slices of a rule rollout, scan_mr deltas, LLM_REASK_INLINE) adds the machine verdicts of an older rule version,
# of core prompts that are neither the pinned (``:pinned_pv``) nor the code's (``:code_pv``) or of a service model
# that is neither the version's (``:pinned_model``) nor the scanner's (``:code_model``). Harness-tier decisions (a
# harness model verified the hit, migration 0020) are kept like human ones on a new version, but asked again when
# the subject's content changed (the service answer then replaces them and the hit is verified again,
# ``services.verify_service``). Otherwise human decisions are final; a NULL stored hash (hits made before migration
# 0018 on subjects gone since) never asks again. ``h``: the rule's hit on the subject (LEFT JOIN); ``s``: the
# subject's current hashes (``s.names_hash`` NULL for field rules; SQL functions of migration 0018, the twins of
# ``discovery_common.keys``). The coverage of the LLM rules counts with the same conditions
# (services.llm_coverage_service; the queries contain ``lifecycle.FRESH_COND`` / ``MIGRATION_COND`` literally,
# checked by a test; they stay literal for the query plan tests). ``hit_bucket``: the rollout order of a stale verdict
# (need_more_info first, then positive, then no_match; fresh subjects -1).
LLM_CANDIDATE_COND = lifecycle.CANDIDATE_COND

# the subject's current hashes: the stored ones (``object_fields.llm_hash`` / ``objects.names_hash``, written with the
# content-addressed rows, migration 0030); a row without one (none after the backfill) is hashed in place
# (lateral, no FROM: pulled up into the condition, so that only happens when the condition gets to it)
LLM_FIELD_SUBJECT = ("CROSS JOIN LATERAL (SELECT COALESCE(f.llm_hash, llm_field_hash(f.field_name, f.field_type, "
                     "f.comment, f.samples)) AS subject_hash, NULL::text AS names_hash) s")
LLM_OBJECT_SUBJECT = ("CROSS JOIN LATERAL (SELECT o.content_hash::text AS subject_hash, COALESCE(o.names_hash, "
                      "llm_names_hash(o.name, ARRAY(SELECT x.field_name FROM object_fields x "
                      "WHERE x.content_hash = o.content_hash))) AS names_hash) s")

LLM_CANDIDATES_SQL = text("""
    SELECT o.object_key, o.content_hash, o.project_id, o.name, o.type, o.parser, o.file, o.props,
           f.field_name, f.field_type, f.field_key,
           CASE WHEN h.subject_key IS NULL THEN -1 WHEN h.status = 'need_more_info' THEN 0
                WHEN h.status IN ('pending_review', 'match') THEN 1 ELSE 2 END AS hit_bucket
    FROM branch_objects b
    JOIN objects o ON o.content_hash = b.content_hash
    JOIN object_fields f ON f.content_hash = b.content_hash
    LEFT JOIN rule_hits h ON h.rule_id = :rule_id AND h.subject_key = f.field_key
    CROSS JOIN LATERAL (SELECT COALESCE(f.llm_hash, llm_field_hash(f.field_name, f.field_type, f.comment, f.samples)) AS subject_hash, NULL::text AS names_hash) s
    WHERE b.branch_id = :branch_id AND b.content_hash IS NOT NULL
      AND ((h.subject_key IS NULL
           OR (h.reviewer IS NULL AND h.subject_hash IS NOT NULL AND COALESCE(h.subject_hash <> s.subject_hash, false))
           OR (h.status = 'pending_review' AND h.reviewer IS NOT NULL AND h.rule_version < :rule_version)
           OR (h.names_hash IS NOT NULL AND COALESCE(h.names_hash <> s.names_hash, false)))
        OR (CAST(:migration AS boolean) AND (h.reviewer IS NULL AND h.decided_tier <> 'harness'
           AND (h.rule_version < :rule_version
                OR (h.prompt_version IS DISTINCT FROM :pinned_pv AND h.prompt_version IS DISTINCT FROM :code_pv)
                OR (CAST(:pinned_model AS text) IS NOT NULL AND h.model IS DISTINCT FROM :pinned_model
                    AND h.model IS DISTINCT FROM :code_model AND COALESCE(h.model, '') NOT LIKE '% via %')))))
    ORDER BY o.object_key, f.field_name
""")

LLM_OBJECT_CANDIDATES_SQL = text("""
    SELECT o.object_key, o.content_hash, o.project_id, o.name, o.type, o.parser, o.file, o.props,
           NULL::text AS field_name, NULL::text AS field_type, o.object_key AS field_key,
           CASE WHEN h.subject_key IS NULL THEN -1 WHEN h.status = 'need_more_info' THEN 0
                WHEN h.status IN ('pending_review', 'match') THEN 1 ELSE 2 END AS hit_bucket
    FROM branch_objects b
    JOIN objects o ON o.content_hash = b.content_hash
    LEFT JOIN rule_hits h ON h.rule_id = :rule_id AND h.subject_key = o.object_key
    CROSS JOIN LATERAL (SELECT o.content_hash::text AS subject_hash, COALESCE(o.names_hash, llm_names_hash(o.name, ARRAY(SELECT x.field_name FROM object_fields x WHERE x.content_hash = o.content_hash))) AS names_hash) s
    WHERE b.branch_id = :branch_id AND b.content_hash IS NOT NULL
      AND ((h.subject_key IS NULL
           OR (h.reviewer IS NULL AND h.subject_hash IS NOT NULL AND COALESCE(h.subject_hash <> s.subject_hash, false))
           OR (h.status = 'pending_review' AND h.reviewer IS NOT NULL AND h.rule_version < :rule_version)
           OR (h.names_hash IS NOT NULL AND COALESCE(h.names_hash <> s.names_hash, false)))
        OR (CAST(:migration AS boolean) AND (h.reviewer IS NULL AND h.decided_tier <> 'harness'
           AND (h.rule_version < :rule_version
                OR (h.prompt_version IS DISTINCT FROM :pinned_pv AND h.prompt_version IS DISTINCT FROM :code_pv)
                OR (CAST(:pinned_model AS text) IS NOT NULL AND h.model IS DISTINCT FROM :pinned_model
                    AND h.model IS DISTINCT FROM :code_model AND COALESCE(h.model, '') NOT LIKE '% via %')))))
    ORDER BY o.object_key
""")


def reask_inline(settings=None) -> bool:
    """LLM_REASK_INLINE: every run asks the MIGRATION class too (the behaviour before the rule lifecycle)."""
    settings = settings or get_settings()
    return bool(getattr(settings, "llm_reask_inline", False))


def candidate_params(rule, migration: Optional[bool] = None, settings=None) -> dict:
    """Bind parameters of the candidate conditions for ``rule`` (``migration`` None: LLM_REASK_INLINE)."""
    settings = settings or get_settings()
    if migration is None:
        migration = reask_inline(settings)
    return lifecycle.version_params(rule, getattr(settings, "llm_api_model", None), migration)


@retry_on_exception()
def get_llm_candidates(branch_id: int, rule: Rule, migration: Optional[bool] = None) -> List[dict]:
    """Subjects of a branch an LLM rule asks about: the FRESH class (no verdict yet, other content, ...) and, with
    ``migration`` (a rollout slice; None: LLM_REASK_INLINE), the machine verdicts of an older version of the rule:
    fields (``target = field``) or objects (``target = object``, one row per object, ``field_name`` NULL). For an MR
    source branch the rows are the delta, so only new/changed objects are candidates."""
    sql = LLM_OBJECT_CANDIDATES_SQL if rule.target == "object" else LLM_CANDIDATES_SQL
    with db.unit_of_work() as s:
        return [dict(r) for r in s.execute(
            sql, {"rule_id": rule.id, "branch_id": branch_id, **candidate_params(rule, migration)}).mappings()]


RESERVED_SQL = """
    rule_id = :r AND rule_version = :v AND purpose = 'score' AND (
        status = 'answered'
        OR (status = 'leased' AND lease_until > now())
        OR (status = 'pending' AND created_at > now() - make_interval(secs => :reserve_s)))"""


@retry_on_exception()
def get_reserved_llm_objects(rule_id: int, rule_version: int) -> set:
    """Objects the external executor holds for a rule version; a service run leaves them to it
    (no double model calls). A reservation lapses so a crashed harness blocks nothing for long:
    an answered item holds its object until it is applied, a claimed one until its lease ends,
    an unclaimed one for LLM_EXTERNAL_RESERVE_H hours."""
    with db.unit_of_work() as s:
        return {r[0] for r in s.execute(text(
            f"SELECT DISTINCT object_key FROM llm_work_items WHERE {RESERVED_SQL}"),
            {"r": rule_id, "v": rule_version, "reserve_s": get_settings().llm_external_reserve_h * 3600})}


def take_over_llm_objects(rule_id: int, rule_version: int, object_keys: Sequence[uuid.UUID]) -> List[int]:
    """A service run asks about objects whose external reservation lapsed: their open items
    (pending / leased) expire, so no harness works on them any more (a late answer would not be
    applied either: the object is no longer a candidate). Returns the jobs whose items changed."""
    if not object_keys:
        return []
    with db.unit_of_work() as s:
        jobs_changed = {r[0] for r in s.execute(text(f"""
            UPDATE llm_work_items SET status = 'expired', updated_at = now(),
                   error = 'taken over by a service run (the reservation lapsed)'
            WHERE rule_id = :r AND rule_version = :v AND object_key = ANY(:objs) AND purpose = 'score'
              AND status IN ('pending', 'leased') AND NOT ({RESERVED_SQL})
            RETURNING job_id"""), {"r": rule_id, "v": rule_version, "objs": list(object_keys),
                                   "reserve_s": get_settings().llm_external_reserve_h * 3600})}
    return sorted(jobs_changed)


@retry_on_exception()
def get_object_fields(content_hashes: Iterable[uuid.UUID]) -> Dict[uuid.UUID, List[Tuple[str, str]]]:
    hashes = list(set(content_hashes))
    result: Dict[uuid.UUID, List[Tuple[str, str]]] = {h: [] for h in hashes}
    if not hashes:
        return result
    with db.unit_of_work() as s:
        rows = s.execute(text(
            "SELECT content_hash, field_name, field_type FROM object_fields WHERE content_hash = ANY(:h) "
            "ORDER BY content_hash, field_name").bindparams(bindparam("h", type_=UUIDS)), {"h": hashes})
        for row in rows:
            result[row.content_hash].append((row.field_name, row.field_type))
    return result


@retry_on_exception()
def get_object_docs(content_hashes: Iterable[uuid.UUID]) -> Dict[uuid.UUID, Tuple[Optional[str], Dict[str, tuple]]]:
    """``{content_hash: (object comment, {field_name: (comment, samples)})}`` (fields with docs only)."""
    hashes = list(set(content_hashes))
    result: Dict[uuid.UUID, Tuple[Optional[str], Dict[str, tuple]]] = {}
    if not hashes:
        return result
    with db.unit_of_work() as s:
        param = bindparam("h", type_=UUIDS)
        for row in s.execute(text("SELECT content_hash, comment FROM objects WHERE content_hash = ANY(:h)")
                             .bindparams(param), {"h": hashes}):
            result[row.content_hash] = (row.comment, {})
        for row in s.execute(text(
                "SELECT content_hash, field_name, comment, samples FROM object_fields "
                "WHERE content_hash = ANY(:h) AND (comment IS NOT NULL OR samples IS NOT NULL)")
                .bindparams(param), {"h": hashes}):
            result.setdefault(row.content_hash, (None, {}))[1][row.field_name] = (row.comment, row.samples)
    return result


# ---- external parsers (POST /ingest) ---------------------------------------------------------

@retry_on_exception()
def latest_ingest_batch(project_id: int, parser: str) -> Optional[dict]:
    """The latest committed / processed state of (project, parser) with its objects (chunks in
    order; an object repeated across chunks keeps its first occurrence)."""
    with db.unit_of_work() as s:
        row = s.execute(text("""SELECT id, snapshot, status, llm FROM ingest_batches
                                WHERE project_id = :p AND parser = :parser AND status IN ('committed', 'processed')
                                ORDER BY id DESC LIMIT 1"""), {"p": project_id, "parser": parser}).mappings().first()
        if row is None:
            return None
        objects = []
        for chunk in s.execute(text("SELECT payload FROM ingest_chunks WHERE batch_id = :b ORDER BY seq"),
                               {"b": row["id"]}):
            objects.extend((chunk.payload or {}).get("objects") or [])
        return {**dict(row), "objects": objects}


# a deterministic label of an external project's snapshot: its latest processed batch per parser
SNAPSHOT_LABEL_SQL = text("""
    SELECT 'ingest-' || md5(COALESCE(string_agg(parser || ':' || id, ',' ORDER BY parser), '')) FROM (
        SELECT DISTINCT ON (parser) parser, id FROM ingest_batches
        WHERE project_id = :p AND status = 'processed' ORDER BY parser, id DESC) latest""")


@retry_on_exception()
def finish_ingest_batch(batch_id: int, project_id: int, parser: str, branch_id: int, stats: dict) -> int:
    """Mark the batch processed, label the branch with the snapshot of all its parsers (commit
    = scanned_commit), supersede the older batches of the same (project, parser) (their chunks
    are deleted, the rows keep their Idempotency-Key; open upload sessions are kept). Returns
    the number of batches superseded."""
    with db.unit_of_work() as s:
        s.execute(text("""UPDATE ingest_batches SET status = 'processed', processed_at = now(), error = NULL,
                          stats = CAST(:st AS jsonb) WHERE id = :b"""), {"b": batch_id, "st": json.dumps(stats, default=str)})
        label = s.execute(SNAPSHOT_LABEL_SQL, {"p": project_id}).scalar()
        s.execute(update(Branch).where(Branch.id == branch_id).values(commit=label, scanned_commit=label,
                                                                         updated_at=func.now()))
        # older states: their chunks go, the rows stay as 'superseded' so their Idempotency-Key
        # is still known (a late retry is replayed, not applied over the newer state); the
        # cleanup deletes them after INGEST_SUPERSEDED_RETENTION
        older = s.execute(text("""UPDATE ingest_batches SET status = 'superseded'
                                  WHERE project_id = :p AND parser = :parser AND id < :b
                                    AND status NOT IN ('open', 'superseded') RETURNING id"""),
                          {"p": project_id, "parser": parser, "b": batch_id}).scalars().all()
        if older:
            s.execute(text("DELETE FROM ingest_chunks WHERE batch_id = ANY(:ids)"), {"ids": list(older)})
        return len(older)


@retry_on_exception()
def fail_ingest_batch(batch_id: int, error: str, final: bool) -> None:
    with db.unit_of_work() as s:
        s.execute(text("""UPDATE ingest_batches SET error = :e,
                          status = CASE WHEN :final AND status = 'committed' THEN 'failed' ELSE status END
                          WHERE id = :b"""), {"b": batch_id, "e": error[:2000], "final": final})
