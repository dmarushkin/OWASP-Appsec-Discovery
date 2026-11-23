"""Objects pushed by external parsers (``POST /ingest``): databases / tables / columns from
SQL servers, a CMDB, an API gateway export, ...

A push is the full state of one parser for one external project (``external/...``; created
on the first push, never cloned or synced from GitLab; one main branch, ``snapshot``). It is
stored as a batch (its objects in chunks: one for ``POST /ingest``, many for an upload
session) and an ``ingest`` job applies the keyword rules (core scoring; nothing in inventory
mode) and saves it as the project's snapshot for that parser, like parsed code: hits,
decisions, tags, review queue, LLM rules over the stored snapshot all work the same. Objects
missing from a new state are removed from the snapshot (decisions on them are kept and come
back with the object).

Idempotency: a push whose content equals the latest processed state of the (project, parser),
or a committed one still being applied, creates nothing (``unchanged: true``); an
``Idempotency-Key`` returns the batch first created with it (``replayed: true``), also after
newer states replaced it (status ``superseded``: kept without chunks for the key's retention).
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from schemas import (
    SESSION_MAX_FIELDS, SESSION_MAX_OBJECTS, IngestIn, IngestObject, IngestSessionIn, IngestTarget,
)
from services.errors import Conflict, Forbidden, Invalid, NotFound, TooLarge
from services.paging import escape_like

SNAPSHOT_BRANCH = "snapshot"
OPEN_SESSION_HOURS = 24


def _chunk(objects: List[IngestObject]) -> Dict[str, Any]:
    """Canonical chunk payload (objects sorted by identity, props as text) and its hash."""
    payload = sorted((o.payload() for o in objects), key=lambda o: (o["type"], o.get("file") or "", o["name"]))
    raw = json.dumps({"objects": payload}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {"payload": raw, "objects": len(payload), "fields": sum(len(o.get("fields") or []) for o in payload),
            "content_hash": hashlib.sha256(raw.encode()).hexdigest()}


def _project(session: Session, path: str, user) -> int:
    if not user.may_ingest(path):
        raise Forbidden(f"this token may not push to {path}")
    session.execute(text("""
        INSERT INTO gitlab_projects (project_name, full_path, visibility, source, created_by, created_at, updated_at)
        VALUES (:name, :path, 'private', 'external', :by, now(), now())
        ON CONFLICT (full_path) DO NOTHING"""), {"name": path.rsplit("/", 1)[-1], "path": path, "by": user.username})
    row = session.execute(text("SELECT id, source FROM gitlab_projects WHERE full_path = :p"), {"p": path}).one()
    if row.source != "external":
        raise Conflict(f"{path} is a GitLab project")
    return row.id


def _branch(session: Session, project_id: int, path: str) -> int:
    session.execute(text("""
        INSERT INTO gitlab_branches (branch_name, is_main, commit, project_id, project_path, created_at, updated_at)
        VALUES (:b, true, 'ingest-none', :p, :path, now(), now()) ON CONFLICT (project_id, branch_name) DO NOTHING"""),
        {"b": SNAPSHOT_BRANCH, "p": project_id, "path": path})
    return session.execute(text("SELECT id FROM gitlab_branches WHERE project_id = :p AND branch_name = :b"),
                           {"p": project_id, "b": SNAPSHOT_BRANCH}).scalar()


def _by_key(session: Session, project_id: int, parser: str, key: Optional[str]) -> Optional[dict]:
    if not key:
        return None
    row = session.execute(text("""SELECT id, status, objects, fields FROM ingest_batches
                                  WHERE project_id = :p AND parser = :parser AND idempotency_key = :k"""),
                          {"p": project_id, "parser": parser, "k": key}).mappings().first()
    return dict(row) if row else None


def _unchanged(session: Session, project_id: int, parser: str, content_hash: str) -> Optional[int]:
    """The latest state that is or will be applied, when it equals ``content_hash``: a
    processed batch, or a committed one whose ingest job is still pending / running. A
    committed batch without an active job (its job failed or was lost: legacy stuck rows)
    will never be applied, so a push of the same state must create a new batch."""
    row = session.execute(text("""
        SELECT b.id, b.content_hash FROM ingest_batches b
        WHERE b.project_id = :p AND b.parser = :parser
          AND (b.status = 'processed'
               OR (b.status = 'committed' AND EXISTS (
                       SELECT 1 FROM jobs j WHERE j.kind = 'ingest' AND j.status IN ('pending', 'running')
                         AND j.payload->>'batch_id' = b.id::text)))
        ORDER BY b.id DESC LIMIT 1"""), {"p": project_id, "parser": parser}).first()
    return row.id if row is not None and row.content_hash == content_hash else None


def _commit(session: Session, batch_id: int, project_id: int, branch_id: int, parser: str, llm: bool,
            content_hash: str, requested_by: Optional[str]) -> Optional[int]:
    from discovery_common import jobs
    session.execute(text("""UPDATE ingest_batches SET status = 'committed', committed_at = now(), content_hash = :h,
                            objects = (SELECT COALESCE(sum(objects), 0) FROM ingest_chunks WHERE batch_id = :b),
                            fields = (SELECT COALESCE(sum(fields), 0) FROM ingest_chunks WHERE batch_id = :b)
                            WHERE id = :b"""), {"b": batch_id, "h": content_hash})
    # one job per batch: a push while a job of the same parser runs is never lost (the job of
    # the newer batch waits for the scan lock and processes the latest committed batch)
    return jobs.enqueue("ingest", {"project_id": project_id, "branch_id": branch_id, "parser": parser,
                                   "batch_id": batch_id, **({"requested_by": requested_by} if requested_by else {})},
                        f"ingest:{project_id}:{parser}:{batch_id}", conn=session)


def _new_batch(session: Session, target: IngestTarget, project_id: int, idempotency_key: Optional[str],
               user) -> Optional[int]:
    """The new batch's id, or None when a concurrent request just created one with the same
    Idempotency-Key (the unique index waits for it: the caller replays that one, no 500)."""
    snapshot = target.snapshot or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return session.execute(text("""
        INSERT INTO ingest_batches (project_id, parser, snapshot, status, llm, idempotency_key, created_by)
        VALUES (:p, :parser, :s, 'open', :llm, :k, :by)
        ON CONFLICT (project_id, parser, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
        RETURNING id"""),
        {"p": project_id, "parser": target.parser, "s": snapshot, "llm": target.llm, "k": idempotency_key,
         "by": user.username}).scalar()


def _result(project_id, target, batch_id, job_id=None, **extra) -> Dict[str, Any]:
    return {"project_id": project_id, "project": target.project, "parser": target.parser, "batch_id": batch_id,
            "job_id": job_id, **extra}


# ---- one request ----------------------------------------------------------------------------

def create_batch(session: Session, data: IngestIn, user, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
    project_id = _project(session, data.project, user)
    branch_id = _branch(session, project_id, data.project)
    existing = _by_key(session, project_id, data.parser, idempotency_key)
    if existing is not None:
        return _result(project_id, data, existing["id"], status=existing["status"], replayed=True)
    chunk = _chunk(data.objects)
    content_hash = hashlib.sha256(chunk["content_hash"].encode()).hexdigest()
    same = _unchanged(session, project_id, data.parser, content_hash)
    if same is not None:
        return _result(project_id, data, same, unchanged=True, objects=chunk["objects"], fields=chunk["fields"])
    batch_id = _new_batch(session, data, project_id, idempotency_key, user)
    if batch_id is None:
        existing = _by_key(session, project_id, data.parser, idempotency_key)
        return _result(project_id, data, existing["id"], status=existing["status"], replayed=True)
    _put_chunk(session, batch_id, 0, chunk)
    job_id = _commit(session, batch_id, project_id, branch_id, data.parser, data.llm, content_hash, user.username)
    return _result(project_id, data, batch_id, job_id, status="committed", objects=chunk["objects"],
                   fields=chunk["fields"])


def _put_chunk(session: Session, batch_id: int, seq: int, chunk: Dict[str, Any]) -> None:
    session.execute(text("""
        INSERT INTO ingest_chunks (batch_id, seq, payload, objects, fields, content_hash)
        VALUES (:b, :seq, CAST(:payload AS jsonb), :n, :f, :h)
        ON CONFLICT (batch_id, seq) DO UPDATE SET payload = EXCLUDED.payload, objects = EXCLUDED.objects,
            fields = EXCLUDED.fields, content_hash = EXCLUDED.content_hash"""),
        {"b": batch_id, "seq": seq, "payload": chunk["payload"], "n": chunk["objects"], "f": chunk["fields"],
         "h": chunk["content_hash"]})


# ---- upload sessions (large states in chunks) -----------------------------------------------

def start_session(session: Session, data: IngestSessionIn, user, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
    project_id = _project(session, data.project, user)
    _branch(session, project_id, data.project)
    existing = _by_key(session, project_id, data.parser, idempotency_key)
    if existing is not None:
        return _result(project_id, data, existing["id"], session_id=existing["id"], status=existing["status"],
                       replayed=True)
    batch_id = _new_batch(session, data, project_id, idempotency_key, user)
    if batch_id is None:
        existing = _by_key(session, project_id, data.parser, idempotency_key)
        return _result(project_id, data, existing["id"], session_id=existing["id"], status=existing["status"],
                       replayed=True)
    return _result(project_id, data, batch_id, session_id=batch_id, status="open",
                   expires_in_hours=OPEN_SESSION_HOURS)


def _open_session(session: Session, session_id: int, user) -> dict:
    row = session.execute(text("""
        SELECT b.id, b.project_id, b.parser, b.status, b.llm, b.objects, b.fields, p.full_path, g.id AS branch_id
        FROM ingest_batches b JOIN gitlab_projects p ON p.id = b.project_id
        JOIN gitlab_branches g ON g.project_id = b.project_id AND g.branch_name = :b
        WHERE b.id = :id FOR UPDATE OF b"""), {"id": session_id, "b": SNAPSHOT_BRANCH}).mappings().first()
    if row is None or not user.may_ingest(row["full_path"]):
        raise NotFound(f"upload session {session_id} not found")
    if row["status"] != "open":
        raise Conflict(f"upload session {session_id} is {row['status']}, not open")
    return dict(row)


def put_chunk(session: Session, session_id: int, seq: int, objects: List[IngestObject], user) -> Dict[str, Any]:
    if not 0 <= seq <= 100_000:
        raise Invalid("seq must be between 0 and 100000")
    _open_session(session, session_id, user)
    chunk = _chunk(objects)
    totals = session.execute(text("""SELECT COALESCE(sum(objects), 0) o, COALESCE(sum(fields), 0) f
                                     FROM ingest_chunks WHERE batch_id = :b AND seq <> :seq"""),
                             {"b": session_id, "seq": seq}).one()
    if totals.o + chunk["objects"] > SESSION_MAX_OBJECTS or totals.f + chunk["fields"] > SESSION_MAX_FIELDS:
        raise TooLarge(f"an upload session holds at most {SESSION_MAX_OBJECTS} objects / {SESSION_MAX_FIELDS} fields")
    _put_chunk(session, session_id, seq, chunk)
    return {"session_id": session_id, "seq": seq, "objects": chunk["objects"], "fields": chunk["fields"],
            "session_objects": totals.o + chunk["objects"], "session_fields": totals.f + chunk["fields"]}


def commit_session(session: Session, session_id: int, user) -> Dict[str, Any]:
    """Apply the uploaded chunks as one new state (objects duplicated across chunks keep the
    first occurrence, with a warning in the job's log)."""
    batch = _open_session(session, session_id, user)
    hashes = [r[0] for r in session.execute(text(
        "SELECT content_hash FROM ingest_chunks WHERE batch_id = :b ORDER BY seq"), {"b": session_id})]
    if not hashes:
        raise Invalid("the session has no chunk")
    content_hash = hashlib.sha256("".join(hashes).encode()).hexdigest()
    target = IngestTarget.model_construct(project=batch["full_path"], parser=batch["parser"])
    same = _unchanged(session, batch["project_id"], batch["parser"], content_hash)
    if same is not None:
        session.execute(text("DELETE FROM ingest_batches WHERE id = :b"), {"b": session_id})
        return _result(batch["project_id"], target, same, unchanged=True)
    job_id = _commit(session, session_id, batch["project_id"], batch["branch_id"], batch["parser"], batch["llm"],
                     content_hash, user.username)
    totals = session.execute(text("SELECT objects, fields FROM ingest_batches WHERE id = :b"), {"b": session_id}).one()
    return _result(batch["project_id"], target, session_id, job_id, status="committed", objects=totals.objects,
                   fields=totals.fields)


def abort_session(session: Session, session_id: int, user) -> Dict[str, Any]:
    _open_session(session, session_id, user)
    session.execute(text("DELETE FROM ingest_batches WHERE id = :b"), {"b": session_id})
    return {"session_id": session_id, "aborted": True}


def list_batches(session: Session, user, project_id: Optional[int] = None, limit: int = 50,
                 include_superseded: bool = False) -> list:
    """Latest batches, newest first; a service token sees only its project prefixes (filtered
    in SQL, before the LIMIT). ``superseded`` batches (older states replaced by a newer
    processed one, kept without their chunks only so that their Idempotency-Key still
    replays) are hidden unless ``include_superseded``."""
    where, binds = [], {"p": project_id, "limit": max(1, min(int(limit), 500))}
    if not include_superseded:
        where.append("b.status <> 'superseded'")
    if project_id:
        where.append("b.project_id = :p")
    if user.is_service:
        prefixes = [p.rstrip("/") for p in user.project_prefixes or [] if p.rstrip("/")]
        if "ingest" not in (user.scopes or []) or not prefixes:
            return []
        where.append("(p.full_path = ANY(:exact) OR p.full_path LIKE ANY(:likes))")   # LIKE escapes with '\'
        binds.update(exact=prefixes, likes=[escape_like(p) + "/%" for p in prefixes])
    rows = session.execute(text(f"""
        SELECT b.id, b.project_id, p.full_path AS project, b.parser, b.snapshot, b.status, b.llm, b.objects, b.fields,
               b.created_by, b.created_at, b.committed_at, b.processed_at, b.stats, left(b.error, 500) AS error
        FROM ingest_batches b JOIN gitlab_projects p ON p.id = b.project_id
        {("WHERE " + " AND ".join(where)) if where else ""}
        ORDER BY b.id DESC LIMIT :limit"""), binds).mappings()
    return [dict(r) for r in rows if user.may_ingest(r["project"])]
