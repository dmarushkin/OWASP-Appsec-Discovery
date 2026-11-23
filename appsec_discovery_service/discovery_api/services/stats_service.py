"""Precomputed statistics (``stats_snapshots``, contract 4) served instead of aggregating millions of rows per request.

The scanner's ``stats_refresh`` job (pipeline wave, every ``STATS_REFRESH_S``) writes one row per name - ``overview``,
``job_health``, ``scan_progress``, ``llm_progress``, ``llm_quality``, ``hits_aggregate`` - with ``data`` = exactly what
the corresponding API function computes and ``computed_at``. The API serves the row while it is fresh (younger than
``STATS_FRESH_FACTOR`` x the interval), computes live when the row is missing or stale, and always when the request
carries filters the snapshot does not hold (a project, a rule, a category, ...).

Every answer carries ``computed_at`` and ``snapshot`` (true: served from the table). REST responses of a snapshot
get a weak ``ETag`` of the name and ``computed_at``; a request with a matching ``If-None-Match`` gets ``304`` -
the UI polls every few seconds, the dashboards cost nothing between two refreshes. ``Cache-Control: max-age`` is
the time to the next expected refresh.
"""

from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

STATS_FRESH_FACTOR = 2
NAMES = ("overview", "job_health", "scan_progress", "llm_progress", "llm_quality", "hits_aggregate")

SNAPSHOT_SQL = text("SELECT data, computed_at FROM stats_snapshots WHERE name = :name")


def refresh_interval_s() -> int:
    from config import get_settings
    return get_settings().stats_refresh_s


def read_snapshot(session: Session, name: str, max_age_s: Optional[float] = None) -> Optional[Tuple[Any, datetime]]:
    """``(data, computed_at)`` of a snapshot younger than ``max_age_s`` (default: STATS_FRESH_FACTOR x the refresh
    interval; 0 disables the snapshots), None when missing or stale."""
    if max_age_s is None:
        max_age_s = STATS_FRESH_FACTOR * refresh_interval_s()
    if max_age_s <= 0:
        return None
    try:
        row = session.execute(SNAPSHOT_SQL, {"name": name}).first()
    except Exception:            # the table is missing (a database before migration 0030): compute live
        session.rollback()
        return None
    if row is None:
        return None
    data, computed_at = row
    now = session.execute(text("SELECT now()")).scalar()
    if (now - computed_at).total_seconds() > max_age_s:
        return None
    return data, computed_at


def etag(name: str, computed_at: datetime) -> str:
    return f'W/"{name}:{computed_at.isoformat()}"'


def serve(session: Session, name: str, compute: Callable[[], Dict[str, Any]], *, live: bool = False,
          request=None, response=None) -> Any:
    """The snapshot ``name`` when fresh and ``live`` is false, else ``compute()``. The result (a dict) gets
    ``computed_at`` and ``snapshot``; with ``request`` / ``response`` (FastAPI) the snapshot sets ``ETag`` /
    ``Cache-Control`` and a matching ``If-None-Match`` returns a 304 ``Response``."""
    from fastapi import Response

    snapshot = None if live else read_snapshot(session, name)
    if snapshot is None:
        data = compute()
        if isinstance(data, dict):
            data.setdefault("computed_at", datetime.now(timezone.utc))
            data["snapshot"] = False
        if response is not None:
            response.headers["Cache-Control"] = "no-store"
        return data
    data, computed_at = snapshot
    tag = etag(name, computed_at)
    if request is not None and _matches(request.headers.get("if-none-match"), tag):
        return Response(status_code=304, headers={"ETag": tag})
    if response is not None:
        response.headers["ETag"] = tag
        now = session.execute(text("SELECT now()")).scalar()
        remaining = max(1, int(refresh_interval_s() - (now - computed_at).total_seconds()))
        response.headers["Cache-Control"] = f"private, max-age={remaining}"
    if isinstance(data, dict):
        data = {**data, "computed_at": computed_at, "snapshot": True}
    return data


def _matches(header: Optional[str], tag: str) -> bool:
    if not header:
        return False
    wanted = {t.strip() for t in header.split(",")}
    return "*" in wanted or tag in wanted or tag[2:] in wanted
