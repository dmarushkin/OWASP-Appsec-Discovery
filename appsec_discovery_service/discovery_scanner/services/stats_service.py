"""The ``stats_refresh`` job (control pool, every STATS_REFRESH_S): recompute the statistics snapshots of
``discovery_common.stats`` into ``stats_snapshots``, one transaction per snapshot (a failing one leaves the others
fresh and is logged). The ``job_health`` snapshot carries, besides what the API computes live, the day's
escalations (``escalations``: items and the overflow over LLM_ESCALATION_DAILY_MAX, contract "escalation cap") and
the scanner's throughput settings (``limits``: workers per pool, LLM_CONCURRENCY, LLM_RATE_PER_MIN and the tokens
left in the shared bucket). Every snapshot's compute time is returned (and warned about when the whole pass takes
longer than half the interval: raise STATS_REFRESH_S then)."""

import time
from typing import Callable, Dict, Optional

from discovery_common import db, llm_rate, stats
from config import get_settings
from logger import get_logger

logger = get_logger(__name__)


def _limits(settings, conn) -> Dict:
    try:
        tokens = llm_rate.tokens_left(settings.llm_rate_per_min, conn=conn)
    except Exception:           # the bucket row does not exist yet, or a transient error
        tokens = None
    return {"scan_workers": settings.max_workers, "sync_workers": settings.sync_workers,
            "control_workers": settings.control_workers, "llm_workers": settings.llm_workers,
            "llm_concurrency": settings.llm_concurrency, "llm_rate_per_min": settings.llm_rate_per_min or None,
            "llm_rate_tokens_left": round(tokens, 1) if tokens is not None else None,
            "escalation_daily_max": settings.llm_escalation_daily_max}


def _job_health(settings) -> Callable:
    def compute(conn):
        data = stats.job_health(conn)
        data["escalations"] = stats.escalations_today(conn, settings.llm_escalation_daily_max)
        data["limits"] = _limits(settings, conn)
        return data
    return compute


def computations(settings) -> Dict[str, Callable]:
    """``{snapshot name: compute(conn)}`` in the order they are refreshed."""
    return {
        "job_health": _job_health(settings),
        "scan_progress": stats.scan_progress,
        "llm_progress": stats.llm_progress,
        "llm_quality": lambda conn: stats.llm_quality(conn, settings.llm_qa_agreement_min),
        "hits_aggregate": stats.hits_aggregate,
        "overview": stats.overview,
    }


def refresh(name: str, compute: Callable, conn=None) -> float:
    """Compute and write one snapshot; returns the seconds it took."""
    started = time.monotonic()
    if conn is not None:
        stats.write_snapshot(conn, name, compute(conn))
    else:
        with db.get_engine().begin() as own:
            stats.write_snapshot(own, name, compute(own))
    return time.monotonic() - started


def refresh_all(settings=None, job_id: Optional[int] = None) -> Dict[str, float]:
    """Every snapshot, each in its own transaction; ``{name: seconds}`` (a failed one: -1, logged)."""
    settings = settings or get_settings()
    timings: Dict[str, float] = {}
    started = time.monotonic()
    for name, compute in computations(settings).items():
        try:
            timings[name] = round(refresh(name, compute), 3)
        except Exception as e:
            timings[name] = -1.0
            logger.error(f"Statistics snapshot {name} not refreshed: {e}")
    total = time.monotonic() - started
    interval = settings.stats_refresh_s
    if interval and total > interval / 2:
        logger.warning(f"Statistics snapshots took {total:.1f}s, more than half of STATS_REFRESH_S={interval:.0f}: "
                       f"{timings}")
    else:
        logger.info(f"Statistics snapshots refreshed in {total:.1f}s: {timings}")
    return timings
