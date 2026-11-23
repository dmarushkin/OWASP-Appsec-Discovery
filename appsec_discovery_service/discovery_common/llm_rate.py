"""A token bucket in Postgres for the service model calls (LLM_RATE_PER_MIN), shared by every LLM worker, every
thread of a worker and every scanner replica (migration 0031, table ``llm_rate_buckets``).

One row per bucket (``service``): ``tokens`` left at ``updated_at``, refilled at ``rate`` tokens per second up to a
capacity of one minute's worth (``rate * 60``, so an idle minute buys a burst of at most a minute). ``acquire``
takes ``n`` tokens in one UPDATE (``FOR UPDATE`` on the row: a short lock, no contention worth noticing at tens of
calls per second) and returns how long to wait when there are not enough; ``wait`` sleeps and tries again until it
gets them or ``stop()`` says so. A rate of 0 means no limit (nothing is read or written).

The limit is on calls, not tokens of the model: it is what API providers meter per minute and what a local server
queues on. Concurrency within a worker (LLM_CONCURRENCY) and the number of workers only decide how many calls are
in flight; this bucket caps how many start per minute over all of them.
"""

import time
from dataclasses import dataclass
from typing import Callable, Optional

from sqlalchemy import text

from discovery_common import db
from discovery_common.log import get_logger

logger = get_logger(__name__)

BUCKET = "service"

ENSURE_SQL = text("""
    INSERT INTO llm_rate_buckets (name, tokens, updated_at) VALUES (:name, :cap, now())
    ON CONFLICT (name) DO NOTHING""")

# refill since updated_at (capped), take :n when there are enough; the row keeps the refilled value either way so a
# later call does not refill the same seconds twice
ACQUIRE_SQL = text("""
    WITH cur AS (
        SELECT name, LEAST(CAST(:cap AS double precision),
                           tokens + :rate * extract(epoch FROM (now() - updated_at))) AS filled
        FROM llm_rate_buckets WHERE name = :name FOR UPDATE)
    UPDATE llm_rate_buckets b
    SET tokens = CASE WHEN cur.filled >= :n THEN cur.filled - :n ELSE cur.filled END, updated_at = now()
    FROM cur WHERE b.name = cur.name
    RETURNING (cur.filled >= :n) AS granted, cur.filled AS filled""")


@dataclass(frozen=True)
class Grant:
    granted: bool
    wait_s: float          # how long until ``n`` tokens are there (0 when granted)
    tokens_left: float


def acquire(rate_per_min: float, n: int = 1, name: str = BUCKET, conn=None) -> Grant:
    """Take ``n`` tokens from the bucket refilled at ``rate_per_min``; ``rate_per_min <= 0``: always granted."""
    if rate_per_min <= 0:
        return Grant(True, 0.0, float("inf"))
    rate = float(rate_per_min) / 60.0
    cap = max(float(rate_per_min), float(n))
    params = {"name": name, "cap": cap, "rate": rate, "n": float(n)}

    def run(c):
        c.execute(ENSURE_SQL, params)
        row = c.execute(ACQUIRE_SQL, params).first()
        return row

    if conn is not None:
        row = run(conn)
    else:
        with db.get_engine().begin() as own:
            row = run(own)
    filled = float(row.filled)
    if row.granted:
        return Grant(True, 0.0, filled - n)
    return Grant(False, max(0.05, (n - filled) / rate), filled)


def wait(rate_per_min: float, n: int = 1, *, name: str = BUCKET, stop: Optional[Callable[[], bool]] = None,
         sleep: Callable[[float], None] = time.sleep, max_wait_s: float = 5.0) -> bool:
    """Block until ``n`` tokens are taken (True) or ``stop()`` returns True (False). A database error lets the call
    through (logged): the limit is a courtesy to the provider, not a correctness guarantee."""
    while True:
        try:
            grant = acquire(rate_per_min, n, name)
        except Exception as e:
            logger.warning(f"LLM rate limit not checked ({e}): call allowed")
            return True
        if grant.granted:
            return True
        if stop is not None and stop():
            return False
        sleep(min(max_wait_s, grant.wait_s))


def tokens_left(rate_per_min: float, name: str = BUCKET, conn=None) -> Optional[float]:
    """The bucket's current fill (refilled to now, nothing taken), for health views; None without a limit."""
    if rate_per_min <= 0:
        return None
    sql = text("""
        SELECT LEAST(CAST(:cap AS double precision), tokens + :rate * extract(epoch FROM (now() - updated_at)))
        FROM llm_rate_buckets WHERE name = :name""")
    params = {"name": name, "cap": float(rate_per_min), "rate": float(rate_per_min) / 60.0}
    if conn is not None:
        value = conn.execute(sql, params).scalar()
    else:
        with db.get_engine().connect() as c:
            value = c.execute(sql, params).scalar()
    return float(value) if value is not None else float(rate_per_min)
