"""The shared LLM rate limit (token bucket in Postgres, migration 0031) against a real Postgres."""

import threading

import pytest
from sqlalchemy import text

from discovery_common import db, llm_rate, testing


@pytest.fixture
def bucket(pg_url):
    testing.migrate(pg_url)
    db.configure(pg_url)
    try:
        yield pg_url
    finally:
        db.configure(None)


def q(sql, **params):
    with db.get_engine().begin() as conn:
        result = conn.execute(text(sql), params)
        return result.all() if result.returns_rows else result.rowcount


def test_no_limit_touches_nothing(bucket):
    grant = llm_rate.acquire(0)
    assert grant.granted and grant.wait_s == 0
    assert llm_rate.wait(0) is True
    assert q("SELECT count(*) FROM llm_rate_buckets") == [(0,)]
    assert llm_rate.tokens_left(0) is None


def test_bucket_starts_full_drains_and_refills(bucket):
    # 60 per minute = one token a second, a full minute's burst at the start
    for _ in range(60):
        assert llm_rate.acquire(60).granted
    denied = llm_rate.acquire(60)
    assert not denied.granted and 0 < denied.wait_s <= 1.05
    assert 0 <= llm_rate.tokens_left(60) < 1
    # time passes: the row refills from updated_at
    q("UPDATE llm_rate_buckets SET updated_at = updated_at - interval '30 seconds' WHERE name = :n", n=llm_rate.BUCKET)
    assert 29 <= llm_rate.tokens_left(60) <= 31
    granted = llm_rate.acquire(60, n=10)
    assert granted.granted and 19 <= granted.tokens_left <= 21
    # never over the capacity
    q("UPDATE llm_rate_buckets SET updated_at = updated_at - interval '1 hour' WHERE name = :n", n=llm_rate.BUCKET)
    assert llm_rate.tokens_left(60) == 60


def test_wait_sleeps_until_granted_and_stops_on_request(bucket):
    for _ in range(6):
        assert llm_rate.acquire(6).granted              # 6 per minute: empty now
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        q("UPDATE llm_rate_buckets SET updated_at = updated_at - interval '10 seconds' WHERE name = :n",
          n=llm_rate.BUCKET)                                # 10 s pass: one token
    assert llm_rate.wait(6, sleep=sleep) is True
    assert len(sleeps) == 1 and 0 < sleeps[0] <= 5.0        # waits at most max_wait_s at a time

    assert llm_rate.wait(6, sleep=lambda s: None, stop=lambda: True) is False   # a graceful stop: no call started


def test_concurrent_acquires_never_grant_more_than_the_bucket_holds(bucket):
    granted = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        for _ in range(5):
            if llm_rate.acquire(20).granted:
                granted.append(1)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # 40 attempts, a bucket of 20 (plus a fraction of a second of refill): at most 21 grants
    assert 20 <= len(granted) <= 21
