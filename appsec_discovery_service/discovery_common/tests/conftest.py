"""Fixtures for discovery_common tests. Postgres-backed tests need TEST_DATABASE_URL, or
TEST_PG_DOCKER=1 for a throwaway postgres:16 container (see discovery_common/testing.py),
and are skipped without them."""

import sys
from pathlib import Path

import pytest

SERVICE_DIR = Path(__file__).resolve().parents[2]
if str(SERVICE_DIR) not in sys.path:
    sys.path.insert(0, str(SERVICE_DIR))

from discovery_common import testing  # noqa: E402


@pytest.fixture(scope="session")
def pg_server():
    try:
        with testing.server_url() as url:
            yield url
    except RuntimeError as e:
        pytest.skip(str(e))


@pytest.fixture
def pg_url(pg_server):
    if not pg_server:
        pytest.skip(f"{testing.ENV} is not set (Postgres integration test)")
    with testing.fresh_database("common") as url:
        yield url
