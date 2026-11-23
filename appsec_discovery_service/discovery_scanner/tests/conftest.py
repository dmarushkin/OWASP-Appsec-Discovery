"""Hermetic fixtures for discovery_scanner unit tests.

Since P1-7 the scanner modules no longer read env at import time, so the real `config`
module is used, fed with a fake environment. GitLab is replaced by `FakeGitlab`
(`gitlab.Gitlab` is monkeypatched; a stub `gitlab` module is installed when python-gitlab
is not available, as in the core dev environment).

Postgres-bound modules are stubbed: `models`, `services.db_service` and
`services.score_service` (LLM). The DB layer itself is tested against a real Postgres in
`discovery_common/tests` (skipped without TEST_DATABASE_URL). `services.gl_service` is stubbed by default too; tests that
exercise it call `scanner.use_real("services.gl_service")`. Everything is restored after
each test.
"""

import importlib
import sys
import types
from pathlib import Path

import pytest

SCANNER_DIR = Path(__file__).resolve().parents[1]
SERVICE_DIR = SCANNER_DIR.parent   # discovery_common lives here
SCANNER_MODULES = {"logger", "config", "models", "services", "main", "supervisor"}

SCANNER_ENV_VARS = (
    "DATABASE_URL", "GITLAB_URL", "GITLAB_PRIVATE_TOKEN", "GITLAB_PROJECTS_PREFIX",
    "GITLAB_SCAN_TYPES", "PARSERS", "MAX_WORKERS", "CACHE_SIZE_GB",
    "LLM_API_URL", "LLM_API_KEY", "LLM_API_MODEL", "LLM_TIMEOUT_S", "LLM_MAX_RETRIES", "LLM_MAX_TOKENS",
    "LLM_STRUCTURED", "LLM_PROMPT", "LLM_PROMPT_VER", "SCAN_LANGS",   # (LLM_PROMPT*: ignored since 0028)
    "GIT_CONFIG_COUNT", "LLM_WORKERS", "PROJECTS_POLL_INTERVAL_S", "JOB_LEASE_S", "JOB_MAX_ATTEMPTS",
    "JOB_BACKOFF_BASE_S", "JOB_BACKOFF_MAX_S", "JOB_POLL_S", "JOBS_RETENTION_DAYS", "SHUTDOWN_TIMEOUT_S",
    "WORKSPACE_DIR", "GITLAB_TIMEOUT_S", "GIT_TIMEOUT_S", "GC_INTERVAL_HOURS", "GITLAB_CACHE_TTL_S",
    "LLM_COVERAGE_INTERVAL_S", "LLM_VERIFY_ESCALATE", "LLM_QA_SAMPLE_RATE", "LLM_QA_DAILY_MAX",
    "LLM_REASK_INLINE", "LLM_CORE_BUMP_MODE", "LLM_MODEL_CHANGE_POLICY", "LLM_ROLLOUT_TICK_S",
    "LLM_ROLLOUT_CALLS_PER_HOUR", "LLM_ROLLOUT_MAX_PARALLEL_JOBS", "LLM_ROLLOUT_FRESH_BACKLOG_MAX",
    "LLM_ROLLOUT_SLICE_OBJECTS", "LLM_ROLLOUT_QA_MIN_SAMPLES", "LLM_ROLLOUT_QA_AGREEMENT_MIN", "LLM_ROLLOUT_QA_MAX_DROP",
    "HIT_HISTORY_DAYS", "SCAN_DIFF_SKIP", "SCAN_DIFF_SKIP_MRS", "SCAN_FULL_RESCAN_DAYS", "SCAN_DIFF_MAX_FILES",
    "SCAN_ALWAYS_RESCAN_GLOBS", "SYNC_WORKERS", "CONTROL_WORKERS", "LLM_CONCURRENCY", "LLM_RATE_PER_MIN",
    "SYNC_UNCHANGED_EVERY_H", "STATS_REFRESH_S", "LLM_ESCALATION_DAILY_MAX", "LLM_QA_AGREEMENT_MIN",
)

FAKE_ENV = {
    "DATABASE_URL": "postgresql://user:db-secret@localhost/discovery",
    "GITLAB_URL": "https://gitlab.example",
    "GITLAB_PRIVATE_TOKEN": "glpat-test-token",
    "GITLAB_PROJECTS_PREFIX": "grp",
    "GITLAB_SCAN_TYPES": "mrs",
    "PARSERS": "all",
    "MAX_WORKERS": "1",
}


class Record:
    """Stand-in for the SQLModel tables: stores kwargs as attributes."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return f"{type(self).__name__}({self.__dict__!r})"


class FakeGitlabGetError(Exception):
    pass


class FakeGitlab:
    """Records constructor calls; `projects` is a plain namespace tests can fill in."""

    instances = []

    def __init__(self, url=None, private_token=None, **kwargs):
        self.url = url
        self.private_token = private_token
        self.kwargs = kwargs
        self.projects = types.SimpleNamespace()
        FakeGitlab.instances.append(self)


def _module(name, **attrs):
    mod = types.ModuleType(name)
    mod.__dict__.update(attrs)
    return mod


def _not_stubbed(name):
    def _fail(*args, **kwargs):
        raise AssertionError(f"{name} was called but not stubbed by the test")
    return _fail


def _install_fake_gitlab(monkeypatch):
    FakeGitlab.instances = []
    try:
        import gitlab
    except ImportError:
        exceptions = _module("gitlab.exceptions", GitlabGetError=FakeGitlabGetError)
        gitlab = _module("gitlab", Gitlab=FakeGitlab, exceptions=exceptions)
        monkeypatch.setitem(sys.modules, "gitlab", gitlab)
        monkeypatch.setitem(sys.modules, "gitlab.exceptions", exceptions)
    else:
        monkeypatch.setattr(gitlab, "Gitlab", FakeGitlab)
    return FakeGitlab


class ScannerEnv:

    def __init__(self, monkeypatch):
        self.monkeypatch = monkeypatch

        for name in SCANNER_ENV_VARS:
            monkeypatch.delenv(name, raising=False)
        for name, value in FAKE_ENV.items():
            monkeypatch.setenv(name, value)

        self.gitlab = _install_fake_gitlab(monkeypatch)

        monkeypatch.syspath_prepend(str(SERVICE_DIR))
        monkeypatch.syspath_prepend(str(SCANNER_DIR))

        self.models = _module(
            "models",
            **{name: type(name, (Record,), {}) for name in (
                "Project", "Branch", "MR", "Scan", "ObjectVersion", "ObjectField", "BranchObject", "Rule", "RuleHit",
            )}
        )

        self.gl_service = _module("services.gl_service", **{name: _not_stubbed(name) for name in (
            "clone_gitlab_project_code", "get_gitlab_project_lang", "get_gitlab_mr_state",
            "get_gitlab_projects_list", "get_gitlab_branches_by_project", "get_gitlab_branches", "get_gitlab_mr_states",
            "get_gitlab_mrs_by_project", "get_gitlab_project", "get_mr_changed_files", "get_gitlab_compare",
            "get_gitlab_merge_base",
        )})

        self.db_service = _module("services.db_service", **{name: _not_stubbed(name) for name in (
            "configure", "init_db", "gl_time", "insert_scan", "get_scan", "get_rules", "ensure_rule",
            "save_main_scan", "save_mr_delta", "load_branch_snapshot", "get_branch", "get_branch_by_id", "get_mr",
            "get_llm_candidates", "get_object_fields", "get_object_docs", "upsert_llm_hits",
            "set_project_processed", "upsert_project", "upsert_branch", "set_branch_processed", "upsert_mr",
            "set_mr_processed", "set_mr_target_commit", "get_delta_owner", "get_project", "scan_lock", "load_snapshot_files",
            "latest_ingest_batch", "finish_ingest_batch", "fail_ingest_batch", "skip_branch_scan",
        )}, PARTIAL_SUFFIX="+partial",
            # no external executor in unit tests: nothing is reserved
            get_reserved_llm_objects=lambda rule_id, rule_version: set(),
            take_over_llm_objects=lambda rule_id, rule_version, object_keys: [])

        self.score_service = _module(
            "services.score_service",
            llm_score_objects=_not_stubbed("llm_score_objects"),
            llm_configured=lambda settings=None: False,
            core_prompts_version=lambda: "core-test",
            get_llm_backend=_not_stubbed("get_llm_backend"),
            llm_rule_verdicts=_not_stubbed("llm_rule_verdicts"),
            LlmObject=type("LlmObject", (Record,), {}),
        )

        # LLM coverage recounts (scan_service.record_llm_coverage): recorded calls, no DB;
        # Postgres tests use the real module (use_real("services.llm_coverage_service"))
        self.coverage_calls = []
        self.llm_coverage_service = _module(
            "services.llm_coverage_service",
            refresh=lambda branch_id, rules=None, after_run=False: self.coverage_calls.append(
                (branch_id, None if rules is None else [getattr(r, "id", r) for r in rules], after_run)) or 0,
            refresh_stale=lambda **kw: {"pairs": 0, "recounted": 0, "failed": 0, "more": False},
        )

        for name, mod in (
            ("models", self.models),
            ("services.llm_coverage_service", self.llm_coverage_service),
            ("services.gl_service", self.gl_service),
            ("services.db_service", self.db_service),
            ("services.score_service", self.score_service),
        ):
            monkeypatch.setitem(sys.modules, name, mod)

        # Real config module, fresh per test (its settings cache starts empty).
        self.config = self.load("config")

    def setenv(self, **env):
        """Change env and drop the cached settings so the next get_settings() sees it."""
        for name, value in env.items():
            if value is None:
                self.monkeypatch.delenv(name, raising=False)
            else:
                self.monkeypatch.setenv(name, value)
        self.config.set_settings(None)

    def settings(self):
        return self.config.get_settings()

    def stub(self, name, module_name, **attrs):
        """Add stubbed modules (e.g. `services.scan_service` when testing main.py)."""
        mod = _module(module_name, **attrs)
        self.monkeypatch.setitem(sys.modules, module_name, mod)
        return mod

    def use_real(self, module_name):
        """Replace a default stub with the real module and import it."""
        self.monkeypatch.delitem(sys.modules, module_name, raising=False)
        return self.load(module_name)

    def patch_parser_factory(self, factory):
        """Replace the parser factory seen by the core runner (``appsec_discovery.scan``) and
        by the scanner's PARSERS validation."""
        import appsec_discovery.runner as runner
        self.monkeypatch.setattr(runner, "ParserFactory", factory)
        scan_service = sys.modules.get("services.scan_service")
        if scan_service is not None:
            self.monkeypatch.setattr(scan_service, "ParserFactory", factory)

    def load(self, module_name):
        sys.modules.pop(module_name, None)
        return importlib.import_module(module_name)


@pytest.fixture
def scanner(monkeypatch):
    before = {name for name in sys.modules if name in SCANNER_MODULES or name.startswith("services.")}
    env = ScannerEnv(monkeypatch)
    try:
        yield env
    finally:
        jobs = sys.modules.get("discovery_common.jobs")
        if jobs is not None and hasattr(jobs, "stop_event"):
            jobs.stop_event().clear()           # a graceful-stop test must not stop the next tests
        # Drop scanner modules imported during the test (logger, config, services, main, ...)
        # so that they do not leak into other test modules.
        for name in set(sys.modules) - before:
            if name in SCANNER_MODULES or name.startswith("services."):
                sys.modules.pop(name, None)


@pytest.fixture(scope="session")
def pg_server():
    """TEST_DATABASE_URL, or a throwaway postgres:16 container with TEST_PG_DOCKER=1."""
    sys.path.insert(0, str(SERVICE_DIR))
    from discovery_common import testing
    try:
        with testing.server_url() as url:
            yield url
    except RuntimeError as e:
        pytest.skip(str(e))


@pytest.fixture
def pg_scanner(scanner, pg_server):
    """`scanner` env with the real DB layer on a fresh, migrated Postgres database
    (TEST_DATABASE_URL, see discovery_common/testing.py); skipped without it."""
    from discovery_common import db, testing

    if not testing.admin_url():
        pytest.skip(f"{testing.ENV} is not set (Postgres integration test)")

    with testing.fresh_database("scanner") as url:
        testing.migrate(url)
        scanner.setenv(DATABASE_URL=url)
        scanner.db = scanner.use_real("services.db_service")
        scanner.db.configure()
        try:
            yield scanner
        finally:
            db.configure(None)
