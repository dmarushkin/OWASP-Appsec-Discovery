"""Typed scanner settings (P1-7).

Nothing is read from the environment at import time: `get_settings()` builds
`ScannerSettings` on first use (normally in `main()`, which fails fast with a readable
error), and caches it for the process.

Env variable names are unchanged (DATABASE_URL, GITLAB_PRIVATE_TOKEN, ...).
Values that are set but empty (docker compose turns an unset `${VAR}` into "") are
treated as unset, so the field default applies or a required field is reported missing.
"""

import base64
import os
from typing import List, Optional

from pydantic import AnyHttpUrl, BaseSettings, Field, SecretStr, ValidationError, root_validator, validator


def _csv(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


class ScannerSettings(BaseSettings):
    # pydantic v1 BaseSettings: both services are pinned to pydantic 1.10.x (P2-5 intermediate
    # step); move to pydantic-settings together with the coordinated v2 migration.

    database_url: SecretStr
    gitlab_url: AnyHttpUrl
    gitlab_token: SecretStr = Field(..., env="GITLAB_PRIVATE_TOKEN")

    # CSV fields are plain `str`: in pydantic v1 a `List` field is JSON-decoded from env
    # before validators run.
    projects_prefix_csv: str = Field(..., env="GITLAB_PROJECTS_PREFIX")
    scan_types_csv: str = Field(..., env="GITLAB_SCAN_TYPES")
    parsers_csv: str = Field("all", env="PARSERS")
    # Languages (as detected by get_gitlab_project_lang) whose branches/MRs are scanned
    # after cloning; "all" (default) disables the gate. Was hard-coded to "go" (P0-2).
    scan_langs_csv: str = Field("all", env="SCAN_LANGS")

    # Job queue (P2-4, worker pools of supervisor.py): MAX_WORKERS scan worker processes (scan_branch / scan_mr /
    # ingest), SYNC_WORKERS for the GitLab polling sync (sync_projects / sync_branches_mrs), CONTROL_WORKERS for the
    # jobs that call no model and must not wait behind the sync (llm_verify, llm_apply, llm_prepare, llm_coverage,
    # llm_rollout, llm_relabel, stats_refresh, cleanup) and LLM_WORKERS for llm_score / llm_trial (service LLM runs).
    max_workers: int = Field(2, ge=1)
    sync_workers: int = Field(2, ge=1)
    control_workers: int = Field(1, ge=1)
    llm_workers: int = Field(1, ge=0)
    # LLM throughput: model calls in flight per LLM worker (a thread pool per chunk of a rule run; raise it for an
    # API model, keep it near LLM_PARALLEL for the bundled llama.cpp server), and the calls per minute of all
    # workers and replicas together (a token bucket in Postgres, discovery_common.llm_rate; 0 = no limit)
    llm_concurrency: int = Field(2, ge=1)
    llm_rate_per_min: int = Field(0, ge=0)
    # a project whose GitLab activity did not change since its last sync is re-read anyway after this many hours
    # (stale MRs are released, deleted branches noticed); the first sync after start-up follows the same rule
    sync_unchanged_every_h: float = Field(24, ge=0)
    # external executor: how long unclaimed work items keep their objects from service runs
    # (a claimed item: until its lease ends; an answered one: until it is applied)
    llm_external_reserve_h: float = Field(1, gt=0)
    projects_poll_interval_s: float = Field(300, gt=0)  # GitLab polling (no webhooks)
    # recount of stale LLM coverage rows (llm_coverage job on the control worker); 0 disables
    llm_coverage_interval_s: float = Field(300, ge=0)
    # statistics snapshots (stats_refresh job, table stats_snapshots, discovery_common.stats) every this many
    # seconds; the API serves them while fresh (< 2x the interval); 0 disables the job
    stats_refresh_s: float = Field(60, ge=0)
    # tiered workflow (services.verify_service, llm_verify job after each service LLM run): every
    # service need_more_info verdict goes to the harness model (LLM_VERIFY_ESCALATE), and a
    # sample of the confident service verdicts (positive and negative, per rule) for quality control:
    # LLM_QA_SAMPLE_RATE (0 disables the QA sample), at most LLM_QA_DAILY_MAX QA items per UTC day
    llm_verify_escalate: bool = True
    # at most this many escalation items per rule and UTC day; the service need_more_info verdicts over the cap
    # stay service-decided (in the review queue) and are counted (``escalation_overflow`` in the verify job's
    # progress and in the job health snapshot)
    llm_escalation_daily_max: int = Field(2000, ge=0)
    llm_qa_sample_rate: float = Field(0.05, ge=0, le=1)
    llm_qa_daily_max: int = Field(500, ge=0)
    # the API's threshold for "needs improvement" (LLM_QA_AGREEMENT_MIN): read here too, so the llm_quality
    # statistics snapshot carries the same flag the live API computation does
    llm_qa_agreement_min: float = Field(0.9, ge=0, le=1)
    # LLM rule lifecycle (services.lifecycle_service, README "LLM rules lifecycle"): a verdict of an older version of
    # a rule (prompt / scope edit, new core prompts, another service model) is kept and flagged stale until a rule
    # rollout asks it again in budgeted slices; LLM_REASK_INLINE=true asks such verdicts in every run instead (the
    # behaviour before the lifecycle)
    llm_reask_inline: bool = False
    llm_core_bump_mode: str = "canary"            # canary | manual: a candidate version per rule; immediate
    llm_model_change_policy: str = "rollout"      # rollout | reask (activate at once) | ignore
    llm_rollout_tick_s: float = Field(60, ge=0)  # the llm_rollout controller job; 0 disables it
    llm_rollout_calls_per_hour: int = Field(2000, ge=1)       # model calls of all rollouts together
    llm_rollout_max_parallel_jobs: int = Field(1, ge=1)       # rollout slices queued / running at once
    llm_rollout_fresh_backlog_max: int = Field(20, ge=0)      # wait while more fresh llm_score jobs are pending
    llm_rollout_slice_objects: int = Field(200, ge=1)         # objects (model calls) of one slice
    # auto-pause: harness agreement (QA sample) of the new version below this (or this much below the old version's)
    llm_rollout_qa_min_samples: int = Field(20, ge=1)
    llm_rollout_qa_agreement_min: float = Field(0.8, ge=0, le=1)
    llm_rollout_qa_max_drop: float = Field(0.1, ge=0, le=1)
    hit_history_days: int = Field(180, ge=1)      # hit_verdicts retention (the last row of a version is kept)
    job_lease_s: float = Field(300, gt=0)               # a dead worker's job is re-run after this
    job_max_attempts: int = Field(5, ge=1)
    job_backoff_base_s: float = Field(30, ge=0)         # retry n waits base * 2**(n-1), capped
    job_backoff_max_s: float = Field(3600, ge=0)
    job_poll_s: float = Field(5, gt=0)                  # idle workers poll the queue this often
    jobs_retention_days: int = Field(7, ge=1)           # done / failed jobs kept this long
    # SIGTERM: the running jobs hand themselves back at their next safe point (an LLM run after the
    # model call in flight, LLM_TIMEOUT_S at most per try); a worker still busy after this is killed.
    # Keep docker-compose's stop_grace_period above it (180s for the default 150s).
    shutdown_timeout_s: float = Field(150, ge=0)
    # Parent of the per-job checkout directories (tempfile.mkdtemp); default: the system temp dir.
    workspace_dir: Optional[str] = None
    # Disk guards of the clones (docs/service/scanning.md "Disk space"): no clone starts while the workspace
    # file system has less than WORKSPACE_MIN_FREE_GB free (0: no check; the job is retried); a repository
    # GitLab reports larger than SCAN_MAX_REPO_MB is not cloned (0: no limit; the job fails, permanent).
    # GIT_PARTIAL_CLONE: MR sources that need their history are cloned with --filter=blob:none.
    workspace_min_free_gb: float = Field(5, ge=0)
    scan_max_repo_mb: int = Field(0, ge=0)
    git_partial_clone: bool = True
    gitlab_timeout_s: float = Field(30, gt=0)
    git_timeout_s: float = Field(1800, gt=0)
    # GitLab API reads are cached in memory (per process; the sync runs in the control worker):
    # at most one request per unique read per this many seconds; 0 disables the cache
    gitlab_cache_ttl_s: float = Field(300, ge=0, env="GITLAB_CACHE_TTL_S")
    # (CACHE_SIZE_GB was removed in P2-4: every job clones into its own workspace, removed when
    # the job ends; a value still set in the environment is ignored like any unknown variable.)

    # Diff-based scan skip (services.diff_service, README "Service mode"): before cloning a main branch
    # (or an MR) the GitLab compare API lists the files changed since the commit the snapshot reflects;
    # when none of them is read by a parser of the scan, the snapshot is moved to the new commit without
    # a clone, a parse or an LLM run. SCAN_DIFF_SKIP=false: every new commit is cloned and parsed (as
    # before); SCAN_DIFF_SKIP_MRS: the same for MR scans. A full scan happens anyway every
    # SCAN_FULL_RESCAN_DAYS days (0: never on time alone), when the compare lists SCAN_DIFF_MAX_FILES
    # files or more (truncated), and when a changed file matches SCAN_ALWAYS_RESCAN_GLOBS (csv of globs).
    scan_diff_skip: bool = True
    scan_diff_skip_mrs: bool = True
    scan_full_rescan_days: int = Field(7, ge=0)
    scan_diff_max_files: int = Field(1000, ge=1)
    scan_always_rescan_globs_csv: str = Field("", env="SCAN_ALWAYS_RESCAN_GLOBS")

    # Any OpenAI-compatible endpoint. docker-compose.yml defaults it to the bundled llama.cpp
    # server (http://discovery_llm:8080/v1); unset/empty disables the LLM rule. Local models
    # run out of process only (LLM_LOCAL_MODEL / LLM_LOCAL_FILE were removed).
    llm_api_url: Optional[str] = None
    llm_api_key: Optional[SecretStr] = None
    llm_api_model: str = "local-model"   # llama.cpp serves its one model under any name
    # (LLM_PROMPT / LLM_PROMPT_VER - the env-managed LLM rule - were removed: set in the environment, they are ignored)
    llm_timeout_s: float = Field(120.0, gt=0)
    llm_max_retries: int = Field(2, ge=0)
    llm_max_tokens: int = Field(8192, ge=1)   # objects with many sensitive fields need long answers
    llm_structured: str = "auto"        # auto | json_schema | json_object | none

    # Retention / GC (storage design). cleanup() runs every GC_INTERVAL_HOURS (0 disables it).
    mr_stale_days: int = Field(30, ge=1)              # open MR not updated -> source branch untracked
    mr_row_retention_days: int = Field(7, ge=0)       # gitlab_mrs rows kept after close/merge
    gc_interval_hours: float = Field(24, ge=0)
    gc_batch_size: int = Field(5000, ge=1)
    hits_pending_orphan_days: int = Field(14, ge=1)   # pending_review hits without a live subject
    hits_decided_unseen_days: int = Field(180, ge=1)  # match / need_more_info, no live subject
    # no_match hits without a live subject (the name predates migration 0023: status rejected -> no_match)
    hits_rejected_unseen_days: int = Field(365, ge=1)
    scans_keep_per_branch: int = Field(20, ge=1)
    # harness verifications (llm_verifications) and finished prompt trials (with their items; trials a proposal
    # refers to are kept) are deleted after this many days; 0 keeps them forever
    llm_verifications_retention_days: int = Field(365, ge=0)
    prompt_trials_retention_days: int = Field(90, ge=0)

    class Config:
        case_sensitive = False

    @root_validator(pre=True, allow_reuse=True)
    def _empty_is_unset(cls, values):
        return {k: v for k, v in values.items() if not (isinstance(v, str) and not v.strip())}

    @validator("llm_core_bump_mode", allow_reuse=True)
    def _known_core_bump_mode(cls, value):
        value = value.strip().lower()
        if value not in ("canary", "manual", "immediate"):
            raise ValueError(f"unknown LLM_CORE_BUMP_MODE {value!r}: expected canary, manual or immediate")
        return value

    @validator("llm_model_change_policy", allow_reuse=True)
    def _known_model_policy(cls, value):
        value = value.strip().lower()
        if value not in ("rollout", "reask", "ignore"):
            raise ValueError(f"unknown LLM_MODEL_CHANGE_POLICY {value!r}: expected rollout, reask or ignore")
        return value

    @validator("llm_structured", allow_reuse=True)
    def _known_structured_mode(cls, value):
        # same modes as appsec_discovery.ai.backends.STRUCTURED_MODES: fail at startup, not per scan
        value = value.strip().lower()
        if value not in ("auto", "json_schema", "json_object", "none"):
            raise ValueError(f"unknown LLM_STRUCTURED {value!r}: expected auto, json_schema, json_object or none")
        return value

    @property
    def projects_prefixes(self) -> List[str]:
        return _csv(self.projects_prefix_csv)

    @property
    def scan_types(self) -> List[str]:
        return _csv(self.scan_types_csv)

    @property
    def parsers(self) -> List[str]:
        return _csv(self.parsers_csv)

    @property
    def scan_langs(self) -> List[str]:
        return _csv(self.scan_langs_csv)

    @property
    def scan_always_rescan_globs(self) -> List[str]:
        return _csv(self.scan_always_rescan_globs_csv)

    def scans_lang(self, lang: Optional[str]) -> bool:
        """True when a project in language ``lang`` must be scanned (see SCAN_LANGS)."""
        langs = [item.lower() for item in self.scan_langs]
        return not langs or "all" in langs or (lang or "").lower() in langs

    @property
    def gitlab_base_url(self) -> str:
        return str(self.gitlab_url).rstrip("/")


def format_settings_error(error: ValidationError) -> str:
    """Render a settings ValidationError in terms of env variable names."""
    lines = []
    for err in error.errors():
        name = err["loc"][0] if err["loc"] else "__root__"
        field = ScannerSettings.__fields__.get(name)
        env_names = sorted(field.field_info.extra.get("env_names", ())) if field else []
        env_name = env_names[0].upper() if env_names else str(name).upper()
        lines.append(f"  {env_name}: {err['msg']}")
    return "\n".join(lines)


_settings: Optional[ScannerSettings] = None


def get_settings() -> ScannerSettings:
    """Return the process-wide settings, building them from env on first call."""
    global _settings
    if _settings is None:
        _settings = ScannerSettings()
    return _settings


def set_settings(settings: Optional[ScannerSettings]) -> None:
    """Install (or with None, reset) the process-wide settings. Used by main() and tests."""
    global _settings
    _settings = settings


def git_auth_env(settings: ScannerSettings, base_env: Optional[dict] = None) -> dict:
    """Environment for `git` subprocesses that authenticates to GitLab over HTTP.

    The token is passed as a Basic `http.<gitlab>/.extraHeader` through GIT_CONFIG_COUNT /
    GIT_CONFIG_KEY_n / GIT_CONFIG_VALUE_n (git >= 2.31): it is never written to disk and
    never appears in argv (`ps`). The header is scoped to the GitLab URL, so it is not sent
    to other hosts. Any GIT_CONFIG_* entries already present in the environment are kept.
    """
    env = dict(os.environ if base_env is None else base_env)

    try:
        index = int(env.get("GIT_CONFIG_COUNT", "0"))
    except ValueError:
        index = 0

    # Same user name as the previous credential-store setup ("git:<token>").
    basic = base64.b64encode(f"git:{settings.gitlab_token.get_secret_value()}".encode()).decode()

    env[f"GIT_CONFIG_KEY_{index}"] = f"http.{settings.gitlab_base_url}/.extraHeader"
    env[f"GIT_CONFIG_VALUE_{index}"] = f"Authorization: Basic {basic}"
    env["GIT_CONFIG_COUNT"] = str(index + 1)
    # Fail instead of hanging on an interactive prompt if the token is rejected.
    env["GIT_TERMINAL_PROMPT"] = "0"

    return env
