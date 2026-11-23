---
hide:
  - footer
---

# Configuration reference (`.env`)

Every setting is an environment variable; `docker-compose.yml` passes them from `.env` (see `.env.example`).
A variable that is set but empty counts as unset in the scanner (the field default applies, or a required
variable is reported missing). Defaults below are the code defaults (`discovery_scanner/config.py`,
`discovery_api/config.py`); `.env.example` sometimes sets a different example value, noted in the last column.

## Database and GitLab (scanner)

| variable | default | meaning |
|---|---|---|
| `POSTGRES_HOST`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` | - | compose builds `DATABASE_URL=postgresql://user:password@host/db` from them for every service |
| `DATABASE_URL` | required | what the scanner, the API and the migration read |
| `GITLAB_URL` | required | the GitLab instance (HTTP URL) |
| `GITLAB_PRIVATE_TOKEN` | required | read-only token: scopes `read_api` + `read_repository`; passed to git as an HTTP header through the environment, never written to disk or argv |
| `GITLAB_PROJECTS_PREFIX` | required | comma separated prefixes matched on path segments: `grp/` = every project of the group, `grp/proj` = that project only, `grp/proj*` = plain string prefix |
| `GITLAB_SCAN_TYPES` | required | `mains`, `mrs` or both: scan main branches, open MRs |
| `PARSERS` | `all` | comma separated parser names, see [Parsers](../parsers/index.md) |
| `SCAN_LANGS` | `all` | languages (as GitLab reports them) whose clones are scanned; `all` disables the gate |
| `PROJECTS_POLL_INTERVAL_S` | `300` | GitLab polling interval (no webhooks) |
| `SYNC_UNCHANGED_EVERY_H` | `24` | a project whose GitLab activity did not change is re-read anyway after this many hours (stale MRs released, deleted branches noticed); `0`: only by the full sync after start-up |
| `GITLAB_CACHE_TTL_S` | `300` | in-memory cache of GitLab API reads, per process; 0 disables |
| `GITLAB_TIMEOUT_S` | `30` | GitLab API request timeout |
| `GIT_TIMEOUT_S` | `1800` | git clone timeout |
| `WORKSPACE_DIR` | system temp dir (`/workspace` in the bundled compose) | parent of the per-job checkout directories |
| `WORKSPACE_MIN_FREE_GB` | `5` | no clone starts with less free space in `WORKSPACE_DIR`; the job is retried; `0` disables, see [Disk space of clones](scanning.md#disk-space-of-clones) |
| `SCAN_MAX_REPO_MB` | `0` | repositories GitLab reports larger are not cloned (the job fails, permanent); `0`: no limit |
| `GIT_PARTIAL_CLONE` | `true` | MR sources that need their history are cloned with `--filter=blob:none` |
| `SCAN_WORKSPACE_VOLUME` | `scan_workspace` | compose only: the volume or host directory mounted at `/workspace` (a directory on another disk keeps clones off the Postgres disk) |

## Scan skip and change detection (scanner)

See [Scanning: diff-based scan skip](scanning.md#diff-based-scan-skip).

| variable | default | meaning |
|---|---|---|
| `SCAN_DIFF_SKIP` | `true` | skip the clone / parse of a main branch when no file a parser reads changed since the snapshot; `false` = every commit is cloned and parsed |
| `SCAN_DIFF_SKIP_MRS` | `true` | the same for MR scans |
| `SCAN_FULL_RESCAN_DAYS` | `7` | a full scan anyway when the last one is older; `0` = never on time alone |
| `SCAN_DIFF_MAX_FILES` | `1000` | a compare that lists this many files or more forces a full scan |
| `SCAN_ALWAYS_RESCAN_GLOBS` | empty | comma separated globs; a changed file matching one forces a full scan (`Makefile,config/*.toml`) |

## Job queue and workers (scanner)

| variable | default | meaning |
|---|---|---|
| `MAX_WORKERS` | `2` (`.env.example`: 5) | scan worker processes (`scan_branch`, `scan_mr`, `ingest`); the code default suits a laptop, the example a stand - the compose file forwards whatever `.env` sets |
| `SYNC_WORKERS` | `2` | GitLab sync worker processes (`sync_projects`, `sync_branches_mrs`) |
| `CONTROL_WORKERS` | `1` | control worker processes (`llm_verify`, `llm_apply`, `llm_prepare`, `llm_coverage`, `llm_rollout`, `llm_relabel`, `stats_refresh`, `cleanup`) |
| `LLM_WORKERS` | `1` | LLM worker processes (`llm_score`, `llm_trial`); 0 = no service model runs |
| `LLM_CONCURRENCY` | `2` | model calls in flight per LLM worker (a thread pool per chunk of a rule run); keep it near `LLM_PARALLEL` for the bundled server, 4-8 for an API model |
| `LLM_RATE_PER_MIN` | `0` | model calls per minute of all LLM workers, threads and replicas together (token bucket in Postgres); 0 = no limit |
| `STATS_REFRESH_S` | `60` | the `stats_refresh` job recomputes the statistics snapshots this often; the API serves a snapshot while younger than twice this; 0 disables (the API computes live) |
| `JOB_LEASE_S` | `300` | a job whose worker died is re-run after this |
| `JOB_MAX_ATTEMPTS` | `5` | attempts per job |
| `JOB_BACKOFF_BASE_S`, `JOB_BACKOFF_MAX_S` | `30`, `3600` | retry n waits `base * 2^(n-1)` seconds, capped |
| `JOB_POLL_S` | `5` | idle workers poll the queue this often |
| `JOBS_RETENTION_DAYS` | `7` | done / failed jobs are deleted after this |
| `SHUTDOWN_TIMEOUT_S` | `150` | SIGTERM: workers still busy after this are killed; keep compose's `stop_grace_period` (180 s) above it |
| `LLM_COVERAGE_INTERVAL_S` | `300` | the control worker recounts stale LLM coverage rows this often; 0 disables |

## Service model (scanner)

| variable | default | meaning |
|---|---|---|
| `LLM_API_URL` | unset in code; compose: `http://discovery_llm:8080/v1` | any OpenAI-compatible endpoint; **empty disables the LLM rules** |
| `LLM_API_KEY` | unset | API key (not needed for the bundled server) |
| `LLM_API_MODEL` | `local-model` | model name; recorded as the service model of every rule version |
| `LLM_TIMEOUT_S` | `120` | seconds per model call |
| `LLM_MAX_RETRIES` | `2` | connection errors, 429 and 5xx are retried |
| `LLM_MAX_TOKENS` | `8192` | answer length (objects with many sensitive fields need long answers) |
| `LLM_STRUCTURED` | `auto` | `response_format`: `auto`, `json_schema`, `json_object`, `none` |
| `LLM_EXTERNAL_RESERVE_H` | `1` | how long unclaimed external work items keep their objects from service runs |

Bundled `discovery_llm` server: `LLM_HF_REPO` (`Qwen/Qwen2.5-3B-Instruct-GGUF:Q4_K_M`, Hugging Face
`<repo>[:quant]`), or a GGUF file: `LLM_MODEL_FILE=/models/<file>.gguf` + `LLM_HF_REPO=` (empty) with the file in
`LLM_MODELS_DIR` (`./llm_models`); `LLM_CTX_SIZE` (8192), `LLM_PARALLEL` (2), `HF_TOKEN` (gated repos). To use an
external API set `LLM_API_URL`, `LLM_API_KEY`, `LLM_API_MODEL` and start with `--scale discovery_llm=0`.
`LLM_LOCAL_MODEL` / `LLM_LOCAL_FILE` / `LLM_PROMPT` / `LLM_PROMPT_VER` are gone and ignored.

## Tiered review (scanner and API)

| variable | default | where | meaning |
|---|---|---|---|
| `LLM_VERIFY_ESCALATE` | `true` | scanner | every service `need_more_info` verdict becomes a verify item for the harness model |
| `LLM_ESCALATION_DAILY_MAX` | `2000` | scanner | escalation items per rule and UTC day; the verdicts over the cap stay service-decided (in the review queue) and are counted as `escalation_overflow` (verify job progress, `job_health.escalations`) |
| `LLM_QA_SAMPLE_RATE` | `0.05` | scanner | share of confident service verdicts sampled for QA (0 disables) |
| `LLM_QA_DAILY_MAX` | `500` | scanner | QA items per UTC day |
| `LLM_QA_AGREEMENT_MIN` | `0.9` | API, scanner | a rule with a lower service / harness agreement (30 days, at least 30 samples) is flagged "needs improvement" (the scanner reads it for the `llm_quality` snapshot) |
| `LLM_TRIAL_MAX_SUBJECTS` | `200` | API | subjects per prompt trial (controls included) |
| `LLM_TRIAL_DAILY_CALLS` | `2000` | API | model calls of all trials per UTC day (0 disables trials) |

## LLM rule lifecycle (scanner and API)

| variable | default | where | meaning |
|---|---|---|---|
| `LLM_REASK_INLINE` | `false` | scanner | `true`: every run asks the stale verdicts at once (the behaviour before rollouts) |
| `LLM_ROLLOUT_DEFAULT` | `canary` | API | the rollout a prompt / scope edit makes: `canary` / `staged` (planned, a human starts it) or `immediate` |
| `LLM_CORE_BUMP_MODE` | `canary` | scanner | new core prompts of a deploy: `canary` / `manual` (a candidate version per rule) or `immediate` (activated, rollout running) |
| `LLM_MODEL_CHANGE_POLICY` | `rollout` | scanner | another `LLM_API_MODEL`: `rollout`, `reask` (activate at once) or `ignore` (record the model, nothing stale) |
| `LLM_ROLLOUT_TICK_S` | `60` | scanner | the `llm_rollout` controller job; 0 disables it |
| `LLM_ROLLOUT_CALLS_PER_HOUR` | `2000` | scanner | model calls of all rollouts together |
| `LLM_ROLLOUT_MAX_PARALLEL_JOBS` | `1` | scanner | rollout slices queued / running at once |
| `LLM_ROLLOUT_FRESH_BACKLOG_MAX` | `20` | scanner | rollouts wait while more fresh `llm_score` jobs are pending |
| `LLM_ROLLOUT_SLICE_OBJECTS` | `200` | scanner | objects (model calls) of one slice |
| `LLM_ROLLOUT_QA_MIN_SAMPLES`, `LLM_ROLLOUT_QA_AGREEMENT_MIN`, `LLM_ROLLOUT_QA_MAX_DROP` | `20`, `0.8`, `0.1` | scanner | auto-pause of a rollout when the harness agreement on the new version is too low or dropped too much |
| `HIT_HISTORY_DAYS` | `180` | scanner | verdict history retention (the last row of every version is kept) |

## Retention (scanner)

See [Retention](retention.md): `MR_STALE_DAYS` (30), `MR_ROW_RETENTION_DAYS` (7), `GC_INTERVAL_HOURS` (24),
`GC_BATCH_SIZE` (5000), `HITS_PENDING_ORPHAN_DAYS` (14), `HITS_DECIDED_UNSEEN_DAYS` (180),
`HITS_REJECTED_UNSEEN_DAYS` (365), `SCANS_KEEP_PER_BRANCH` (20), `JOBS_RETENTION_DAYS` (7), `HIT_HISTORY_DAYS`
(180), `LLM_VERIFICATIONS_RETENTION_DAYS` (365; 0 keeps them), `PROMPT_TRIALS_RETENTION_DAYS` (90; 0 keeps them).

## Postgres (compose)

`docker-compose.yml` starts the bundled Postgres with these server settings (`postgres -c ...`); the image's defaults
(128 MB `shared_buffers`, 4 MB `work_mem`, `random_page_cost` 4) make the planner choose sequential scans and on-disk
sorts once the tables hold millions of rows. The defaults suit an 8 GB host shared with the scanner and the LLM
server; on a dedicated database host raise `shared_buffers` to ~25% of RAM and `effective_cache_size` to ~75%.

| variable | default | meaning |
|---|---|---|
| `PG_SHARED_BUFFERS` | `1GB` | Postgres buffer cache |
| `PG_WORK_MEM` | `32MB` | per sort / hash of a query (several per query, per connection) |
| `PG_MAINTENANCE_WORK_MEM` | `256MB` | index builds, VACUUM |
| `PG_EFFECTIVE_CACHE_SIZE` | `3GB` | what the planner assumes is cached (buffers + OS cache) |
| `PG_RANDOM_PAGE_COST` | `1.1` | SSD storage; keep 4 for spinning disks |
| `PG_MAX_WAL_SIZE` | `2GB` | fewer checkpoints during big scans and backfills |
| `PG_SHM_SIZE` | `512mb` | `/dev/shm` of the container (parallel query workers) |

## API and UI

| variable | default | meaning |
|---|---|---|
| `UI_ADMIN_EMAIL` | required | the login |
| `UI_ADMIN_PASSWORD_HASH` | required | bcrypt hash of the password; a plain `UI_ADMIN_PASSWORD` is refused, so are well-known passwords (`admin`, `password`, ...) unless `UI_ALLOW_WEAK_PASSWORD=true` (local stands only) |
| `UI_JWT_KEY` | required | at least 32 characters, not the example value |
| `UI_TOKEN_TTL_MINUTES` | `30` | lifetime of the bearer tokens of `POST /api/token` (1 .. 10080) |
| `STATS_REFRESH_S` | `60` | also read by the API: a statistics snapshot older than twice this is stale and the API computes live; `0` disables the snapshots in the API |
| `MCP_MAX_RESPONSE_BYTES` | `200000` | byte cap of one MCP tool result (lists are cut, `truncated: true` + `hint`); `0` disables |
| `MCP_RATE_LIMIT_PER_MINUTE` | `600` | MCP requests per minute per client (service token or admin); `429` + `Retry-After` above; `0` disables |
| `UI_BASE_URL` | empty | base of the `ui_url` deep links in MCP answers (e.g. `https://discovery.example.com`); empty: paths only |
| `HTTP_PORT` | `80` | host port of nginx, the only published port |
| `POSTGRES_DEV_PORT` | `54321` | `docker-compose.dev.yml` only: host port of Postgres on 127.0.0.1 |
| `LOG_MAX_SIZE`, `LOG_MAX_FILE` | `50m`, `5` | Docker log rotation of every container (`json-file` driver): size per file, files kept |

Removed settings, ignored when still set: `CACHE_SIZE_GB`, `MR_ALERTS`, `TG_ALERT_TOKEN`, `TG_CHAT_ID`,
`ALERT_TIMEOUT_S`, `LLM_LOCAL_MODEL`, `LLM_LOCAL_FILE`, `LLM_PROMPT`, `LLM_PROMPT_VER`.

Every scanner setting above is forwarded by `docker-compose.yml` from `.env` (with the code default when unset),
including `GITLAB_CACHE_TTL_S`, `GITLAB_TIMEOUT_S`, `GIT_TIMEOUT_S`, `WORKSPACE_DIR`, `JOB_POLL_S`,
`LLM_EXTERNAL_RESERVE_H` and the `LLM_ROLLOUT_QA_*` thresholds, which earlier versions of the file left out.
