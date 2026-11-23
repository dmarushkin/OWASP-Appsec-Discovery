---
hide:
  - footer
---

# Troubleshooting

Start with **Pipeline health** (Admin role): which stage is behind, the oldest waiting job, failures of the last 24
hours grouped by cause. The same data: `GET /jobs/health`, `GET /jobs/errors`, `GET /scan_progress`,
`GET /llm_progress` (MCP `job_health`, `scan_progress`, `llm_progress`).

| symptom | where to look | usual cause |
|---|---|---|
| the API or the scanner does not start | `docker compose logs discovery_api` / `discovery_scanner` | an invalid setting: the API refuses a missing `UI_ADMIN_PASSWORD_HASH`, a plain `UI_ADMIN_PASSWORD`, a short or example `UI_JWT_KEY`, a well-known password; the scanner reports every bad variable by name (`GITLAB_PROJECTS_PREFIX: field required`, ...) |
| `docker compose up` fails to build | - | Docker Compose v2.20+ with BuildKit is needed (`depends_on.required`, per-Dockerfile `.dockerignore`) |
| the scanner waits forever at start | `docker compose ps discovery_llm` | the bundled model is still downloading (`/health` answers 503 meanwhile; `start_period` 600 s); or use an external API and `--scale discovery_llm=0` |
| no projects appear | Jobs: `sync_projects`; scanner log | the token lacks `read_api`, the prefix does not match (matched on path segments: `grp/` not `grp`), the project is archived |
| a scan fails with `cannot clone ...` | the job's `last_error` | the token lacks `read_repository`, or the branch of a still open MR was deleted (permanent: the job fails at once, the MR is marked processed); a merged / closed MR with a deleted source branch is skipped, not failed |
| a scan fails with `not enough disk space for a clone` / `no space left on device` | Pipeline health "Needs attention"; `df` of `WORKSPACE_DIR` | the disk of the clones is full (often Postgres or other volumes on the same Docker disk); free space, or move clones to another disk with `SCAN_WORKSPACE_VOLUME`; `WORKSPACE_MIN_FREE_GB` sets the reserve |
| a scan fails with `repository too large` | the job's `last_error` | the repository is above `SCAN_MAX_REPO_MB`; raise the limit or set `0` |
| a scan is `partial` | job progress `failed_parsers`, `last_error` | one parser broke on this repository; the other parsers' objects are saved, the branch is retried |
| a main branch is `skipped` | `GET /scan_progress` | the `SCAN_LANGS` gate excluded the project's language; `all` disables the gate |
| a scan ended `skipped: no parser files changed` | the job page | the diff-based skip: nothing a parser reads changed; set `SCAN_DIFF_SKIP=false` or `SCAN_ALWAYS_RESCAN_GLOBS` if a file type matters, see [Scanning](scanning.md#diff-based-scan-skip) |
| LLM rules never run | `LLM_API_URL` | empty disables them; `LLM_WORKERS` 0 runs no service model jobs |
| an LLM run has failed objects | the job page, `GET /llm_rules/{id}/errors` | `LLM answer truncated at max_tokens` (raise `LLM_MAX_TOKENS`), `Request timed out` (`LLM_TIMEOUT_S`), `LLM answer is not JSON` (`LLM_STRUCTURED=json_object` or another model); the failed objects are asked again by the next run |
| the LLM backlog grows | Pipeline health "Service model", `GET /jobs/health` throughput and ETA | a slow model: more `LLM_WORKERS` and `LLM_PARALLEL` for the bundled server, a smaller model, or a harness model taking over service runs (`llm_take_over`) |
| hits are stale | hits filter `stale=true`, the Versions tab of the rule | the rule has a new version and its rollout is planned, not started: start it in the Versions tab or Pipeline health "Rollouts", or set `LLM_REASK_INLINE=true` |
| a rollout is paused | `GET /llm_rollouts/{id}` `paused_reason` | the budget (`max_calls`) is used, or the harness agreement on the new version dropped (auto-pause) |
| a harness answer is refused as `stale` | `llm_work_items.error`, the Harness work page | the hit was decided by a human meanwhile, or its service verdict changed; claim again |
| a harness shows "gone?" | the Harness work page | claimed items without an answer for an hour; leases expire (30..900 s) and are claimable again; `llm_work_release` gives them back at once |
| login returns 429 | nginx | 5 logins per minute per client; behind a TLS terminator declare it in `discovery_nginx/conf.d/real_ip.conf` or every client shares the limit |
| MCP returns 401 / 403 | the token | expired (`UI_TOKEN_TTL_MINUTES`), or a service token (`adt_...`): those are for `/ingest` only |
| a rule pattern stopped matching after an upgrade | the migration `0027` log, the keyword rules page | object names lost their type word: `^Route /admin` -> `object_type_re: route` + `object_re: /admin` |
| the database is not reachable from the host | - | by design; `docker compose -f docker-compose.yml -f docker-compose.dev.yml up` publishes it on `127.0.0.1:54321` |

Failure texts never contain credentials (`discovery_common/redact.py`); if a text looks truncated, the full
exception is in the scanner log with the job id.
