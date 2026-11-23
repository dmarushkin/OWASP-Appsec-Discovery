---
hide:
  - footer
---

# Jobs and workers

All scanner work goes through the `jobs` table (`discovery_common/jobs.py`): `INSERT ... ON CONFLICT DO NOTHING`
on a dedup key that is unique among the active (pending / running) jobs, claimed with `FOR UPDATE SKIP LOCKED` in
`ORDER BY priority DESC, run_after, id`, leased to a worker (`JOB_LEASE_S`, renewed by a heartbeat; an expired
lease puts the job back to pending), retried with exponential backoff (`JOB_BACKOFF_BASE_S * 2^(n-1)`, capped at
`JOB_BACKOFF_MAX_S`, `JOB_MAX_ATTEMPTS` attempts), deleted `JOBS_RETENTION_DAYS` after they finished. A claim is one
`UPDATE` by the kinds of the worker's pool (index `jobs_ready_kind`); expired leases are reaped by the scheduler every
few seconds (and by a worker at most once per lease), not on every claim.

Statuses: `pending`, `running`, `done`, `failed`. Priorities: rule rollout slices -10, fresh work 0, prompt trials and
relabel jobs +5. `started_at` (migration `0031_scale_pipeline`) records when the last attempt was claimed and stays on
the finished row (`locked_at` is the lease and is cleared), so `GET /jobs/health` can compute the typical run and wait
times.

## Process model

One supervisor process runs the **scheduler** (periodic jobs; it reads the last job of each kind from the table,
so restarts do not reset the schedule and several replicas do not double it) and supervises the worker pools (one
OS process each, `spawn`):

| pool | count | job kinds |
|---|---|---|
| `sync` | `SYNC_WORKERS` (2) | `sync_projects`, `sync_branches_mrs` - the GitLab polling. A pool of its own: a sync of one project is seconds to minutes of GitLab calls and there are thousands of projects; nothing else waits behind it |
| `control` | `CONTROL_WORKERS` (1) | `llm_verify`, `llm_apply`, `llm_prepare`, `llm_coverage`, `llm_rollout`, `llm_relabel`, `stats_refresh`, `cleanup` - jobs that call no model and must run promptly (harness verify items, answers of external runs); they work in bounded slices and requeue themselves (`RequeueJob`, no attempt used) so one of them never holds up the others for long |
| `scan` | `MAX_WORKERS` (2; `.env.example`: 5) | `scan_branch`, `scan_mr`, `ingest` - each scan clones into its own temporary workspace, removed when the job ends |
| `llm` | `LLM_WORKERS` (1) | `llm_score` (service model runs), `llm_trial` (prompt trials); each worker keeps `LLM_CONCURRENCY` model calls in flight, all of them together within `LLM_RATE_PER_MIN` |

Before the split the single control worker ran the sync too: thousands of `sync_branches_mrs` jobs (p50 94 s each on a
100-project stand) delayed `llm_verify` (the harness got no items) and `llm_apply` (answers were not applied) for
hours. The supervisor restarts crashed workers (with a backoff), puts the jobs of a dead worker back to pending and
removes its leftover workspaces.

### LLM throughput

A rule run sends its objects to the model in chunks of 25 (between chunks the objects reserved by an external run are
dropped); within a chunk up to `LLM_CONCURRENCY` calls are in flight from a thread pool (one object per call: a field
rule asks about every candidate field of the object in one call, an object rule about the object; the core prompt
contract has no multi-object call, and changing it would make every verdict stale). The verdicts of a chunk are stored
in chunk order whatever order the calls finished in, so writes stay deterministic and idempotent. A graceful stop
lets the calls in flight finish and asks nothing new. `LLM_RATE_PER_MIN` is a token bucket in Postgres
(`llm_rate_buckets`, `discovery_common/llm_rate.py`) shared by every worker, thread and replica: each call takes a
token first and waits while the bucket is empty (0 = no limit; set it to the provider's quota). Keep `LLM_CONCURRENCY`
near `LLM_PARALLEL` for the bundled llama.cpp server; raise it (4-8) and `LLM_WORKERS` for an API model. The
`job_health` snapshot shows the settings and the tokens left (`limits`).

## Job kinds

| kind | queued by | what it does |
|---|---|---|
| `sync_projects` | scheduler, every `PROJECTS_POLL_INTERVAL_S` | lists the projects of the prefixes, queues `sync_branches_mrs` for the ones with new GitLab activity (`last_activity_at`) or not synced for `SYNC_UNCHANGED_EVERY_H` |
| `sync_branches_mrs` | `sync_projects` | re-reads one project: its open MRs (one page of 100), the default branch and the MR branches by name (not every branch of the repository), the states of the MRs that left the open list in one batched call; queues `scan_branch` / `scan_mr` |
| `scan_branch` | sync, `POST /projects/parse` | clone, parse, keyword rules, save the snapshot of a main branch (or a diff-based skip); then queues `llm_score` |
| `scan_mr` | sync, `POST /mrs/{id}/scan` | the delta of an open MR against its target, LLM rules on the delta |
| `llm_score` | after a main scan, `POST /llm_rules/run` (executor `service`), rollout slices | the service model runs the LLM rules on the fresh candidates of a branch |
| `llm_prepare` | `POST /llm_rules/run` (executor `external`), take-over | records the model calls of an external run as work items, no model call |
| `llm_apply` | `llm_work_submit`, scheduler (safety net) | replays submitted answers through the hit code |
| `llm_verify` | after every service `llm_score` run | records verify items (escalations, QA sample, re-verifications) for the harness model |
| `llm_trial` | `POST /llm_rules/{id}/trials` | a candidate prompt on a few subjects with the service model, no hits |
| `llm_rollout` | scheduler, every `LLM_ROLLOUT_TICK_S` | rule versions vs core prompts / model; queues `llm_score` slices of the running rollouts |
| `llm_coverage` | scheduler, every `LLM_COVERAGE_INTERVAL_S` | recounts stale LLM coverage rows (`GET /llm_progress`) |
| `llm_relabel` | activation of a rule version that differs only in core prompts / model, a rollback (`lifecycle.enqueue_relabel`) | relabels / adopts the machine verdicts of the rule in slices of 5000 rows (one transaction each, yields after 20 slices) instead of one UPDATE over every hit of the rule inside the API transaction; the rollout controller waits for it; `progress = {phase, action, rule_id, to_version, rows, slices}` |
| `stats_refresh` | scheduler, every `STATS_REFRESH_S` | recomputes the statistics snapshots (`stats_snapshots`: `overview`, `job_health`, `scan_progress`, `llm_progress`, `llm_quality`, `hits_aggregate`; `discovery_common/stats.py`) the API serves while fresh; `progress.seconds` per snapshot |
| `ingest` | `POST /ingest` / sessions | applies a pushed external parser state |
| `cleanup` | scheduler, every `GC_INTERVAL_HOURS` | retention and garbage collection |

## Progress and runs

`GET /jobs`, `GET /jobs/{id}` (MCP `list_jobs` / `get_job`; UI Jobs page with tabs Active / Failed 24 h / All) show
every job with its resolved `subject` (project, branch, MR, rule names) and `progress`:

* `scan_branch` / `scan_mr`: the phase (`waiting` -> `clone` -> `parse` -> `save` -> `done` | `skipped` |
  `partial` | `failed`), object counts per parser, `failed_parsers`, `full_scan_reason` or `skipped`.
* `llm_score` / `llm_prepare`: `{"executor", "phase", "total_objects", "done_objects", "failed_objects",
  "skipped_objects", "rule_ids", "started_at", "finished_at", "errors"}`, written in batches;
  `skipped_objects` are objects a service run left to an external run that reserved them.

`GET /llm_runs` (MCP `llm_runs`) lists the active LLM runs (queued, running, external ones awaiting answers,
verify jobs with `purpose: verify`) and the ones finished in the last 24 hours with rule names, project / branch and
"N of M processed"; the Pipeline health page ("Rule runs"), the Runs tab of an LLM rule and the Jobs page show
them as progress bars.

`GET /jobs/stats` (MCP `job_stats`): counts per kind and status. `GET /jobs/health` (MCP `job_health`): per kind
pending / retrying / running / failed, done and failed in the last hour / 24 hours (skipped scans counted apart),
the oldest pending and longest running job, the typical run and wait time of the last 24 hours (p50 from
`started_at`) and an ETA for the pending jobs, busy workers, service LLM throughput (objects per hour from the runs'
progress), an ETA for the pending LLM runs and `scans` (full vs skipped in 24 hours). Served from the `job_health`
statistics snapshot (refreshed every `STATS_REFRESH_S`, `computed_at` in the response), which also carries
`escalations` (the day's harness escalations per rule and the overflow over `LLM_ESCALATION_DAILY_MAX`) and `limits`
(workers per pool, `LLM_CONCURRENCY`, `LLM_RATE_PER_MIN` and the tokens left). No history is stored: the Pipeline
health page judges by the current backlog and ages. `POST /jobs/{id}/retry` (failed jobs) and
`POST /jobs/{id}/cancel` (pending ones) are available as MCP `job_retry` / `job_cancel`.

## Why a job failed

`jobs.last_error` carries the real cause, not a generic "scan failed" (`discovery_scanner/services/failures.py`:
a `ScanError` raised where the cause is known, the handler puts the job's subject in front):

* a failed git clone: the last `fatal:` line - `scan of 'grp/payments-api', MR !25: cannot clone source branch
  'release/x': remote branch not found in upstream origin (deleted?)`;
* a parser that broke a partial scan, and its error;
* an LLM run: the per-rule summary - `LLM rule 'db-tables-with-client-data': 3 of 120 objects failed: LlmError:
  LLM answer truncated at max_tokens=8192 (2), APITimeoutError: Request timed out (1)`; the failed objects with
  their reason stay in `jobs.progress.errors` (the first 20 and counts per error class, also when the run ended
  done / incomplete).

Credentials never reach the database or the UI (`discovery_common/redact.py`: URL userinfo, GitLab / generic
bearer tokens, `Authorization` headers, `token=` / `password:` values are replaced by `***`). A permanent cause (a
deleted MR source branch or repository, a configuration error) fails the job at once instead of retrying, and the
MR is marked processed. An MR that was merged or closed (or deleted) in GitLab before its scan, with its source
branch deleted, is not a failure: the job ends as `skipped` ("MR merged, source branch deleted: not scanned") and
the next sync stores the MR's state; only a deleted source of a still open MR fails.

Where it shows: the Jobs list and job page, Pipeline health "Failures (24 h)", `GET /jobs/errors` (failures grouped
by cause: quoted subjects, ids and hashes replaced by `#`), `GET /llm_rules/{id}/errors` ("Last errors" in the
Runs tab of an LLM rule: failed objects, failed runs and refused harness answers, `llm_work_items.error`, also on
the Harness work page).

## Graceful shutdown

On SIGTERM (`docker compose stop`, a deploy) the supervisor stops its workers: each sets a stop flag that the
running job checks at its next safe point and then hands the job back (pending again at once, no attempt used,
`stopping: job N requeued ...` in the log). A service LLM run stops after the model call in flight and stores the
verdicts of the objects asked so far (no paid answer is lost; the next run asks only what is left); a parse scan
stops before clone / parse / save; `llm_prepare` / `llm_apply` / `llm_coverage` end their slice. Workers still busy
after `SHUTDOWN_TIMEOUT_S` (150 s; one model call takes up to `LLM_TIMEOUT_S` per try) are killed and their jobs
re-queued; `stop_grace_period` of the scanner in `docker-compose.yml` (180 s) must stay above it.
