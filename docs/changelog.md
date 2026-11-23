---
hide:
  - footer
---

# Changelog

## 1.1.0 (2026-11-23)

* **Closed MRs with a deleted source branch** (service, scanner): a `scan_mr` whose source branch is gone because the
  MR was merged / closed (or deleted) in GitLab meanwhile ends as `skipped` instead of failing; a deleted source of
  a still open MR, or a state GitLab cannot tell, fails as before.
* **Disk guards of clones** (service, scanner): no clone starts while the workspace has less than
  `WORKSPACE_MIN_FREE_GB` (5) free (a retried failure with the cause on Pipeline health); `SCAN_MAX_REPO_MB` (0 = off)
  refuses repositories GitLab reports larger (permanent); MR sources that need their history are partial clones
  (`--filter=blob:none`, `GIT_PARTIAL_CLONE`); a clone that fills the disk reports `no space left on device` and its
  partial checkout is removed at once; compose mounts the workspace as the volume `scan_workspace`
  (`SCAN_WORKSPACE_VOLUME`: a host directory on another disk).
* **UI at scale** (service, `discovery_ui`): the Review page opens on a **cluster board** (the open hits grouped by
  same schema / same field / same object name / rule x group, `GET /hits/clusters`) with **Decide cluster**
  (`POST /hits/decide`: dry run, "Apply to N" with `expected_total`, a toast with **Undo** and a "Recent decisions by
  filter" section) and "Decide all" on any filter in the list view; the flat list with keyboard triage stays as a view
  and inside a cluster; the Questions tab stays one by one. The tabs, the menu badge, the Work desk tiles, the Pipeline
  "Human" tile and the Group view count the same queues from one `GET /hits/aggregate` (the Work desk tiles showed
  wrong captions and three different numbers for one queue). Lists show estimated totals ("about N rows", an exact
  count on click) and page by keyset cursor. Statistics come from the snapshots with `ETag` and "updated N s ago";
  polling waits for the previous answer, slows down in hidden tabs and backs off on errors. A **scope bar** (GitLab
  group, kept in the URL) narrows every list and count; a **project page** (`/projects/:id/show`) and a **Group view**
  (`/groups`) replace the project searches; Jobs filter by project. Server-side autocompletes (`/rules?q=`,
  `/categories`, `/object_types`, `/groups?q=`) replace the 500-rule and overview dropdowns. Hit rows, the verdict card
  and object rows carry **In main / Only in open MR / Gone** chips. Pipeline health shows the real typical run / wait
  times and ETAs, the escalation overflow, the worker pools and limits, collapses idle kinds and says the reach of its
  actions ("Parse first 200 of N"). Service tokens can be created with scope `mcp` (the connect snippet shown once);
  the Harness snippets take a token placeholder. Every API cap is said on the page ("N of M shown", "top 200"). See
  [UI](service/ui.md).
* **API and MCP at scale** (service, migration `0032_scale_api`): hit presence filters read the stored
  `in_main` / `in_open_mr` flags (manual labels refresh them); list totals are **estimates above 10 000 rows**
  (`X-Total-Estimate`, `exact=true` for a count) and lists page by **keyset cursor** (`after` / `X-Next-Cursor`)
  next to `range`; `GET /objects` lists the main snapshot without a DISTINCT ON over every live row and computes
  the per-row figures for the page only; `GET /overview`, `GET /jobs/health`, `GET /scan_progress` /
  `GET /llm_progress` totals and `GET /llm_quality` are served from the scanner's **statistics snapshots** with
  `computed_at`, `ETag` and `304`; `GET /jobs/health` `typical_run_s` / `typical_wait_s` / `eta_s` are no longer
  null (`jobs.started_at`). **Review at scale**: `GET /hits/aggregate` (counts by queue / rule / category / project /
  group ... in one call), `GET /hits/clusters` (schema / field pattern / object name / rule x group clusters of the
  open hits), `POST /hits/decide` (one decision on every hit of a filter: dry run, `expected_total`, human decisions
  kept, `review_batches`, `POST /hits/decide/{id}/undo`, `batch_id` in the verdict history); the `cluster` and
  `group` filters of `GET /hits`. **Autocompletes**: `GET /rules?q=`, `GET /categories`, `GET /object_types`,
  `GET /groups`; `group=<prefix>` on hits / objects / projects; `GET /projects/{id}` is the project page (hits by
  rule, objects by type, open MRs, jobs; `GET /jobs?filter={"project_id"}`). **MCP**: response byte cap
  (`MCP_MAX_RESPONSE_BYTES`, `truncated` + `hint`), cursor paging and estimated totals, `summary` views of
  `get_hit` / `get_object`, `scan_progress` without the project list by default (`include_projects=true` or a
  filter), per-client service tokens with scope `mcp` (`POST /tokens`; reviewer and lease owner `token:<name>`,
  accepted on REST too) and a per-client rate limit (`MCP_RATE_LIMIT_PER_MINUTE`), `ui_url` deep links
  (`UI_BASE_URL`), new tools `hits_aggregate`, `hits_clusters`, `decide_hits`, `undo_decision`, `review_batches`,
  `list_groups`, `get_project`. Prompt trial samples use `TABLESAMPLE`. See [REST API](service/api.md),
  [MCP server](service/mcp.md), [Tiered review](service/tiers.md#human-review).
* **Pipeline at scale** (service, migration `0031_scale_pipeline`): the GitLab sync gets a worker pool of its own
  (`SYNC_WORKERS`, 2) and the control jobs theirs (`CONTROL_WORKERS`, 1), so harness verify items, external answers
  and rollouts never wait behind thousands of project syncs; a sync reads only the default branch and the MR branches
  by name, the MR states in one batched call, and skips projects without new GitLab activity (`SYNC_UNCHANGED_EVERY_H`,
  24; polling only, no webhooks). LLM throughput: `LLM_CONCURRENCY` (2) model calls in flight per LLM worker, verdicts
  stored in chunk order; `LLM_RATE_PER_MIN` (0 = off), a token bucket in Postgres shared by every worker and replica.
  Harness escalations capped at `LLM_ESCALATION_DAILY_MAX` (2000) per rule and UTC day, the overflow counted
  (`escalation_overflow` in the verify job, `job_health.escalations`). Relabel / adopt of a rule version's verdicts
  as an `llm_relabel` job in slices (`lifecycle.enqueue_relabel`, `batch_jobs=True`) instead of one UPDATE in the API
  transaction. `stats_refresh` job (`STATS_REFRESH_S`, 60) writes the `stats_snapshots` (`overview`, `job_health`,
  `scan_progress`, `llm_progress`, `llm_quality`, `hits_aggregate`; shared SQL in `discovery_common/stats.py`) the
  API serves while fresh. `jobs.started_at` stays on finished rows, so `GET /jobs/health` `typical_run_s` /
  `typical_wait_s` / ETA are no longer null; expired leases are reaped by the scheduler, not on every claim. The
  compose file forwards every scanner setting (`GITLAB_CACHE_TTL_S`, `GIT_TIMEOUT_S`, `JOB_POLL_S`, `LLM_ROLLOUT_QA_*`,
  ...) and rotates the logs of every container (`LOG_MAX_SIZE` 50m x `LOG_MAX_FILE` 5). See
  [Jobs and workers](service/jobs.md), [Scanning](service/scanning.md#projects-and-branches),
  [Tiered review](service/tiers.md#verify-items), [Configuration](service/config.md).
* **Storage at scale** (service, migration `0030_scale_storage`): hit presence stored on the row (`rule_hits.in_main`
  / `in_open_mr`, maintained by the scanner on every snapshot, MR and branch change, backfilled) with partial indexes
  for the live list, the open queue and the retention; stored LLM hashes (`object_fields.llm_hash`,
  `objects.names_hash`) so candidate selection and coverage no longer hash every field per run; coverage groups only
  by what a rule's patterns look at; indexes `rule_hits (object_key)`, `rule_hits (project_id, rule_id)`, `objects
  (name, object_key)`, `jobs` ready-by-kind; `rule_hits` fillfactor 85 and autovacuum settings; the snapshot diff of
  a main scan is linear in the branch size (was quadratic: minutes for a 300k-object branch); orphan GC in one pass;
  retention of harness verifications (`LLM_VERIFICATIONS_RETENTION_DAYS`, 365) and finished prompt trials
  (`PROMPT_TRIALS_RETENTION_DAYS`, 90); `stats_snapshots` for precomputed statistics; Postgres memory / planner
  settings in the compose file (`PG_*`). See [Data model](service/data-model.md), [Retention](service/retention.md),
  [Configuration](service/config.md#postgres-compose).
* **Diff-based scan skip** (service): a new main branch commit or MR activity that changes no file a parser reads
  moves the snapshot without a clone, a parse or an LLM run (GitLab compare API; `SCAN_DIFF_*` settings; migration
  `0029_diff_skip`; `GET /jobs/health` `scans`). Full MR scans take the changed files from the compare API and
  clone the source shallow. Core 1.1.0: `Parser.file_patterns`, `appsec_discovery.affected_parsers`. See
  [Scanning](service/scanning.md#diff-based-scan-skip).
* **Failure causes in the UI**: `jobs.last_error` carries the real cause of a failed scan or LLM run (the git
  `fatal:` line, the parser that broke, the per-rule summary of an LLM run; `discovery_scanner/services/failures.py`),
  credentials stripped (`discovery_common/redact.py`); `GET /jobs/errors` groups failures by cause,
  `GET /llm_rules/{id}/errors` collects a rule's failed objects, runs and refused harness answers. Permanent
  causes (a deleted MR branch, a configuration error) fail at once without retries.
* **LLM rules lifecycle** ([LLM rule lifecycle](service/llm-lifecycle.md)): rule versions (`rule_versions`; the
  Versions tab with diff, cost estimate, activate, rollback), budgeted **rule rollouts** of the stale verdicts
  (`llm_rollouts`, the `llm_rollout` controller job, pause / resume / cancel, auto-pause on a harness agreement
  drop), explicit stale-while-revalidate (`stale` / `stale_reason` on hits, filter `stale`, `answered_stale` in
  the LLM coverage), the verdict history of every LLM hit (`hit_verdicts`, `GET /hits/{id}/history`, the hit page
  tab History), core prompts versioned per family (`classifier3` / `rule3`) and pinned per rule version, the
  service model tracked per version, `jobs.priority`. **Behaviour change**: a prompt / scope edit, an accepted
  proposal, new core prompts or another `LLM_API_MODEL` no longer re-ask every machine verdict in the next runs:
  the verdicts stay (flagged stale, still scoring) and a rollout - started by a human (`LLM_ROLLOUT_DEFAULT=canary`)
  - asks them again within `LLM_ROLLOUT_CALLS_PER_HOUR`; accepting a prompt proposal makes a candidate version.
  The previous behaviour: `LLM_REASK_INLINE=true`, `LLM_ROLLOUT_DEFAULT=immediate`, `LLM_CORE_BUMP_MODE=immediate`,
  `LLM_MODEL_CHANGE_POLICY=ignore`. Migrations `0024_rule_versions`, `0025_hit_verdicts`, `0026_llm_rollouts`.
  New MCP read tools `llm_rule_versions`, `llm_rule_version_estimate`, `llm_rollouts`, `llm_rollout`, `hit_history`.
* **Stored object names are renamed** (migration `0027_object_names`): stored versions get the new names without
  the type prefix and the LLM hits' `names_hash` is recomputed, so the rename asks nothing again. Rules whose
  patterns still contain an old type word (`^Route`, `Struct dto`, `Table `, `Rpc `, `Mutation`, `Query `,
  `Virtual machine`...) are not rewritten: the migration lists them in its log - drop the word and use
  `object_type_re`. Run this revision online (the rename is computed in Python).
* **Built-in rules** (migration `0028_builtin_rules`): the keyword scoring rules are renamed `kw-fields` /
  `kw-props` and are **disabled on a new install** (existing installs keep their state); disabled, no `score_tags`
  hit is recorded. **The env-managed LLM rule is removed**: `LLM_PROMPT` / `LLM_PROMPT_VER` are gone (ignored
  when still set), the rule synced from them is soft-deleted (or only disabled when it has human decisions);
  create a classifier rule (an LLM field rule without category) in the UI if you used it. A second default LLM
  rule `api-with-auth` (disabled) is seeded on new installs.
* **Object names no longer contain the object type** (it is `object_type`): graphql `Mutation X.f` -> `X.f`,
  protobuf `Rpc /pkg.Svc/Method` -> `/pkg.Svc/Method`, swagger `Route /path (GET)` -> `GET /path`, python routes
  `Flask route /path calls Get handler (GET)` -> `GET /path (get)`, python / golang / java `Pydantic dto User` /
  `Struct dto User` / `Jpa entity User` -> `User`, javascript `JS GQL Resolver me in query GetUser` ->
  `GetUser.me`, migrations `Table public.users` -> `public.users`, terraform `Resource aws_s3_bucket.logs` /
  `Module x` -> `aws_s3_bucket.logs` / `x`, `Virtual machine vm` -> `vm`. Object identities (`hash`, the
  service `object_key`) are unchanged. **Breaking for config patterns that include the type word**: `object` of
  `score_rules`, `object_name` of `exclude_scan` / `exclude_scoring` (`^Route /admin`, `Struct dto`, ...) no
  longer match; drop the word and add `object_type` (and `parser`): `{object_type: route, object: 'POST /admin'}`.
  Names may now repeat across types; nothing keys on the name. SARIF messages keep the
  `[<parser>.<object_type>]` prefix.
* **Hit statuses renamed to the verdict words**: `confirmed` -> `match`, `rejected` -> `no_match`
  (`pending_review` and `need_more_info` stay). Who decided is `decided_tier` (`service` | `harness` | `human`).
  The reviewer actions keep their names (`confirm` / `reject` / `request_info` / `reopen`). Migration
  `0023_match_statuses` rewrites `rule_hits.status`, `machine_status`, the status suffix of `verify_key`,
  `llm_verifications.service_status`, trial items and open verify items. For one release the REST / MCP status
  filters and the library's `apply_hit_statuses` / `RuleHit(status=...)` accept `confirmed` / `rejected` as
  aliases; every output has the new values only. The aggregate keys `human_confirmed` / `human_rejected` (dry
  run) and `confirmed_by_category` (overview) and the settings `HITS_DECIDED_UNSEEN_DAYS` /
  `HITS_REJECTED_UNSEEN_DAYS` keep their names. Roll out the API, scanner and UI together with the migration.
* **Tier names** (migration `0021_service_tier`): the tiers are `service` (was `weak`) and `harness` (was
  `strong`) - `rule_hits.decided_tier`, `llm_verifications` columns `service_status` / `service_verdict` /
  `service_model`, the verify items' context keys; the API / MCP / UI say "service model" and "harness model". The
  hits filter `decided_tier` still accepts `weak` / `strong` for one release; the `GET /llm_quality` keys
  (`service_verdicts`, `service_unsure`, `harness_decisions`) and `llm_mislabeled` items (`harness_verdict`) are
  renamed without aliases. `VERIFY_PROMPT_VERSION` 2. The UI role "Engineer" is now "Datasec".
* **Alerting removed, read-only GitLab.** The service no longer posts MR comments or Telegram messages and never
  writes to GitLab: a token with `read_api` + `read_repository` is enough. The settings `MR_ALERTS`,
  `TG_ALERT_TOKEN`, `TG_CHAT_ID` and `ALERT_TIMEOUT_S` are gone (ignored), `get_mr` has no `alert_candidates`,
  MRs and hits no `alerted_at` / `alerted`. Migration `0022_no_alerts` turns keyword rules with `action: alert`
  into `score` rules. The REST / MCP rule API accepts `action` `score` | `exclude` only. `action: alert` in
  `conf.yaml` is deprecated: accepted for one release as `score` with a warning.
* **Default rules of a new service installation**: migration `0013_example_rules` seeds the LLM object rules
  `db-tables-with-client-data` (enabled) and `api-with-auth` (disabled), mode `auto`.
* **Default mode `auto` for new rules**: LLM rules default to mode `auto` like keyword rules (was `review`); auto
  hits are a `match` at once but stay in the harness QA sample. MCP `create_rule` / `update_rule` use the same
  defaults as the UI / REST (`allow_auto` is accepted and ignored).
* **UI**: the "Merge requests" page is removed (MR data stays available through `GET /mrs`, `GET /mrs/{id}`,
  `POST /mrs/{id}/scan` and the MCP tools `list_mrs` / `get_mr` / `scan_mr`); the keyword rule action "Alert"
  is gone.
* **Graceful shutdown** of the scanner on SIGTERM: running jobs are requeued at their next safe point, a service
  LLM run keeps the verdicts it already got (`SHUTDOWN_TIMEOUT_S`).
* **CLI**: the in-process llama.cpp backend (`ai_local`, `llama-cpp-python`) was removed; every model is reached
  through the OpenAI-compatible `ai_api` client. An `ai_local` section still loads as a deprecated alias.
