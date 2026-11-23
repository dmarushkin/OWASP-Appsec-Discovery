---
hide:
  - footer
---

# Data model and migrations

The schema is owned by Alembic (`discovery_common/migrations`, run by the `discovery_migrate` container:
`python -m discovery_common.migrate [revision]`); the services never create tables. Models:
`discovery_common/models.py`.

## Tables

| table | what it holds |
|---|---|
| `gitlab_projects` | tracked projects: `gitlab_id`, `full_path`, `scan_mode` (`rules` \| `inventory`), `source` (`gitlab` \| `external`), `updated_at` / `processed_at` of the sync |
| `gitlab_branches` | main branches and tracked MR source branches: `commit`, `scanned_commit`, `scan_fingerprint`, `full_scanned_at`, `delta_target_commit` (0029) |
| `gitlab_mrs` | open MRs (`state`, `closed_at`) and which source branch owns a delta |
| `discovery_scans` | scan markers per branch and commit (parsers, rule versions, partial scans) |
| `objects`, `object_fields` | content-addressed object versions and their fields (comments, samples); `objects.names_hash` / `object_fields.llm_hash` (0030): what the LLM rules see of the row, stored once |
| `branch_objects` | which object version a branch has (`is_main`; MR deltas: `change` added \| modified \| removed), lines |
| `rules` | keyword / LLM / manual rules: `kind`, `target`, `mode`, `scope` (jsonb), `prompt`, `version`, `tags`, `enabled`, `deleted_at` |
| `rule_hits` | one row per rule and subject: `status`, `category`, `severity`, `reviewer`, `decided_via`, `decided_tier`, `machine_status`, `rule_version`, `prompt_version`, `model`, `reason`, `fields`, `names_hash`, `subject_hash`, `verify_key`, `asked_by_model`, `verifier_model`; presence `in_main` / `in_open_mr` (0030, see below) |
| `hit_verdicts` | verdict history of the LLM hits (triggers) |
| `rule_versions` | versions of LLM rules with the pinned core prompts version and service model |
| `llm_rollouts` | rule rollouts (status, mode, budget, progress) |
| `llm_runtime` | what the scanner runs with (`service_model`) |
| `stats_snapshots` | statistics precomputed by the scanner (`overview`, `job_health`, `scan_progress`, `llm_progress`, `llm_quality`, `hits_aggregate`: `name`, `data` jsonb, `computed_at`), served by the API while fresh (0030) |
| `llm_coverage` | per branch and LLM rule: candidates, answered, stale, pending external, failed |
| `llm_work_items` | work items of external runs (`purpose = score`) and verify items (`purpose = verify`): `pending`, `leased`, `answered`, `applied`, `failed`, `expired` |
| `llm_verifications` | every harness answer applied or refused (QA metrics) |
| `prompt_trials`, `prompt_trial_items`, `prompt_proposals` | prompt trials and proposals |
| `jobs` | the job queue: `kind`, `status`, `payload`, `dedup_key`, `priority`, `attempts`, `locked_by`, `progress`, `last_error` |
| `ingest_batches`, `ingest_chunks` | external parser states |
| `api_tokens` | service tokens (sha256 only) |

## Keys (`discovery_common/keys.py`)

* `object_key` - identity of an object: project + parser + the core's `CodeObject.hash`; lines, fields, props,
  severity, branch and commit are not part of it, so it is stable across branches and commits.
* `content_hash` - identity + sorted `field_name:field_type` + sorted `prop=value`: changes exactly when the
  object's shape changes.
* `field_key` - `object_key` + field name: the subject of field-level rules (`rule_hits.subject_key`; the
  field type is deliberately not in it).
* `names_hash` / `subject_hash` - what an LLM verdict was made on, see [LLM rule lifecycle](llm-lifecycle.md).

All keys are `md5(...)` cast to `uuid`; the migrations compute the same keys in SQL and the tests check both
implementations agree.

## Presence of a hit (`in_main`, `in_open_mr`)

A hit is branch-agnostic (one row per rule and subject). Whether its subject is in some main snapshot or in the delta
of an open MR is stored on the row (`rule_hits.in_main` / `in_open_mr`, migration `0030`) and maintained by the
scanner (`discovery_common/presence.py`): a main scan marks its hits `in_main` and refreshes the hits of the objects
the snapshot diff removed or changed, an MR scan does the same with `in_open_mr`, pruned MR rows, a reopened or
closed MR, a released or untracked source branch and a demoted main branch refresh the hits of the objects they
held, LLM verdicts and harness field marks refresh the objects they are about. The API's `presence` filter
(`main` = `in_main`, `mr` = `in_open_mr AND NOT in_main`, `live` = either) and `HitOut.in_main` / `in_open_mr` read the
columns; the [retention](retention.md) deletes only hits with both flags false. Anything else that inserts hits
calls `presence.refresh(session, object_keys=...)` afterwards. Partial indexes: `hits_live_seen` (live hits in list
order), `hits_live_queue` (the open review queue per project), `hits_seen` (hits in no branch, for the retention).

## Stored LLM hashes

`object_fields.llm_hash` = `llm_field_hash(name, type, comment, samples)` and `objects.names_hash` =
`llm_names_hash(name, field names)` (migration `0030`) are written with the content-addressed rows (the Python twins
in `discovery_common/keys.py`; `names_hash` follows a rename of the stored version) so the candidate selection of an
LLM run and the coverage counts compare stored hashes instead of hashing every field of the branch per run. A row
without one (none after the backfill) is hashed in place (`COALESCE`).

## Migrations

| revision | effect |
|---|---|
| `0001_baseline` | the schema the services created before Alembic; idempotent, adopts an existing database |
| `0002_storage_v2` | content-addressed objects, relational fields, branch deltas, `rules` / `rule_hits` |
| `0003_rules_review` | rule modes and human review |
| `0004_jobs` | the job queue |
| `0005_inventory_mode` | scan mode `inventory`, the `manual:labels` rule |
| `0006_hit_fields` | `rule_hits.fields` of object hits |
| `0007_rule_tags` | rule tags set on objects |
| `0008_decided_via` | `rest` \| `mcp` on human decisions |
| `0009_external_ingest` | external projects, ingest batches, service tokens |
| `0010_comments_samples` | comments and samples of objects and fields |
| `0011_ingest_superseded` | ingest batch status `superseded` |
| `0012_llm_work` | `jobs.progress`, `llm_work_items` (external executor) |
| `0013_example_rules` | default LLM rules `db-tables-with-client-data` (enabled) and `api-with-auth` (disabled) |
| `0014_hit_prompt_version` | `rule_hits.prompt_version` |
| `0015_jobs_subject` | indexes of the jobs of one branch / MR |
| `0016_llm_prepare` | the `llm_prepare` job kind; external runs queued as `llm_score` become `llm_prepare` |
| `0017_llm_coverage` | `llm_coverage`, index of the LLM jobs of one branch |
| `0018_llm_reask` | `names_hash` / `subject_hash` on LLM hits, SQL hash functions, backfill from the current snapshot (asks nothing again) |
| `0019_prompt_trials` | prompt trials and proposals, `rule_hits.machine_status` |
| `0020_llm_tiers` | tiered decisions: `decided_tier`, verify items, `llm_verifications` |
| `0021_service_tier` | tiers renamed `weak` -> `service`, `strong` -> `harness` (columns, constraints, verify item keys); the hits filter accepts the old names for one release |
| `0022_no_alerts` | alerting removed: `alert` keyword rules become `score`, `alerted_at` columns dropped |
| `0023_match_statuses` | hit statuses `confirmed` -> `match`, `rejected` -> `no_match` everywhere (`rule_hits`, `machine_status`, `verify_key`, `llm_verifications`, trial items, open verify items) |
| `0024_rule_versions` | `rule_versions`, `llm_runtime`, core prompt versions per family (`classifier{N}` / `rule{N}`), backfilled so nothing is asked again |
| `0025_hit_verdicts` | verdict history triggers, backfill of the current LLM hits |
| `0026_llm_rollouts` | `llm_rollouts`, `jobs.priority` |
| `0027_object_names` | stored object names lose their type prefix (`Route /x (GET)` -> `GET /x`); `names_hash` recomputed; rules whose patterns still contain a type word are listed in the log (run online: the rename is computed in Python) |
| `0028_builtin_rules` | built-in keyword rules renamed `kw-fields` / `kw-props` and disabled on new installs; the env-managed LLM rule removed; `api-with-auth` seeded |
| `0029_diff_skip` | `gitlab_branches.scan_fingerprint`, `full_scanned_at`, `delta_target_commit` for the diff-based scan skip; existing branches are fully scanned once at their next commit |
| `0030_scale_storage` | storage at scale: `rule_hits.in_main` / `in_open_mr` (backfilled) with the partial indexes `hits_live_seen`, `hits_live_queue`, `hits_seen`; `objects.names_hash`, `object_fields.llm_hash` (backfilled); indexes `hits_object (object_key)`, `hits_project_rule (project_id, rule_id)`, `objects_name_key (name, object_key)`, `jobs_ready_kind`, `hit_verdicts_subject` gets `rule_version`; `rule_hits` fillfactor 85 + autovacuum settings; table `stats_snapshots` |

`0030_scale_storage` rewrites every row of `object_fields`, `objects` and `rule_hits` once (the backfills run project
by project in the migration's transaction). Measured on a throwaway Postgres 13 with 587k fields, 61k object
versions and 152k hits: 63 s, most of it the rewrite of `object_fields` (index maintenance of the rewritten rows, the
trigram index included); budget roughly a minute per 600k fields for the upgrade.

Upgrade the migrate, API, scanner and UI images together: older versions cannot write to a migrated database
(e.g. an old scanner writes `confirmed`, which the `0023` CHECK refuses).
