---
hide:
  - footer
---

# LLM rule lifecycle

What makes the service ask the model again, how rule and prompt versions are tracked, and how the verdicts of an
old version migrate to a new one (`discovery_common/lifecycle.py`, scanner `services/lifecycle_service.py`,
migrations `0018`, `0024` .. `0026`).

## What a verdict was made on

Every LLM hit stores the rule version (`rule_hits.rule_version`), the core prompt version (`prompt_version`,
per family: `classifier{N}` for the built-in classifier, `rule{N}` for the other rules; both currently `3`), the
`model`, and two hashes of what the model saw (`discovery_common/keys.py`, SQL twins `llm_names_hash` /
`llm_field_hash`):

* `names_hash` - object name + sorted field names (field hits: object name + the one field);
* `subject_hash` - object rules: the object's content hash (field names, types, props, comments, samples);
  field rules: the field's name, type, comment and samples.

A subject is asked again when:

| what changed | machine verdict (tier `service`) | harness decision | human decision |
|---|---|---|---|
| nothing | kept | kept | kept |
| rule version / core prompts / service model | **stale**: kept, shown, scoring; asked again by the rule's rollout (`LLM_REASK_INLINE=true`: by the next run) | kept | kept |
| content only (types, comments, samples; field rules: the field's own content) | asked again by the next run, replaced | asked again: the service answer replaces it and the hit is verified again (`reverify`) | kept |
| object rules: the object's field names (a field added / removed / renamed) | asked again, replaced | carried over like a human decision | asked again, see below |
| field rules: a field renamed | a new subject (new field key): asked | the old field's decision stays with the old name | the same |

A human-decided object hit asked again because its field names changed: the fields confirmed before are the
`fields` of an object hit a human set to `match` plus the fields whose field hits (`mark_fields`) a human set to
`match`. When the model's answer names a field not confirmed before, the hit goes back to `pending_review` in the
review queue (reviewer cleared, note `re-review: new fields X, Y (was confirmed by alice)`; the new fields' marks
`pending_review` too, also in mode `auto`). When it names only confirmed fields, or answers `no_match`, the
decision is carried over (status, reviewer, `decided_via`, category, severity kept; version, prompts, hashes,
model, reason updated; note `confirmation carried over to the new version`). A harness decision is carried over
the same way (`confirmation (harness model M) carried over ...`). A reopened hit asked again gets the new
proposal and stays pending.

When a main snapshot is saved, machine-made LLM hits of fields that no longer exist in any stored version of their
object are removed (also when an object rule no longer names a field it marked before); human decisions on deleted
fields are kept as history under the [retention](retention.md). Keyword hits are not affected. Hits are
branch-agnostic: an object whose MR version differs from its main version is asked again by each branch's run
after the other (once per scan, not in a loop).

## Rule versions

A prompt / scope / target / `mark_fields` edit of an LLM rule, an accepted prompt proposal, new core prompts of a
deploy or another `LLM_API_MODEL` make a new **rule version** (`rule_versions`: `draft` -> `candidate` ->
`active` -> `retired` | `rolled_back`; `rules.version` is the active one's number). A version pins the core
prompts version and the service model its verdicts belong to; a verdict is current when it was made by the active
version with its pinned (or the code's) core prompts and its model. Name, category, severity, mode, `enabled` and
`tags` are metadata and keep the version; a category / severity edit goes to the machine hits at once.

* **Fresh vs migration**: every LLM run asks the *fresh* subjects (no verdict, other content, other field names, a
  reopened hit); the machine verdicts of an older version (*migration*) are kept, shown and scoring, flagged
  **stale** (`HitOut.stale` / `stale_reason`, hits filter `stale=true`, a badge in Review, `answered_stale` in
  `GET /llm_progress`) until the rule's rollout asks them again. Human and harness decisions are never migrated.
* **Versions tab** of the LLM rule page (`GET /llm_rules/{id}/versions`, `POST /llm_rules/{id}/versions` makes a
  candidate, `GET /llm_rule_versions/{id}[/estimate]`, `POST /llm_rule_versions/{id}/activate | rollback |
  discard`): the diff to the active version, the cost of activating it (model calls: fresh subjects, the migration
  by old status, protected human / harness decisions; nothing is asked), activation by a human. A `PUT` edit of the
  prompt / scope is active at once (`?candidate=true`: only a candidate) and its rollout is `planned`
  (`LLM_ROLLOUT_DEFAULT` canary | staged: a human starts it; immediate: running at once). On activation the open
  verify items of older versions expire; a version that differs only in core prompts / model relabels the verdicts
  that already have its key without model calls.
* **Rollback** to a retired version: a new version with its content is activated and its verdicts are adopted from
  the history without model calls (not for `mark_fields` rules); the rest migrates by a rollout.
* **Relabel / adopt at scale**: both touch every machine verdict of the rule. Done inline they are one `UPDATE` inside
  the API's transaction (minutes at millions of hits, every row of the rule locked meanwhile), so the API queues them
  as an `llm_relabel` job instead (`lifecycle.enqueue_relabel`, `batch_jobs=True` on `activate_version` /
  `rollback`; the response carries `relabel_job_id` / `adopt_job_id` and `relabelled` / `adopted` are `null`). The job
  (control pool, priority +5) changes 5000 rows per transaction with the same `hit_verdicts.source` (`relabel` /
  `adopt`) and yields every 20 slices; the rollout controller does not queue slices of the rule while it runs
  ("a relabel / adopt job of the rule is running"). The scanner's own activations (core bump / model change in
  `immediate` mode) use the job too.
* **Deploys**: the `llm_rollout` controller pins every LLM rule to the core prompts / `LLM_API_MODEL` the scanner
  runs with (`llm_runtime`); new core prompts make a candidate version per affected rule (`LLM_CORE_BUMP_MODE`
  canary | manual: a human activates it; immediate: activated, rollout running), another model likewise
  (`LLM_MODEL_CHANGE_POLICY` rollout | reask | ignore - ignore records the new model without making verdicts
  stale). Nothing is asked before activation; a new classifier prompt does not touch the object / field rules.

MCP reads all of it (`llm_rule_versions`, `llm_rule_version_estimate`); activating a version is for humans.

## Rollouts

`llm_rollouts` (Pipeline health "Rollouts", the Versions tab, `GET /llm_rollouts[/{id}]`,
`POST /llm_rollouts/{id}/start | pause | resume | cancel`; MCP `llm_rollouts`, `llm_rollout` read): the
`llm_rollout` job (control worker, every `LLM_ROLLOUT_TICK_S` = 60 s) queues `llm_score` slices of the stale
verdicts per main branch - `need_more_info` first, then positive, then `no_match`; rules by severity - within the
budget of all rollouts: `LLM_ROLLOUT_CALLS_PER_HOUR` (2000 model calls), `LLM_ROLLOUT_MAX_PARALLEL_JOBS` (1 slice
of `LLM_ROLLOUT_SLICE_OBJECTS` = 200 objects), nothing while more than `LLM_ROLLOUT_FRESH_BACKLOG_MAX` (20) fresh
LLM runs wait. Slices have job priority -10 and are never taken over by an external run. A rollout's own `budget`
overrides these (`max_calls` pauses it once used). Statuses: `planned`, `canary`, `awaiting_approval`, `running`,
`paused`, `done`, `cancelled`, `rolled_back`, `failed`.

A rollout pauses itself when the harness model's agreement on the QA sample of the new version drops
(`LLM_ROLLOUT_QA_MIN_SAMPLES` 20, `LLM_ROLLOUT_QA_AGREEMENT_MIN` 0.8, `LLM_ROLLOUT_QA_MAX_DROP` 0.1). MR deltas
are not migrated by rollouts: `scan_mr` asks the stale verdicts of its (small) delta. Progress: planned /
remaining objects, calls, ETA, why it waits.

## Verdict history

`hit_verdicts` logs every change of an LLM hit's verdict (status, version, prompts, model, reason, fields, tier,
reviewer) by a trigger with its source (`service` | `harness` | `human` | `adopt` | `relabel` | `backfill`) and
rollout. `GET /hits/{id}/history` (MCP `hit_history`) and the hit page tab **History** show it with a
per-version diff; kept `HIT_HISTORY_DAYS` (180), the last row of every version of a subject always.
