---
hide:
  - footer
---

# REST API

Behind nginx at `/api` (`uvicorn --root-path /api`); the interactive OpenAPI UI is at `/api/docs`. Every call
except `/health` needs `Authorization: Bearer <token>` from `POST /api/token` (`username` + `password` form
fields; rate limited to 5 per minute per client by nginx) or a service token with scope `mcp` (`POST /tokens`;
identity `token:<name>`, refused by the admin-only token endpoints). Lists follow the react-admin simple-rest
conventions: `?range=[0,24]&sort=["id","ASC"]&filter={"status":"pending_review"}`, the page size is capped, the
response carries `Content-Range`. Service errors map to 400 / 403 / 404 / 409 / 413 / 422 / 429.

## Paging at scale

`GET /hits`, `GET /objects` and `GET /projects` (millions of rows):

* the total of `Content-Range` is **exact up to 10 000 filtered rows and an estimate above** (the planner's row
  estimate; header `X-Total-Estimate: true`). `exact=true` (query parameter, or `"exact": true` inside `filter`)
  forces an exact count;
* **keyset paging**: every page answers `X-Next-Cursor` (absent on the last page); `after=<cursor>` (query parameter,
  or `"after"` inside `filter`) returns the rows after the previous page in the same sort order at the cost of one
  index probe, whatever the depth. A cursor is bound to the sort it was made with (422 otherwise). `range` (offset)
  keeps working for react-admin; `after` resets the offset to 0. `GET /projects` sorted by `pending_hits` (a count
  computed per row) answers no cursor: offset paging only;
* `group=<path>` on these three lists scopes to a GitLab group (a prefix of `full_path`: `grp/payments` matches
  `grp/payments/ledger`, not `grp/payments-old`); `GET /groups` lists the groups.

## Statistics snapshots

`GET /overview` (without arguments), `GET /jobs/health`, `GET /scan_progress` / `GET /llm_progress` (totals), `GET
/llm_quality` (without `rule_id`) and `GET /hits/aggregate` are served from `stats_snapshots`, recomputed by the
scanner's `stats_refresh` job every `STATS_REFRESH_S` (60 s) and served while younger than twice that. The answer
carries `computed_at` and `snapshot` (`true` from the table, `false` computed live - filters, a stale or missing
row, `live=true`). Snapshot answers get a weak `ETag` and `Cache-Control: max-age` until the next refresh; a request
with `If-None-Match` gets `304 Not Modified` - poll freely.

| endpoint | purpose |
|---|---|
| `POST /token` | login -> bearer token (`UI_TOKEN_TTL_MINUTES`) |
| `GET /health`, `GET /health/db` | liveness; database health and table statistics |
| **Hits (review)** | |
| `GET /hits` | the queue: filters `project_id`, `group`, `status` (list; `confirmed` / `rejected` accepted as aliases for one release), `category`, `rule_id`, `kind`, `severity`, `q`, `presence` (`main` \| `mr` \| `live` \| `all`; from the stored `in_main` / `in_open_mr` flags), `decided_tier` (`weak` / `strong` accepted as aliases of `service` / `harness` for one release), `decided_via`, `reviewer`, `asked_by_model`, `field_marks`, `stale`, `reviewed_after`, `first_seen_after`, `object_key`, `object_type`, `cluster` (`<by>:<key>` of `/hits/clusters`); paging: see above |
| `GET /hits/aggregate` | `by=` (comma separated) `queue` (questions \| pending \| unsure \| human \| harness \| service), `status`, `presence` (main \| mr \| gone), `rule_id` (+ `rule_name`), `category`, `severity`, `decided_tier`, `asked_by_model`, `in_main`, `in_open_mr`, `field_mark`, `kind`, `project_id` (+ `project_path`), `group`, `object_type`, `first_seen_day`; `filter=` as `GET /hits` (presence defaults to `live`). `{by, rows: [{<dim>..., n}], total, truncated, computed_at, snapshot}`; from the `hits_aggregate` snapshot when the filters / dimensions are in it (not for `q`, `project_id`, `group`, `object_type`, `cluster`, ...) |
| `GET /hits/clusters` | `by=schema` (object type + sorted `field:type` pairs) \| `field_pattern` (rule + field name) \| `object_name` (rule + type + name) \| `rule_group` (rule + GitLab group + type), `filter=` as `GET /hits` (default status open), `limit` (<= 100), `after`. `{by, items: [{key, cluster, label, rule_id, rule_name, object_type, field_name, group, n, n_open, questions, projects, groups, severity_max, in_main_share, new_7d, sample_ids, fields?, sample?}], scanned, truncated (more than 200 000 hits matched: narrow the filter), total_clusters, next_cursor, computed_at}` |
| `POST /hits/decide` | `{"filter": {...as GET /hits, at least one condition}, "action", "note" (required), "category", "severity", "expected_total", "dry_run": true, "include_human": false, "include_harness": false, "skip_questions": true}`. The dry run (default) returns `matched` (hits the action would change), `kept` (`human`, `harness`, `questions`, `transition`: hits whose status does not allow the action), `by_status`, `by_project` (top 10) + `by_project_more`, `sample` (5 ids). The apply needs `expected_total` = `matched` of the dry run (409 when the set changed meanwhile) and at most 100 000 hits; it returns `applied`, `cascaded` (field marks of decided object hits) and `batch_id`. Human decisions are kept unless `include_human`; the review transitions apply (a confirm changes open hits only) |
| `POST /hits/decide/{batch_id}/undo` | restores the previous state of the batch's hits nobody decided again since: `{restored, skipped}`; 409 when already undone |
| `GET /review_batches`, `GET /review_batches/{id}` | decisions by filter (newest first; `limit`, `reviewer`): filter, action, reviewer, `via`, `expected_total`, `matched`, `applied`, `cascaded`, `applied_at`, `undone_at`, `undone_by`, `restored` |
| `GET /hits/{id}` | the hit with its rule, object, fields (comments, samples), presence, other hits, `allowed_actions` |
| `POST /hits/{id}/review` | `{"action": "confirm" \| "reject" \| "request_info" \| "reopen", "category", "severity", "note"}` |
| `POST /hits/review_bulk` | the same on many hits, note required, `dry_run` |
| `PATCH /hits/{id}`, `PUT /hits/{id}` | category / severity / note |
| `POST /hits/{id}/request_human` | the harness model asks a human (`question`) |
| `GET /hits/{id}/history` | verdict history; rows written by a decision by filter (or its undo, `source: undo`) carry `batch_id` |
| **Rules** | |
| `GET/POST /keyword_rules`, `GET/PUT/DELETE /keyword_rules/{id}` | keyword rules (soft delete) |
| `GET/POST /llm_rules`, `GET/PUT/DELETE /llm_rules/{id}` | LLM rules; `PUT ...?candidate=true` makes a candidate version instead of activating |
| `POST /rules/dry_run`, `GET /rules/stats` | dry run of a rule; precision per version |
| `GET /rules?q=&kind=&limit=` | autocomplete: live rules of any kind by name substring (`[{id, name, kind, category, severity, mode, target, enabled, version}]`, prefix matches first) |
| `GET /categories`, `GET /object_types` | autocompletes: `{items: [{category, rules, hits, matches}]}` / `{items: [{type, n}]}` with `computed_at`, `snapshot` (from the snapshots when fresh, else cached 5 min) |
| `GET /groups?q=&depth=2&parent=` | GitLab groups = path prefixes of the projects: `{items: [{path, depth, projects, parent}], depth}` |
| `POST /llm_rules/run`, `POST /llm_rules/{id}/run` | run LLM rules: `{"rule_ids", "project_ids", "mrs", "executor": "service" \| "external"}` |
| `GET /llm_rules/{id}/errors` | last errors of a rule's runs and refused harness answers |
| `GET /llm_rules/{id}/mislabeled` | disagreements with the service model (`source=human` \| `verification`) |
| `GET/POST /llm_rules/{id}/trials`, `GET /prompt_trials/{id}` | prompt trials |
| `GET/POST /llm_rules/{id}/proposals`, `GET /prompt_proposals[/{id}]`, `GET /prompt_proposals/{id}/reask`, `POST /prompt_proposals/{id}/accept \| reject` | prompt proposals; accept takes `activate` |
| `GET/POST /llm_rules/{id}/versions`, `GET /llm_rule_versions/{id}[/estimate]`, `POST /llm_rule_versions/{id}/activate \| rollback \| discard` | rule versions |
| `GET /llm_rollouts[/{id}]`, `POST /llm_rollouts/{id}/start \| pause \| resume \| cancel` | rule rollouts |
| `GET /llm_quality` | service / harness agreement per rule |
| **LLM runs and harness work** | |
| `GET /llm_runs` | active and recent LLM runs |
| `GET /llm_progress` | LLM coverage |
| `GET /llm_work/jobs`, `GET /llm_work/stats` | external runs and verify jobs; harness work summary |
| `POST /llm_work/claim`, `POST /llm_work/submit`, `POST /llm_work/release`, `POST /llm_work/take_over` | the external executor and the verify items (`purpose`) |
| **Projects and MRs** | |
| `GET /projects` | tracked projects (filters `q`, `id`, `scan_mode`, `group`, `source`, `severity`, `tag`; sort `full_path` \| `id` \| `pending_hits` \| `scan_mode`) with `group_path`, `pending_hits` (open live hits), `scan` (parse state, MRs), `llm` (coverage) |
| `GET /projects/{id}` | the project page: the list row plus `description`, `default_branch`, `visibility`, `severity`, `tags`, `hits_by_rule` (`[{rule_id, rule_name, kind, category, match, no_match, open, questions}]`, live hits), `objects_by_type` (main), `objects_in_open_mrs`, `open_mrs`, `jobs` (last 20); `detail=false` for the row only |
| `PATCH /projects/{id}`, `PUT /projects/{id}` | `{"scan_mode": "rules" \| "inventory"}` |
| `POST /projects/parse`, `POST /projects/{id}/parse` | clone and parse again (`project_ids`, `parsers`, `mains`, `mrs`, `llm`, `force`) |
| `GET /scan_progress` | parse scan states |
| `GET /mrs`, `GET /mrs/{id}`, `POST /mrs/{id}/scan` | open MRs, one MR with its delta and hits, a scan on demand |
| **Objects** | |
| `GET /objects`, `GET /objects/{key}` | the inventory (filters as MCP `list_objects`), one object with fields and hits |
| `POST /objects/{key}/labels`, `DELETE /objects/{key}/labels`, `POST /objects/labels` | manual labels, bulk labels |
| `GET /overview` | matches and objects by type / project for a category, tag, rule or severity; `computed_at`, `snapshot` (see above) |
| **Ingest and tokens** | |
| `POST /ingest`, `GET /ingest` | push an external parser state; list batches |
| `POST /ingest/sessions`, `PUT /ingest/sessions/{id}/chunks/{seq}`, `POST /ingest/sessions/{id}/commit`, `DELETE /ingest/sessions/{id}` | chunked upload |
| `POST /tokens`, `GET /tokens`, `DELETE /tokens/{id}` | service tokens (admin only): `{"name", "scopes": ["ingest" and/or "mcp"], "project_prefixes"}` - `ingest` needs prefixes under `external/`; `mcp` tokens act as the reviewer `token:<name>` on REST and MCP |
| **Jobs** | |
| `GET /jobs`, `GET /jobs/{id}` | the queue with `progress`, `subject`, `last_error`; filters `id`, `kind`, `status`, `q`, `project_id` (the jobs of one project) |
| `GET /jobs/stats`, `GET /jobs/health`, `GET /jobs/errors` | counts; queue health (`typical_run_s` / `typical_wait_s` from `jobs.started_at`, `eta_s` from the last hour's rate or the typical run time x backlog / busy workers; snapshot, ETag); failures grouped by cause |
| `POST /jobs/{id}/retry`, `POST /jobs/{id}/cancel` | retry a failed job, cancel a pending one |
| `/mcp` | the [MCP server](mcp.md) |

Request bodies are validated (`discovery_api/schemas.py`); rule bodies: `KeywordRuleIn` (`name`, `category`,
`severity`, `mode`, `enabled`, `action`, `project_re`, `parser`, `object_re`, `object_type_re`, `field_re`,
`field_type_re`, `fields_all`, `fields_none`, `min_groups`, `tags`) and `LlmRuleIn` (`name`, `category`,
`severity`, `mode`, `enabled`, `target`, `prompt`, `project_re`, `object_re`, `object_type_re`, `field_re`,
`field_type_re`, `mark_fields`, `tags`). Hit ids are `"<rule_id>:<subject_key>"`.
