---
hide:
  - footer
---

# Rules and hits in the service

Rules live in the `rules` table and are edited in the UI (Keyword rules, LLM rules), over REST
(`/api/keyword_rules`, `/api/llm_rules`) and over MCP (`create_rule`, `update_rule`, `get_rule`, `list_rules`,
`delete_rule`). Rule edits apply on the next scan of each project; keyword rule edits make the branches rescan
once by themselves, LLM rule runs are started by hand or after scans. Hits and their statuses are described in
[Objects, hits and scoring](../scoring.md).

Every rule has `name`, `category`, `severity` (`critical` .. `info`), `mode`, `enabled`, `tags` (object tags once a
hit is a `match`) and a **scope**: `project_re`, `parser` (exact), `object_re`, `object_type_re`, `field_re`,
`field_type_re` - patterns matched from the start of the value (regex) or as a case-insensitive substring.

**Modes**: `auto` - hits are a `match` at once (and stay in the harness model's QA sample); `review` - every hit
waits in the review queue as `pending_review`. New rules default to `auto` and enabled, in the UI, REST and MCP
alike; pass `mode: review` / `enabled: false` to stage one. An update without `mode` keeps the rule's mode.

Deleting a rule is a soft delete (`deleted_at`, `enabled = false`): hits keep their rule.

## Keyword rules (`kind = keyword`)

Besides the scope: `action` (`score` | `exclude` - exclude rules suppress every hit on the matching subjects and
produce none) and field combinations `fields_all` (groups of regexes searched in the field names, at most 20),
`fields_none`, `min_groups`. A rule with `field_re` / `field_type_re` / `fields_all` hits fields (a combination:
the object, listing the fields), otherwise the object. They are mapped to the core's `score_rules` and evaluated by
the scan itself.

Built-in keyword rules (`scope.source = core`, migration `0028_builtin_rules`): **`kw-fields`** (the `score_tags`
keywords in field names) and **`kw-props`** (in the object's properties) - **disabled on a new install**; enable
them, switch their mode or set tags in the UI (nothing else of them is editable). Disabled, the core records no
`score_tags` hit.

`POST /rules/dry_run` (MCP `dry_run_rule`): what a keyword rule would hit on the stored main snapshots, with how
many of those subjects people already set to `match` / `no_match`, without writing anything; for an LLM rule the
number of model calls a run would make. `GET /rules/stats` (MCP `rule_stats`): per rule and version, the precision
of human decisions and the top reject notes.

## LLM rules (`kind = llm`)

Besides the scope: `target` (`field` | `object`), `prompt` (the system prompt, up to 20000 characters),
`mark_fields` (object rules: the fields the model names get hits too). An LLM field rule without `category` is
the built-in classifier (pii / finance / auth / other). How field and object rules work, what the model sees and
`mark_fields` are described in [LLM scoring in the CLI](../cli/llm.md#3-llm_rules); the service adds versions,
re-asks and rollouts ([LLM rule lifecycle](llm-lifecycle.md)) and the tiered review ([Tiered review](tiers.md)).

LLM rules run with the **service model** (`LLM_API_URL`, `LLM_API_MODEL`):

* after every successful main scan (every enabled rule) and MR scan (on the delta), when `LLM_API_URL` is set;
* on demand: `POST /llm_rules/run` (MCP `run_score_rules`, UI "Run" on the LLM rules page): `{"rule_ids": [6, 7],
  "project_ids": [1, 5], "mrs": false}` over the stored snapshots (no clone, no parse). Only subjects without a
  current verdict are sent, so a second run costs nothing. `"executor": "external"` (UI: "Harness model (answers
  via MCP)") runs the rule with a model outside the service: [External executor](external-executor.md).

Verdicts: a positive answer is a `match` (mode `auto`) or `pending_review` (mode `review`), `need_more_info` is a
machine `need_more_info` hit in the review queue, a negative answer is a machine `no_match` hit so the subject is
not asked again. Every LLM hit stores the `model`, the model's `reason`, the rule version and the core prompt
version it was made with.

**Coverage**: `GET /llm_progress` (MCP `llm_progress`; Pipeline health "LLM coverage", the Projects page's "LLM
rules" column) says how far the LLM rules got: per main branch exactly one of `current` (every enabled rule has a
fresh row with nothing remaining), `failed` (the last `llm_score` / `llm_prepare` job of the branch failed),
`never` (a rule not counted yet), `outdated` (subjects remain or a row is stale), `not_scanned`; `queued` /
`running` / `awaiting_answers`; per rule `answered` / `total` / `remaining`, `answered_stale`, `pending_external`,
`failed`, `projects_current`; the same for open MRs; `projects` with the same filters as `/scan_progress`
(`?status=failed,never`, `incomplete`, ...). The scanner records the rows (table `llm_coverage`) after every LLM
run and snapshot save and recounts stale ones with the `llm_coverage` job; no model is called for it.

## Default rules of a new installation

Migration `0013_example_rules` seeds two LLM object rules in mode `auto` with `mark_fields` (one call per object
marks it and the fields the model names); each is skipped when a live rule already has its name:

| rule | category / severity / tags | scope | state |
|---|---|---|---|
| `db-tables-with-client-data` | `pii` / `high` / `personal-data` | `object_type_re: table` | **enabled** |
| `api-with-auth` | `auth` / `critical` / `auth-data` | `object_type_re: route|rpc|query|mutation` | **disabled** - enable it in the UI / API / MCP |

`db-tables-with-client-data` marks database tables that store personal data of natural persons and their columns;
`api-with-auth` marks API operations whose request or response carries authentication secrets (passwords, PIN /
OTP codes, access / refresh / session tokens, API keys, client secrets, private keys, CVV; not logins, ids, roles
or public keys). Their `match` verdicts score the objects at once but stay in the tiered workflow: they are part
of the harness model's QA sample, their `need_more_info` verdicts are escalated, and a harness or human decision
overrides them.

There is no env-managed LLM rule (`LLM_PROMPT` is gone): an LLM field rule without category made in the UI / REST
/ MCP is the built-in classifier.

## Tags

An object's tags are read at query time: the `tags` of the rules of its `match` hits plus the tags of manual
labels. Rule tags are edited in the UI (also on the built-in rules). `GET /objects?filter={"tag": "gdpr"}` and MCP
`list_objects(tags=[...])` filter by them; the Landscape page shows where the data of a category / tag lives.

## Manual labels and inventory mode

A project in scan mode `inventory` (`PATCH /projects/{id}` `{"scan_mode": "inventory"}`, MCP `set_scan_mode`)
is parsed without categorisation. Objects and fields are labelled by hand: UI Objects page, REST
`POST /objects/{key}/labels` / `DELETE`, `POST /objects/labels` (bulk), MCP `label` / `unlabel` / `label_bulk`.
A label is a `match` hit of the built-in `manual:labels` rule (kind `manual`) with the reviewer set, so scans
never overwrite it; it shows up in `/hits` like any decision. Labels work in `rules` mode too.

## External parser states

Objects pushed with `POST /ingest` go through the keyword rules (and the LLM rules with `llm: true`) like parsed
code: [External parsers](ingest.md).
