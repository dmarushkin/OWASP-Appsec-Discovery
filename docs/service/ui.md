---
hide:
  - footer
---

# UI

`http://<host>/`, login with `UI_ADMIN_EMAIL` and the password of `UI_ADMIN_PASSWORD_HASH` (one user; decisions
are recorded under it). The UI calls the REST API under `/api`.

## Roles

The app bar has a switch **View as: Admin | Datasec**. The role orders the menu and picks the home page; it is
remembered per browser (the stored choice of the old name "Engineer" is read as Datasec) and every page stays
reachable in both roles (the other role's pages sit in a collapsed section at the end of the menu).

| role | who | home | menu |
|---|---|---|---|
| **Admin** | keeps the pipeline going: scans, LLM runs, harness work | **Pipeline health** | Pipeline: Pipeline health, Jobs, Groups, Projects, Ingest batches, Harness work; Settings: Service tokens; collapsed: Review & rules |
| **Datasec** | writes rules, reviews hits, improves prompts | **Work desk** | Work: Work desk, Review; Rules: LLM rules, Keyword rules; Landscape: Landscape, Objects, Groups, Projects; Harness: Harness work; collapsed: Pipeline & settings |

## Scope: a GitLab group

The app bar has **Scope: [group]** (autocomplete over `GET /groups`): a prefix of the projects' `full_path`
(`grp/payments` means `grp/payments/ledger-svc` and everything below, not `grp/payments-old`). It is kept in the URL
(`?scope=grp/payments`, so a link carries it; a link with another scope wins over the remembered one) and per
browser. Every hits / objects / projects list and every count, cluster and decision of the Review page, the Work
desk, the Pipeline "Human" tile, the Landscape "By group" panel and the Group view sends it as `group=`; the page
titles name it ("Review · grp/payments"). Jobs have no group filter (the project filter instead).

## At scale

* **Totals are estimates** above 10 000 rows: the Review, Objects and Projects lists say "about N rows (estimate)"
  with an **exact count** action (one `count(*)` on click, never per page; `X-Total-Estimate`).
* **Keyset paging**: paging forward continues from the previous page's cursor (`X-Next-Cursor` / `after=`), so a
  deep page costs one index probe; a jump to a far page without a cursor falls back to the offset.
* **One queue definition** (`choices.js` `QUEUES`): the Review tabs, the Review menu badge, the Work desk tiles,
  the Pipeline "Human" tile and the Group view count the same sets (questions / pending / model unsure: live hits
  without the field marks of object rules) from one `GET /hits/aggregate?by=queue` each, served from the scanner's
  statistics snapshot. Counts reload two seconds after a decision, not on every page of the list.
* **Snapshots**: the Pipeline health, Work desk and the autocompletes read the statistics snapshots (`ETag`, `304`)
  and say "updated N s ago" (or "live" when the snapshot was stale and the API computed). Polling waits for the
  previous answer, runs four times slower in a hidden tab and backs off after errors.
* **No silent truncation**: wherever the API caps a list or an aggregate the page says "N of M shown" / "top N" /
  "first 200 of N" (Landscape top 200 projects, Parse / Run rules next actions, Retry of the first 50 ids, cluster
  pages, aggregate rows, rule runs).
* **Server-side autocompletes**: rules (`GET /rules?q=`, both kinds), categories (`GET /categories`), object types
  (`GET /object_types`), groups (`GET /groups?q=`) instead of loading 500 rules or the whole overview per dropdown.

## Pages

| page | what it shows |
|---|---|
| **Pipeline health** (`/pipeline`) | is the pipeline GitLab sync -> Parse -> Service model -> Harness model -> Human keeping up: a tile per stage with the backlog, the oldest waiting age and the hourly rate (Parse: full vs skipped scans in 24 h; Harness: today's escalations against the daily cap `LLM_ESCALATION_DAILY_MAX` and the overflow kept service-decided; Human: questions, pending, unsure from the queues aggregate); Job queue (per kind: waiting / running / failed, done 1h / 24h with skipped counts, oldest waiting coloured against the kind's typical wait, typical run / wait, throughput and ETA; idle kinds collapsed), Workers with the pools and limits (`scan` / `sync` / `control` / `llm` workers, LLM concurrency, rate limit tokens left), Failures (24 h) grouped by cause, Parse details, LLM coverage, Rule runs, Rollouts. Next actions say their reach ("Parse first 200 of 1 480 behind"). Sources: the snapshots `/jobs/health`, `/scan_progress`, `/llm_progress`, `/llm_quality` (ETag, "updated N s ago"), `/llm_work/stats`, `/llm_runs`, `/llm_rollouts`, `/jobs/errors`, `/hits/aggregate` |
| **Work desk** (`/workdesk`) | what waits for me: Questions (from the harness model), Clusters to decide, Pending review, Model unsure (the same numbers as the Review tabs), open Proposals, Rules (health); the top 10 clusters (same schema across services) with "Decide"; Open hits by rule (questions / pending / unsure per rule, from the aggregate); New in 24 h; Rule health with a search box and "only rules that need attention"; Coverage of the LLM rules |
| **Review** (`/hits`) | tabs Questions / To decide / Pending / Model unsure / Verified by harness / All, counted by one `GET /hits/aggregate`; two views: **Clusters** (default for the open queues): the open hits grouped by *Same schema*, *Same field*, *Same object name* or *Rule x group x type* (`GET /hits/clusters`) with open count, projects, groups, in-main share, new in 7 days, questions inside, severity; a row opens the cluster panel (5 sample hits with the evidence panel, keys `j` / `k`, `c` / `r` / `i` decide the cluster, `l` opens it as a list, `Esc`); **Decide** opens the decision dialog: a note (required), the dry run (`POST /hits/decide`: how many change, what is kept - human and harness decisions, the model's questions, status transitions - by project, a sample), **Apply to N** sends the dry run's figure as `expected_total` (the server refuses when the set changed and the dry run runs again), then a toast "Batch #id ... Undo" for a minute and the "Recent decisions by filter" section (`GET /review_batches`) with Undo per batch. **List** (the Questions tab, "Verified by harness", a cluster opened as a list, or the toggle): the triage view - the list with an evidence panel (object, fields with comments and samples, the model's reason and verifier, presence in branches / MRs, other hits, history with batch ids), shortcuts `j` / `k`, `c` / `r` / `i` / `u`, `x`, `o`, `?`, bulk decisions on selected hits (at most 50) and **Decide all** on everything the current filter matches (server side, dry run, undo). Filters: project, object / field text, rule (server search), category, severity, rule kind, object type, decided by, stale, reviewed after, first seen after, presence, field marks. Hit rows, the cluster samples, the verdict card and the hit page carry the presence chip **In main** / **Only in open MR** (with the `MR !iid` chips) / **Gone**. The hit page has tabs Evidence and History (batch ids and undo rows) |
| **LLM rules** (`/llm_rules`) | list with Run / Run selected (dialog: all or selected projects, also open MRs, Service model or Harness model via MCP); the rule page ("Rule studio") with tabs Definition, Versions, Health & quality, Mislabelled, Trials, Proposals, Runs (progress bars, last errors) |
| **Keyword rules** (`/keyword_rules`) | list that says in words what a rule matches; the form: What / Scope / Behaviour / Field combination, a dry run, "Count objects in scope", statistics |
| **Objects** (`/objects`) | the inventory with filters (object type from `GET /object_types`), a **Where** column (In main / Only in open MR / Gone) and estimated totals; an object page with its fields, comments, samples, hits (with their presence) and a link to the project page; manual labels on an object or a field (categories from `GET /categories`) |
| **Landscape** (`/landscape`) | where in the landscape the data of a category / tag / rule lives (`GET /overview`): matches, objects by type, by GitLab group (`GET /hits/aggregate?by=group`, honours the scope), by project (the top 200 by matches - said so; CSV of the same rows), "Copy MCP query" |
| **Groups** (`/groups?path=`) | a GitLab group: sub-groups with their project counts and open hits, the group's queues (questions / pending / unsure / open) with links into Review, "Use as scope", and the projects of the group (open hits, parse, MRs, LLM coverage, criticality) sorted by open hits |
| **Projects** (`/projects`) | one row per project: group (link to the Group view), open hits, Parse state, MRs, LLM rules coverage, criticality, scan mode (rules / inventory); filters project text, group, scan mode, criticality, tag, source; Parse / Parse selected / Parse all (only some parsers optional). A row opens the **project page** (`/projects/:id/show`, `GET /projects/{id}`): tiles Parse, LLM rules, Open hits, Open MRs (objects only in open MRs - MRs are markers, not a page), Objects (main); Hits by rule (match / no match / open / questions, every figure a link into Review), Objects by type, the last 20 jobs with a link to the Jobs page filtered to the project; Review hits / Objects / Jobs / Parse actions. Every project link in the UI (hits, objects, jobs, Landscape, Parse details, LLM coverage) opens this page |
| **Jobs** (`/jobs`) | the queue with tabs Active / Failed 24 h / All; filters error text, kind, **project**, status; the subject's project links to the project page; a job page with progress, the subject, the real failure cause, Retry (failed) and Cancel (pending); run times from `started_at` |
| **Harness work** (`/harness`) | the harnesses connected over MCP (answers in the last hour, leases, "gone?" when a claimed item has had no answer for an hour), checks queued for the harness model, external runs with Take over / Release to service, pending service runs, refused answers, MCP snippets to copy (the connect snippet takes a per-harness token with scope `mcp`) |
| **Ingest batches** (`/ingest`) | the states pushed by external collectors (`POST /ingest`), their status and jobs |
| **Service tokens** (`/tokens`) | admin only: tokens for collectors (scope `ingest` on project prefixes under `external/`) and for harnesses / agents (scope `mcp`: the client acts as `token:<name>` on REST and MCP, with its own rate limit, revocable on its own); created once, shown once with the MCP connect command for `mcp` tokens, revoked by delete; "Last used" links to the token's batches or decisions |

There is no merge requests page: an MR is a marker on a hit or an object (**Only in open MR** = the code is not in
a main branch yet), a row "Only in open MRs" on the project page and in Landscape, and the filter presence "Only in
open MRs" in Objects and Review. MR data is reached through `GET /mrs`, `GET /mrs/{id}`, `POST /mrs/{id}/scan` and
the MCP tools `list_mrs` / `get_mr` / `scan_mr`. There are no alerts: the service never posts to GitLab or
messengers.

The words of the UI (statuses, tiers, modes, actions, queues, presence) are one glossary (`discovery_ui/src/choices.js`):
hit statuses Pending review / Needs more info / Match / No match; decided by Service model / Harness model / Human;
actions Mark as match / Mark as no match / Ask for more info / Reopen; queues Questions / Pending / Model unsure;
presence In main / Only in open MR / Gone.
