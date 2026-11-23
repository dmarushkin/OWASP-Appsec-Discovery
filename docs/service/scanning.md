---
hide:
  - footer
---

# Scanning and change detection

The scanner polls GitLab; there are no webhooks. Everything it does is a job of the Postgres queue (see
[Jobs and workers](jobs.md)).

```
scheduler -> sync_projects (every PROJECTS_POLL_INTERVAL_S, a full sync first after start-up)
          -> sync_branches_mrs      per new / changed project
               -> scan_branch       main branch with a new commit            (GITLAB_SCAN_TYPES mains)
                    -> llm_score    after a successful main scan (LLM_API_URL set; not after a diff-based skip)
                         -> llm_verify   verify items for the harness model
               -> scan_mr           open MR with activity in the last day    (GITLAB_SCAN_TYPES mrs)
scheduler -> cleanup (every GC_INTERVAL_HOURS), llm_coverage (every LLM_COVERAGE_INTERVAL_S),
             llm_rollout (every LLM_ROLLOUT_TICK_S)
```

## Projects and branches

`sync_projects` lists the projects of every `GITLAB_PROJECTS_PREFIX` (matched on path segments: `grp/` is the
group, `grp/proj` that project only, `grp/proj*` a plain string prefix) and queues `sync_branches_mrs` for the
projects whose GitLab activity (`last_activity_at`) is newer than what was processed, and for the ones not re-read
for `SYNC_UNCHANGED_EVERY_H` (24 h: stale MRs are released and deleted branches noticed even without activity; the
full sync after start-up follows the same rule, every project only with the setting at 0). That job reads the
project, its open MRs (one page of 100), the default branch (the project's **main**) and the branches of the
non-stale open MRs **by name** - not every branch of the repository, which cost a page of 20 per call - and the
states of the MRs that left the open list in one batched call per 100 (`iids[]`); it tracks the MR source branches
and queues the scans. The sync runs on its own worker pool (`SYNC_WORKERS`), so the harness verify items, external
answers and rollouts of the control pool never wait behind it. Projects of a prefix removed from the configuration
stay in the database until deleted.

**Main branch**: `scan_branch` clones the branch at its head commit into a temporary workspace of the job, runs the
parsers of `PARSERS` (when `SCAN_LANGS` lists the project's language, or is `all`), applies the keyword rules of
the project and saves the **snapshot** in one transaction: objects and fields (content-addressed, see
[Data model](data-model.md)), the diff to the previous snapshot, keyword hits, `scanned_commit`, the deltas of
MRs now merged. When `LLM_API_URL` is set an `llm_score` job follows with every enabled LLM rule. Dedup keys
contain the commit, so a commit pushed while a scan runs is queued as a new job.

**Merge requests**: `scan_mr` makes sure the target's snapshot is current (scans the target main first if needed),
scans the source branch and stores only the **delta** against the target - objects added, modified or removed by
the MR (`branch_objects.change`) - then runs the LLM rules on the delta. MRs are scanned automatically only when
they were updated in the last day; `POST /mrs/{id}/scan` / MCP `scan_mr` scans one at any time. Hits on MR
objects are reviewed like any other (presence "Only in open MRs"); the MR itself is reached through
`GET /mrs`, `GET /mrs/{id}` and MCP `list_mrs` / `get_mr`. Closed / merged MRs lose their tracked source branch
and delta, stale open ones (`MR_STALE_DAYS`) likewise.

**Hits are branch-agnostic**: one hit per rule and subject, whatever branch the subject is in; a decision made on
the MR version of an object holds for the main version.

## Re-parsing on demand

`POST /projects/parse` (MCP `parse_projects`, UI Projects page "Parse"): `{"project_ids": [1, 5], "parsers":
["protobuf"], "mains": true, "mrs": true, "llm": false, "force": false}` clones and parses projects again, e.g.
after a keyword rule edit. Without `project_ids` every project; with `parsers` only those run and only their
objects are replaced (the other parsers' objects are kept). LLM rules are off by default. A keyword rule edit also
makes the branches rescan once by itself (scan markers carry the rules' versions).

## Scan modes

`PATCH /projects/{id}` `{"scan_mode": "inventory"}` (MCP `set_scan_mode`, UI Projects page): an **inventory**
project is parsed without categorisation - no keyword or LLM rules - and labelled by hand
([Rules: manual labels](rules.md#manual-labels-and-inventory-mode)). The default mode is `rules`.

## Diff-based scan skip

Every new commit of a main branch used to mean a full clone and every parser, although most commits touch no file a
parser reads. Before cloning, the scanner asks the GitLab compare API (polling, no webhooks) which files changed since
the commit its snapshot reflects (`gitlab_branches.scanned_commit`) and checks them against the files each parser
declares it reads (core `Parser.file_patterns`: `*.proto`; `*.graphql` / `*.gql`; `*.js` / `*.jsx` / `*.ts` / `*.tsx` /
`*.mjs` / `*.cjs`; `*.sql`; `*.go`; `*.java`; `*.py` / `*.pyi`; `*.yaml` / `*.yml` / `*.json`; `*.tf` / `*.tf.json`;
`appsec_discovery.affected_parsers`). When no changed file is read by a parser of the scan, the snapshot is moved to the
new commit (`scanned_commit`, a scan marker and the LLM coverage rows; objects, hits and verdicts untouched, no LLM run)
and the job ends in seconds with `progress = {"phase": "skipped", "skipped": "no parser files changed",
"changed_files": N}`.

A full scan happens anyway (the clone phase records why in `progress.full_scan_reason`) when:

* the snapshot is missing, or was made with another scan configuration (`gitlab_branches.scan_fingerprint`: core
  package version, parsers, keyword rules, scan mode; stored with every full scan, so an upgrade or a rule edit rescans
  every branch once);
* the last full scan is older than `SCAN_FULL_RESCAN_DAYS` (default 7; `0` = never on time alone);
* the scanned commit is not an ancestor of the new one (force push / rebase, GitLab merge base API);
* the compare is truncated (`compare_timeout`, or `SCAN_DIFF_MAX_FILES` files or more, default 1000);
* a changed file matches `SCAN_ALWAYS_RESCAN_GLOBS` (comma separated globs, default empty; a pattern with `/` matches
  the repository path, one without matches the file name); `go.mod` / `package.json` count while the `SCAN_LANGS` gate
  is on, because the language detection reads them;
* the compare API fails for any reason (logged with the cause, credentials stripped; the shortcut never fails a job).

Merge requests (`SCAN_DIFF_SKIP_MRS`, default `true`): the stored delta is kept only when neither the source (since the
scanned source commit) nor the target (since the target commit the delta was computed against,
`gitlab_branches.delta_target_commit`) moved in parser files; the same fingerprint / age / ancestry rules apply to the
source branch. A full MR scan takes the files the MR changes from the compare of the merge base (the same set as
`git diff --name-only <merge-base> HEAD`, both paths of a rename) and clones the source shallow; the git diff in a
history clone stays the fallback when that compare is truncated or fails. A main target behind its snapshot is moved
the same way instead of being cloned and scanned for the MR.

Visibility: the Jobs page shows `skipped: no parser files changed (N files)` or `full scan: <reason>`;
`GET /scan_progress` counts a skipped branch as `scanned_current` (its snapshot is at the head commit); `GET /jobs/health`
(MCP `job_health`) adds `skipped_24h` per kind and `scans` (`scan_branch` / `scan_mr`: `full` vs `skipped` in the last
24 hours), shown on the Pipeline health page (Parse tile "24 h: X full, Y skipped scans", queue table "Done 1h / 24h
(N skipped)"). No `llm_score` job follows a skipped scan.

Settings (scanner): `SCAN_DIFF_SKIP=true` (`false` restores the previous behaviour exactly: every commit cloned and
parsed, MR sources cloned with history), `SCAN_DIFF_SKIP_MRS=true`, `SCAN_FULL_RESCAN_DAYS=7`,
`SCAN_DIFF_MAX_FILES=1000`, `SCAN_ALWAYS_RESCAN_GLOBS=`. Migration `0029_diff_skip` adds the branch columns; existing
branches are fully scanned once at their next commit and skipped from then on. Core 1.1.0 adds `Parser.file_patterns`
and `appsec_discovery.affected_parsers` / `parser_file_patterns`.

## Disk space of clones

Every scan job clones into its own directory under `WORKSPACE_DIR` and removes it when the job ends, success or not;
a worker that died leaves its directory behind, and the supervisor removes it (at once, and all of them at start-up).
Clones do not pile up: the disk holds at most the clones of the running scan jobs (`MAX_WORKERS`, an MR scan holds
the source and the target). Main branches and MR targets are cloned with `--depth 1`; an MR source whose changed files
the compare API could not give keeps its history as a partial clone (`--filter=blob:none`: all commits and trees,
the file contents of the checkout only; `GIT_PARTIAL_CLONE=false` clones the full history).

Guards before a clone:

* `WORKSPACE_MIN_FREE_GB=5`: no clone starts while the file system of the workspace has less free space. The job
  fails with `not enough disk space for a clone: N GB free in the workspace` and is retried with backoff; the cause is
  one row of "Needs attention" on the Pipeline health page. `0` disables the check. A clone that fills the disk anyway
  fails with `no space left on device` (transient) and its partial checkout is removed at once.
* `SCAN_MAX_REPO_MB=0`: a repository GitLab reports larger (`statistics.repository_size`, the whole history, so a
  shallow clone is smaller) is not cloned: the job fails at once with `repository too large: N MB` (permanent). `0`:
  no limit. Without Reporter access GitLab gives no statistics and the limit does not apply.

In the bundled compose the workspace is the volume `scan_workspace` mounted at `/workspace` (`WORKSPACE_DIR`). It is
on the Docker disk, next to the Postgres volume: the free-space guard keeps clones from taking the last
`WORKSPACE_MIN_FREE_GB` of it. To keep clones off the database disk entirely, set `SCAN_WORKSPACE_VOLUME` to a host
directory on another disk (`SCAN_WORKSPACE_VOLUME=/mnt/scans`).

## Progress of parse scans

`GET /scan_progress` (MCP `scan_progress`; computed from the database, no GitLab calls) reports, for the tracked
GitLab projects (`source = gitlab`; external `POST /ingest` projects are counted apart under `external`):

* `main`: how many projects are `synced` (branches and MRs re-read for their latest activity; `sync_queued` /
  `sync_running`) and the state of each main branch, exactly one of `scanned_current` (snapshot at the head
  commit, a diff-based skip included), `outdated` (snapshot of an older commit), `never_scanned`, `partial` (a
  parser failed at the head commit, retried), `failed` (the last `scan_branch` job used up its attempts),
  `skipped` (the last scan job of the head commit saved nothing: `SCAN_LANGS` gate) and `no_main`; `queued` /
  `running` / `retrying` count the main branches with a `scan_branch` job pending / running / pending after a
  failed attempt; the same by scan mode (`by_scan_mode`: `rules`, `inventory`).
* `mrs`: open MRs: `scanned_current` (delta at the MR's source commit), `outdated`, `never_scanned`, `partial`,
  `failed`, `not_tracked` (no tracked branches, or another open MR of the source branch owns the delta),
  `queued`, `running`.
* `queue`: active jobs by kind; the last `sync_projects` job.
* `projects`: the projects, problems first (`?status=failed,partial` or `queued`, `running`, `active`,
  `attention`, `not_synced`, any state; `scan_mode`, `q`, `project_id=1,5`, `limit` up to 500, `offset`;
  `projects=false` for totals only) with commit / scanned commit, last scan, job, last error and open MR counts.

The Pipeline health page shows it as "Parse" (bars, counts, projects that failed or wait), the Projects page as the
"Parse" column. `scan_branch` jobs carry their phase in `progress`: `waiting` -> `clone` -> `parse` -> `save`
(with `objects`, `by_parser`, `failed_parsers`) -> `done` | `skipped` | `partial` | `failed`.
