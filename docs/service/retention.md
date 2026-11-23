---
hide:
  - footer
---

# Retention

The `cleanup` job (control worker, every `GC_INTERVAL_HOURS`, default 24; 0 disables it; guarded by an advisory
lock so only one process collects) deletes in batches of `GC_BATCH_SIZE` (5000):

| what | when | setting (default) |
|---|---|---|
| closed / merged MR rows | `closed_at` older than | `MR_ROW_RETENTION_DAYS` (7) |
| the tracked source branch of an open MR without activity (and its delta) | not updated for | `MR_STALE_DAYS` (30) |
| untracked branches, orphan object versions (no branch has them; collected in one anti-join pass, deleted by key in batches) | at once | - |
| scan markers of a branch | beyond the newest N | `SCANS_KEEP_PER_BRANCH` (20) |
| `pending_review` hits whose subject is in no branch (`in_main` and `in_open_mr` false, see [presence](data-model.md#presence-of-a-hit-in_main-in_open_mr)) | older than | `HITS_PENDING_ORPHAN_DAYS` (14) |
| `match` / `need_more_info` hits in no branch | last seen older than | `HITS_DECIDED_UNSEEN_DAYS` (180) |
| `no_match` hits in no branch | last seen older than | `HITS_REJECTED_UNSEEN_DAYS` (365; the name predates the status rename) |
| finished jobs (done / failed) | older than | `JOBS_RETENTION_DAYS` (7); the newest job of every kind is kept for the scheduler |
| external work / verify items: open ones expire, finished ones are deleted | older than | 7 days (`llm_work.RETENTION_DAYS`) |
| verdict history rows (`hit_verdicts`) | older than; the last row of every version of a subject is kept | `HIT_HISTORY_DAYS` (180) |
| harness verifications (`llm_verifications`; the QA metrics read the last 30 days) | older than; 0 keeps them | `LLM_VERIFICATIONS_RETENTION_DAYS` (365) |
| finished prompt trials with their items (a trial a proposal refers to is kept) | older than; 0 keeps them | `PROMPT_TRIALS_RETENTION_DAYS` (90) |
| ingest upload sessions left open | after | 24 hours |

Decisions on objects that disappear from the code are therefore kept for the retention above and come back with
the object when it reappears (same `object_key`). The hit retention reads the partial index `hits_seen`
(`COALESCE(last_seen_at, first_seen_at)`, status; hits in no branch only), so a batch costs milliseconds whatever the
table size. The cleanup logs table statistics afterwards (`GET /health/db`).
