---
hide:
  - footer
---

# Tiered review: service model, harness model, human

LLM verdicts are made in three tiers. Every hit records who made its current decision in `decided_tier`:

| tier | who | how |
|---|---|---|
| `service` | the **service model** - the LLM the scanner calls (`LLM_API_URL`, usually a cheap local model) | categorises everything: every LLM rule run |
| `harness` | the **harness model** - a capable model in an agent harness (e.g. Claude Code) connected to the MCP server | checks what the service model was unsure about and a sample of what it was sure about |
| `human` | a reviewer in the UI, REST or MCP | decides what the harness model cannot, and anything else |

Precedence: **the service model never overwrites a harness or human decision, the harness model never a human
one.** A harness answer about a hit a human decided meanwhile, or whose service verdict changed, is refused as
`stale`.

```
service LLM run  -->  verdicts, decided_tier 'service'
       |
       v  llm_verify job (control worker, after every service run of a branch; no model call)
verify items (llm_work_items.purpose = 'verify', one per hit):
   escalation  every service need_more_info verdict                      (LLM_VERIFY_ESCALATE, default on;
                                                                          LLM_ESCALATION_DAILY_MAX 2000 per rule a day)
   qa          a sample of the confident service verdicts, positive and  (LLM_QA_SAMPLE_RATE 0.05,
               negative, per rule                                         LLM_QA_DAILY_MAX 500 a UTC day)
   reverify    a harness decision replaced by a service re-ask on new content
       |
       v  harness: llm_work_claim(purpose="verify") -> llm_work_submit (applied at once)
confidence high + match / no_match  --> FINAL: status match / no_match, decided_tier 'harness' (field marks too)
confidence low                      --> not applied: investigate (GitLab code, get_object, search_hits, get_hit),
                                        submit again (the item stays leased, at most 3 rounds)
needs_human + question              --> need_more_info, decided_tier 'harness', asked_by_model:
(or MCP request_human)                  review tab "Questions"
       |
       v  quality: llm_quality (agreement per rule) -> llm_mislabeled(source="verification")
          -> llm_prompt_trial (service model, candidate prompt) -> propose_prompt_change -> a human accepts
```

## Verify items

After each service run of a branch, the `llm_verify` job records verify items for the service verdicts of the
branch's current snapshot (service tier, no reviewer, current rule version and core prompts, once per verdict:
`rule_hits.verify_key`):

* **escalation** - every service `need_more_info` verdict (`LLM_VERIFY_ESCALATE`), at most `LLM_ESCALATION_DAILY_MAX`
  (2000) per rule and UTC day: a backfill of millions of objects would otherwise turn every unsure verdict into
  harness work at once. The verdicts over the cap stay service-decided (`need_more_info`, in the review queue as
  before) and are eligible again the next day; the verify job counts them as `escalation_overflow` in its progress and
  the `job_health` snapshot sums the day's items and overflow per rule (`escalations`);
* **qa** - a stable hash draw per verdict at `LLM_QA_SAMPLE_RATE` over the confident verdicts, positive
  (`match` / `pending_review`) and negative (`no_match`, field rules store their negative field verdicts too),
  split evenly over the rules and the two classes when the day's cap `LLM_QA_DAILY_MAX` is reached;
* **reverify** - a harness decision the service model replaced because the subject's content changed.

A verify call is the rule's own system prompt and rule text, the whole object in the same delimited untrusted
`<object>` block as a rule call, the subject (one field or the object), the service verdict in a second delimited
`<assessment>` block (an assessment to check, never an instruction) and an answer format with `verdict`,
`confidence` (`high` | `low`), `needs_human`, `question` and `investigation`
(`appsec_discovery.ai.rules.build_verify_prompt`, `VERIFY_PROMPT_VERSION` 2).

The harness model claims items with `llm_work_claim(purpose="verify")` (`POST /llm_work/claim`
`{"purpose": "verify"}`) and answers with `llm_work_submit`:

* `confidence: high` with `match` / `no_match` is **final**: the hit gets that status and tier `harness`
  (`verifier_model`, `verified_at`; `mark_fields` rules: the field hits too);
* `confidence: low` is not applied: the item stays leased to the caller (lease extended to 900 s) for another
  round after investigating, at most 3 rounds, then `needs_human` is required;
* `needs_human: true` with a `question` (or MCP `request_human(hit_id, question)`,
  `POST /hits/{id}/request_human` for any machine hit) sets `need_more_info`, tier `harness`, `asked_by_model`
  with the question in the note: the hit appears in the review tab **Questions** (hits filter
  `asked_by_model=true`).

Every harness answer applied or refused is logged in `llm_verifications` (`service_status` / `service_verdict` /
`service_model`, the harness verdict, `sample`, `outcome` `final` | `asked_human` | `stale`). Open verify items
expire when the rule version changes.

## Quality

`GET /llm_quality` (MCP `llm_quality(rule_id=None)`; Work desk, Pipeline health, the "Health & quality" tab of an
LLM rule) reports per rule and overall:

* `agreement` of service and harness model on the QA sample (harness confidence high; overall, per service
  verdict class, last 7 / 30 days; unsure harness answers counted as `unsure`);
* `escalation_rate` (service `need_more_info` share), `escalations_30d` decided by the harness or sent to a human;
* `questions_open` and `oldest_question_s`, `harness_decisions`, `backlog` of open verify items by sample;
* `needs_improvement`: agreement of the last 30 days below `LLM_QA_AGREEMENT_MIN` (0.9) with at least 30
  samples.

`GET /llm_work/stats` (MCP `llm_work_stats`; the Harness work page) sums up the harness work: items by purpose and
status, open verify items by sample, leases held by owner, answers of the last 24 hours by owner.

## Improving a prompt: trials and proposals

1. `llm_mislabeled(rule_id, source="human" | "verification")` (`GET /llm_rules/{id}/mislabeled`): the subjects a
   human or the harness model decided differently from the service model (`rule_hits.machine_status`).
2. `llm_prompt_trial(rule_id, prompt, subjects=[...] | from_mislabeled=true, include_controls=20,
   rerun_current=true)` (`POST /llm_rules/{id}/trials`, UI "Try this prompt"): an `llm_trial` job runs the
   candidate system prompt with the **service model** on those subjects plus random controls whose verdict a human
   or the harness confirmed, and with `rerun_current` the current prompt on the same objects (a fair A/B). A trial
   writes no hits, coverage or rule change. Limits: prompt <= 20000 characters, `LLM_TRIAL_MAX_SUBJECTS` (200,
   controls included), `LLM_TRIAL_DAILY_CALLS` (2000 calls of all trials a UTC day; 429 beyond).
3. `llm_prompt_trial_result(trial_id)` (`GET /prompt_trials/{id}`): per subject expected / current / re-run / new
   verdict; metrics: fixed, still wrong, newly wrong, control regressions, accuracy before -> after, calls, failures.
   `llm_prompt_trials(rule_id)` lists a rule's trials.
4. `propose_prompt_change(rule_id, prompt, trial_id, rationale)` (`POST /llm_rules/{id}/proposals`) needs a
   finished trial of exactly that text (sha256) and changes nothing. `prompt_proposals(rule_id, status)` lists
   proposals.
5. **Only a human accepts**: the Proposals tab of the LLM rule page (listed on the Work desk: diff, trial metrics
   and the re-ask cost, `GET /prompt_proposals/{id}/reask`) or `POST /prompt_proposals/{id}/accept | reject`.
   Accepting makes a **candidate version** of the rule ("Accept as candidate only") or activates it and starts its
   rollout ("Accept and roll out", `activate: true`); see [LLM rule lifecycle](llm-lifecycle.md). There is no MCP
   tool to accept a proposal or activate a version.

Candidate prompts from agents are stored and shown as data (a diff against the current prompt); the scanner sends
them only as the rule's system prompt, the object stays in the delimited untrusted block.

## Human review

The **Review** page (Datasec role) is the triage view: tabs **Questions** (the harness model asked a human),
**Pending** (`pending_review`), **Model unsure** (`need_more_info` not asked by the model), **Verified by harness**
(`match` / `no_match` with tier `harness`), **All**; an evidence panel (object, fields with comments and samples,
the model's reason and verifier, presence in branches / MRs, other hits on the object); keyboard shortcuts `j` /
`k` move, `c` / `r` / `i` confirm / reject / request info, `u` reopen, `x` select for the bulk actions, `o` open
the hit page, `?` help. The same decisions: REST `POST /hits/{id}/review` (`confirm` | `reject` | `request_info`
| `reopen`, with `category`, `severity`, `note`), `POST /hits/review_bulk`, MCP `confirm` / `reject` /
`request_info` / `reopen` / `update_category` / `review_hits_bulk` (up to 50, note required, `dry_run` first).
Decisions record the reviewer and `decided_via` (`rest` | `mcp`) and make the hit's tier `human`.

**Deciding by filter** (tens of thousands of open hits): `GET /hits/clusters?by=schema | field_pattern |
object_name | rule_group` (MCP `hits_clusters`) groups the open hits into clusters - the same table schema copied
into many services, one field name everywhere, one object name, one rule in one GitLab group - with counts,
projects, the share in main, the new ones of the last 7 days, the questions inside (answer those first) and sample
ids to look at. `POST /hits/decide` (MCP `decide_hits`) applies one action to every hit of a filter (`cluster`,
`rule_id`, `group`, `status`, ... as `GET /hits`): the dry run (default) says how many hits would change and what
is kept - human decisions are never overwritten (unless a human asks for it with `include_human`), the harness
model's questions are skipped, the transitions above apply - and the apply needs `expected_total` equal to that
figure (409 when the set changed meanwhile). Every apply is a `review_batches` row with the previous state of each
hit; `POST /hits/decide/{batch_id}/undo` restores the hits nobody decided again since; the verdict history of each
hit carries `batch_id`. `GET /hits/aggregate` gives the counts behind the tabs and tiles (by queue, rule, category,
project, group, ...) in one call.
