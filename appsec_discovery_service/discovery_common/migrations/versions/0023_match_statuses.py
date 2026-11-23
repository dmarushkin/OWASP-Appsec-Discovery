"""Hit statuses are the verdict words: ``confirmed`` -> ``match``, ``rejected`` -> ``no_match``
(``pending_review`` / ``need_more_info`` stay). Who decided is ``decided_tier`` (service | harness | human), not the
status; the reviewer actions (confirm / reject / request_info / reopen) keep their names.

Every place that stores a hit status is rewritten:

* ``rule_hits.status`` (and its CHECK ``rule_hits_status_check``) and ``rule_hits.machine_status``;
* ``rule_hits.verify_key`` (``<rule version>:<prompts>:<subject hash>:<status>``): the status suffix, so a verdict
  already sent to the harness model is not sent again;
* ``llm_verifications.service_status`` (``service_verdict`` / ``verdict`` hold verdict words already: untouched);
* ``prompt_trial_items.current_status`` (``expected`` / ``*_verdict`` are verdict words: untouched);
* ``llm_work_items.verify ->> 'service_status'`` (open and answered verify items: the harness answer is applied
  only while the hit still has that status).

The partial indexes on ``rule_hits`` (``hits_queue``: pending_review / need_more_info, ``hits_model_questions``:
need_more_info) do not name the renamed statuses: unchanged. The QA sample draw of the verify job hashes the
verdict key, so the confident service verdicts not yet sampled get a new draw once.

The downgrade reverses all of it (``match`` -> ``confirmed``, ``no_match`` -> ``rejected``).

Revision ID: 0023_match_statuses
Revises: 0022_no_alerts
Create Date: 2026-11-22
"""
from alembic import op

revision = "0023_match_statuses"
down_revision = "0022_no_alerts"
branch_labels = None
depends_on = None

NEW_STATUSES = {"confirmed": "match", "rejected": "no_match"}
OPEN = ("pending_review", "need_more_info")
COLUMNS = (("rule_hits", "status"), ("rule_hits", "machine_status"), ("llm_verifications", "service_status"),
           ("prompt_trial_items", "current_status"))


def _rename(mapping: dict) -> None:
    cases = " ".join(f"WHEN '{old}' THEN '{new}'" for old, new in mapping.items())
    olds = ", ".join(f"'{old}'" for old in mapping)
    op.execute("ALTER TABLE rule_hits DROP CONSTRAINT IF EXISTS rule_hits_status_check")
    for table, column in COLUMNS:
        op.execute(f"UPDATE {table} SET {column} = CASE {column} {cases} END WHERE {column} IN ({olds})")
    for old, new in mapping.items():
        # chr(58) = ':' (a literal colon would be read as a bind parameter)
        op.execute(f"UPDATE rule_hits SET verify_key = left(verify_key, length(verify_key) - {len(old)}) || '{new}' "
                   f"WHERE right(verify_key, {len(old) + 1}) = chr(58) || '{old}'")
    op.execute(f"UPDATE llm_work_items SET verify = jsonb_set(verify, '{{service_status}}', to_jsonb(CASE "
               f"verify ->> 'service_status' {cases} END)) "
               f"WHERE purpose = 'verify' AND verify ->> 'service_status' IN ({olds})")
    statuses = ", ".join(f"'{s}'" for s in (*OPEN, *mapping.values()))
    op.execute(f"ALTER TABLE rule_hits ADD CONSTRAINT rule_hits_status_check CHECK (status IN ({statuses}))")


def upgrade() -> None:
    _rename(NEW_STATUSES)


def downgrade() -> None:
    _rename({new: old for old, new in NEW_STATUSES.items()})
