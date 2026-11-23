"""Quality of the service model's verdicts per LLM rule, measured by the harness model (tiered workflow,
``discovery_common.llm_verify``; ``GET /llm_quality``, MCP ``llm_quality``, Dashboard "LLM quality").

* ``agreement``: on the QA sample (confident service verdicts the harness model checked with confidence high and a
  verdict match / no_match, ``llm_verifications``), the share where both say the same; overall, per service verdict
  class (``match`` = service positive, ``no_match`` = service negative) and over the last 7 / 30 days. QA answers the
  harness model was unsure about (low confidence / a question for a human) are counted as ``unsure``.
* ``escalation_rate``: service ``need_more_info`` verdicts among the rule's current service verdicts (they all go to the
  harness model); ``escalations_30d``: escalations the harness model decided (``final``) or sent to a human.
* ``questions_open``: hits the harness model asked a human about that are still open (review tab "Questions from
  the model"), ``oldest_question_s``: how long the oldest has waited (per rule and in the totals);
  ``harness_decisions``: hits whose current decision is the harness model's.
* ``backlog``: open verify items (pending / leased / answered) by sample; per rule also ``escalation_pending`` (the
  service model's need_more_info verdicts still waiting for the harness model).
* ``needs_improvement``: agreement of the last 30 days below LLM_QA_AGREEMENT_MIN with at least ``QA_MIN_SAMPLES``
  samples; ``llm_mislabeled(source="verification")`` lists the disagreements for a prompt trial.
"""

from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from discovery_common import stats
from services.errors import NotFound

# the SQL and the helpers of the ``llm_quality`` snapshot (``discovery_common.stats``): one copy for the scanner's
# ``stats_refresh`` job and the API's live answer
QA_MIN_SAMPLES, ESCALATION_SAMPLE = stats.QA_MIN_SAMPLES, stats.ESCALATION_SAMPLE
VERIFY_SQL, HITS_SQL, BACKLOG_SQL, RULES_SQL = (stats.QUALITY_VERIFY_SQL, stats.QUALITY_HITS_SQL,
                                                stats.QUALITY_BACKLOG_SQL, stats.QUALITY_RULES_SQL)
_share, backlog = stats._share, stats.quality_backlog


def llm_quality(session: Session, rule_id: Optional[int] = None) -> Dict[str, Any]:
    """Per LLM rule (``rule_id``: that one, 404 when there is no such rule): agreement service vs harness, escalation
    rate, open questions (and the age of the oldest, ``oldest_question_s``), harness decisions, verify backlog
    (``escalation_pending``: the escalations among it), and the ``needs_improvement`` flag (agreement of the last 30
    days below LLM_QA_AGREEMENT_MIN); plus totals. = ``stats.llm_quality`` with the API's ``LLM_QA_AGREEMENT_MIN``."""
    from config import get_settings
    out = stats.llm_quality(session, get_settings().llm_qa_agreement_min, rule_id)
    if rule_id is not None and not out["rules"]:
        raise NotFound(f"llm rule {rule_id} not found")
    return out
