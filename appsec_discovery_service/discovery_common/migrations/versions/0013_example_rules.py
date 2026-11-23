"""Default rules of a fresh installation (llm, object, ``mark_fields``: one call per object marks the object and the
fields the model names):

* ``db-tables-with-client-data`` (category ``pii``, severity ``high``, tags ``personal-data``): database tables
  holding personal data - installed ENABLED;
* ``api-with-auth`` (category ``auth``, severity ``critical``, tags ``auth-data``, object types route / rpc / query /
  mutation): API operations whose request or response carries authentication secrets (passwords, codes, tokens,
  keys) - installed DISABLED (enable it in the UI / API / MCP).

Both are in mode ``auto``: the service model's ``match`` verdicts are ``confirmed`` at once
(``decided_tier = 'service'``) and score the tables. They stay under the tiered workflow (migrations 0020,
0021): confirmed service verdicts are in the harness model's QA sample (``qa_positive``, LLM_QA_SAMPLE_RATE),
``need_more_info`` ones are escalated, a harness or human decision overrides them. Automatic runs (after a scan)
need LLM_API_URL; a manual run can also use the external executor. Switch them off / on or to ``review`` from the
UI / API / MCP.

A rule is only added when no live rule has its name (an existing installation keeps its own rules and
decisions). Downgrade removes the rules this revision added when they have no hits.

Revision ID: 0013_example_rules
Revises: 0012_llm_work
Create Date: 2026-11-21
"""
import json

import sqlalchemy as sa
from alembic import op

revision = "0013_example_rules"
down_revision = "0012_llm_work"
branch_labels = None
depends_on = None

AUTHOR = "migration:0013_example_rules"

DB_TABLES = (
    "You are a data protection reviewer for a bank. The object is a database table with its columns. Mark the table "
    "only if its rows store personal data of natural persons (clients, employees, representatives): names, identity "
    "documents, INN / SNILS, dates of birth, phones, e-mails, addresses, card holder data, biometrics. Do NOT mark "
    "tables that only hold technical data, ids, statuses, amounts, settings, queues, logs without personal data or "
    "data of legal entities. Answer need_more_info only when the columns strongly suggest personal data but their "
    "meaning is ambiguous. On match list in fields the columns that hold the personal data.")

API_AUTH = (
    "You are an application security reviewer. The object is an API operation (HTTP route, gRPC method or GraphQL "
    "query / mutation) with its request and response fields. Mark the operation only if its request or response "
    "carries authentication or authorization secrets or credentials: passwords and password hashes, PIN codes, OTP / "
    "SMS / confirmation codes, access / refresh / session / bearer / JWT tokens, API keys, client secrets, private or "
    "signing keys, session cookies or session ids, CVV/CVC, 3-D Secure data, answers to security questions. Do NOT "
    "mark operations that only carry logins or e-mails (of clients or employees), user / client / account ids, role / "
    "permission / scope names, token types and expiry times, public keys and certificates, hashes used as identifiers "
    "(request hash, idempotency key), account or card tokens used as references, flags such as is_authorized or "
    "is_blocked. Answer need_more_info only when a field looks like a secret but its name and context are ambiguous. "
    "On match list in fields the fields that hold the secrets.")

EXAMPLES = [
    dict(kind="llm", name="db-tables-with-client-data", category="pii", severity="high", target="object",
         mode="auto", enabled=True, tags=["personal-data"], prompt=DB_TABLES,
         scope={"object_type_re": "table", "mark_fields": True}),
    dict(kind="llm", name="api-with-auth", category="auth", severity="critical", target="object",
         mode="auto", enabled=False, tags=["auth-data"], prompt=API_AUTH,
         scope={"object_type_re": "route|rpc|query|mutation", "mark_fields": True}),
]


def upgrade() -> None:
    conn = op.get_bind()
    insert = sa.text("""
        INSERT INTO rules (kind, name, category, severity, target, mode, scope, prompt, version, enabled,
                           tags, created_at, updated_at, updated_by)
        SELECT :kind, :name, :category, :severity, :target, :mode, CAST(:scope AS jsonb), :prompt, 1, :enabled,
               :tags, now(), now(), :author
        WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = :name AND deleted_at IS NULL)""")
    for rule in EXAMPLES:
        conn.execute(insert, {**rule, "scope": json.dumps(rule["scope"]), "author": AUTHOR})


def downgrade() -> None:
    op.get_bind().execute(sa.text("""
        DELETE FROM rules r WHERE r.updated_by = :author AND r.name = ANY(:names)
          AND NOT EXISTS (SELECT 1 FROM rule_hits h WHERE h.rule_id = r.id)"""),
        {"author": AUTHOR, "names": [rule["name"] for rule in EXAMPLES]})
