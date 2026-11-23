"""Service tokens for collectors of external parsers (admin only): scope ``ingest`` on project
path prefixes under ``external/``. The token is shown once; only its sha256 is stored."""

from typing import Any, Dict, List

from sqlalchemy import text
from sqlalchemy.orm import Session

from auth import hash_token, new_service_token
from schemas import ApiTokenIn
from services.errors import NotFound


def create_token(session: Session, data: ApiTokenIn, created_by: str) -> Dict[str, Any]:
    token = new_service_token()
    row = session.execute(text("""
        INSERT INTO api_tokens (name, token_hash, scopes, project_prefixes, created_by)
        VALUES (:n, :h, :s, :p, :by) RETURNING id, created_at"""),
        {"n": data.name, "h": hash_token(token), "s": data.scopes,
         "p": [p.rstrip("/") for p in data.project_prefixes], "by": created_by}).one()
    return {"id": row.id, "name": data.name, "token": token, "scopes": data.scopes,
            "project_prefixes": [p.rstrip("/") for p in data.project_prefixes], "created_at": row.created_at,
            "note": "store the token now: it is not shown again"}


def list_tokens(session: Session) -> List[Dict[str, Any]]:
    return [dict(r) for r in session.execute(text("""
        SELECT id, name, scopes, project_prefixes, created_by, created_at, last_used_at, revoked_at
        FROM api_tokens ORDER BY id""")).mappings()]


def revoke_token(session: Session, token_id: int) -> Dict[str, Any]:
    row = session.execute(text("""UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, now()) WHERE id = :i
                                  RETURNING id, name, revoked_at"""), {"i": token_id}).mappings().first()
    if row is None:
        raise NotFound(f"token {token_id} not found")
    return dict(row)
