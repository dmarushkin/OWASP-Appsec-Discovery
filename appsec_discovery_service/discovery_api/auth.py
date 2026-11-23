"""Authentication (P3-2): bcrypt admin password, short-lived HS256 JWTs.

The same bearer token protects the REST API and the MCP endpoint (``/mcp``); the token's
``sub`` is recorded as ``reviewer`` of review decisions.

Service tokens (``adt_...``, created by the admin with ``POST /tokens``, only their sha256 is
stored) carry scopes:

* ``ingest``: collectors of external parsers, limited to project path prefixes, accepted by the ``/ingest``
  endpoints only (``get_ingest_user``);
* ``mcp`` (scale, contract 8): a harness / agent client. Accepted by the MCP endpoint and by the REST endpoints
  the MCP tools wrap, with the identity ``token:<name>`` - the reviewer of its decisions, the owner of its work
  item leases, the key of its MCP rate limit (``MCP_RATE_LIMIT_PER_MINUTE``). Refused by the admin-only endpoints
  (``get_admin_user``: tokens).

Everything else refuses service tokens.
"""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from config import ALGORITHM, ApiSettings, ConfigError, get_settings
from models import UserData

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

# Refused as admin password (checked against the configured hash at startup).
WEAK_PASSWORDS = ("admin", "password", "changeme", "123456", "discovery")


class AuthError(Exception):
    pass


def check_settings(settings: ApiSettings) -> None:
    """Startup checks that need the password hash: a bcrypt hash, not a well-known password."""
    if pwd_context.identify(settings.ui_admin_password_hash) is None:
        raise ConfigError("UI_ADMIN_PASSWORD_HASH is not a bcrypt hash")
    if settings.allow_weak_password:
        import logging
        logging.getLogger(__name__).warning("UI_ALLOW_WEAK_PASSWORD is on: the admin password is not checked "
                                            "against well-known passwords (use it on local stands only)")
        return
    weak = list(WEAK_PASSWORDS) + [settings.ui_admin_email, settings.ui_admin_email.split("@")[0]]
    for password in weak:
        if pwd_context.verify(password, settings.ui_admin_password_hash):
            raise ConfigError("UI_ADMIN_PASSWORD_HASH is the hash of a well-known password, choose another one")


def authenticate_user(username: str, password: str) -> Optional[UserData]:
    settings = get_settings()
    user_ok = hmac.compare_digest(username.encode(), settings.ui_admin_email.encode())
    # verify even for an unknown user: no timing difference between the two failures
    password_ok = pwd_context.verify(password, settings.ui_admin_password_hash)
    if user_ok and password_ok:
        return UserData(username=settings.ui_admin_email)
    return None


def create_access_token(username: str, now: Optional[datetime] = None) -> str:
    settings = get_settings()
    now = now or datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.token_ttl_minutes)
    claims = {"sub": username, "iat": int(now.timestamp()), "exp": int(expire.timestamp())}
    return jwt.encode(claims, settings.ui_jwt_key, algorithm=ALGORITHM)


def user_from_token(token: Optional[str]) -> UserData:
    """Validate a bearer token (signature, ``exp``, known user); raises ``AuthError``."""
    if not token:
        raise AuthError("missing bearer token")
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.ui_jwt_key, algorithms=[ALGORITHM])
    except JWTError as e:
        raise AuthError(f"invalid token: {e}") from None
    username = payload.get("sub")
    if not username or "exp" not in payload or username != settings.ui_admin_email:
        raise AuthError("invalid token")
    return UserData(username=username)


def bearer_token(authorization: Optional[str]) -> Optional[str]:
    """The token of an ``Authorization: Bearer <token>`` header value."""
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return None
    return token.strip() or None


def principal(token: Optional[str]) -> UserData:
    """The admin of a JWT, or the ``token:<name>`` identity of a service token with scope ``mcp``; ``AuthError``
    for anything else (an ingest-only token included)."""
    if token and token.startswith(SERVICE_TOKEN_PREFIX):
        user = service_principal(token)
        if MCP_SCOPE not in (user.scopes or []):
            raise AuthError("this service token has no mcp scope (ingest tokens are accepted by /ingest only)")
        return user
    return user_from_token(token)


def get_current_user(token: Optional[str] = Depends(oauth2_scheme)) -> UserData:
    if token and token.startswith(SERVICE_TOKEN_PREFIX):
        try:
            return principal(token)
        except AuthError as e:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from None
    try:
        return user_from_token(token)
    except AuthError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None


def get_admin_user(token: Optional[str] = Depends(oauth2_scheme)) -> UserData:
    """Admin-only endpoints (tokens): the JWT of the admin, never a service token."""
    if token and token.startswith(SERVICE_TOKEN_PREFIX):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="service tokens cannot manage tokens")
    return get_current_user(token)



SERVICE_TOKEN_PREFIX = "adt_"
MCP_SCOPE = "mcp"
TOKEN_SCOPES = ("ingest", MCP_SCOPE)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_service_token() -> str:
    return SERVICE_TOKEN_PREFIX + secrets.token_urlsafe(32)


def service_principal(token: str) -> UserData:
    """The principal of a live service token (``last_used_at`` is bumped); raises ``AuthError``."""
    from sqlalchemy import text as sql

    from discovery_common import db
    with db.unit_of_work() as session:
        row = session.execute(sql("""
            UPDATE api_tokens SET last_used_at = now() WHERE token_hash = :h AND revoked_at IS NULL
            RETURNING name, scopes, project_prefixes"""), {"h": hash_token(token)}).first()
    if row is None:
        raise AuthError("invalid or revoked service token")
    return UserData(username=f"token:{row.name}", scopes=list(row.scopes), project_prefixes=list(row.project_prefixes))


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials",
                         headers={"WWW-Authenticate": "Bearer"})


def get_ingest_user(token: Optional[str] = Depends(oauth2_scheme)) -> UserData:
    """``/ingest`` endpoints: the admin (JWT) or a service token with scope ``ingest``."""
    if token and token.startswith(SERVICE_TOKEN_PREFIX):
        try:
            user = service_principal(token)
        except AuthError:
            raise _unauthorized() from None
        if "ingest" not in (user.scopes or []):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="token has no ingest scope")
        return user
    return get_current_user(token)