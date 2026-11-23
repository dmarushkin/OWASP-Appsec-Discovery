"""Secret detection for the samples taken from the code (one filter for every parser).

Samples are stored by the discovery service, shown in the UI / MCP and sent to the LLM in the
classification prompts, so a hardcoded password / token in a default, an example tag or a spec
example must never become one. ``CodeObjectField`` applies both checks to its samples:

* ``is_secret_name(field_name)`` - the field is named like a credential (``db_password``,
  ``apiKey``, ``x-auth-token``, ``client_secret``, ``basic_auth``...): it gets no samples at all;
* ``looks_like_secret(value)`` - the value looks like a credential whatever the field name (PEM
  blocks, JWTs, AWS / GitHub / GitLab / Slack / Vault... tokens, ``scheme://user:pass@`` URLs,
  ``Password=...`` connection strings, ``Authorization`` / ``Bearer`` / ``Basic`` headers, long
  mixed-case base64-like blobs): the value is dropped.

Names are split into words (snake_case, kebab-case, camelCase, dotted paths) and only the last
path segment is looked at (the one before it when the last one is generic: ``password.value``).
Metadata about a secret is not a secret: ``token_type``, ``password_min_length``,
``secret_question_id``, ``api_key_id``, ``max_tokens``, ``next_page_token``.
"""
import base64
import binascii
import re

# a word of a name that names a credential
SECRET_WORDS = frozenset((
    'password', 'passwords', 'passwd', 'pwd', 'pass', 'passphrase', 'passcode',
    'secret', 'secrets', 'token', 'tokens', 'credential', 'credentials', 'creds',
    'apikey', 'apikeys', 'privatekey', 'accesskey', 'secretkey', 'authtoken', 'accesstoken',
    'refreshtoken', 'idtoken', 'apitoken', 'clientsecret', 'authorization', 'privkey',
    'dsn', 'connstr', 'connectionstring', 'cvv', 'cvv2', 'cvc', 'cvc2',
))
# parts of a single lowercase word (``dbpassword``, ``mysecret``)
SECRET_SUBSTRINGS = ('password', 'passwd', 'secret', 'credential', 'apikey', 'privatekey')
# ``<prefix>_key``: a key that is key material (``key`` alone, ``primary_key``, ``sort_key`` are not)
KEY_PREFIXES = frozenset(('api', 'private', 'access', 'signing', 'encryption', 'master', 'ssh',
                          'client', 'app', 'license', 'hmac', 'jwt', 'session', 'shared', 'priv'))
# ``auth`` is a credential only at the end of a name (``basic_auth``), not in ``auth_method``
GENERIC_WORDS = frozenset(('value', 'val', 'data', 'raw', 'plain', 'text', 'content', 'b64', 'base64',
                           'header', 'string', 'str'))
# a word before the secret word that makes it a count / a cursor (``max_tokens``, ``page_token``)
NOT_SECRET_PREFIXES = frozenset(('max', 'min', 'num', 'total', 'count', 'prompt', 'completion', 'input',
                                 'output', 'page', 'pagination', 'continuation', 'next', 'prev', 'previous',
                                 'cursor', 'sync'))
# a word after the secret word that makes the name metadata about the secret
NOT_SECRET_SUFFIXES = frozenset((
    'type', 'types', 'kind', 'id', 'ids', 'name', 'names', 'ref', 'refs', 'arn', 'path', 'file', 'filename',
    'url', 'uri', 'endpoint', 'length', 'len', 'size', 'min', 'max', 'count', 'ttl', 'expiry', 'expires',
    'expiration', 'expire', 'expired', 'lifetime', 'timeout', 'age', 'policy', 'policies', 'rule', 'rules',
    'format', 'version', 'enabled', 'disabled', 'required', 'hint', 'question', 'prompt', 'label',
    'description', 'desc', 'mode', 'strategy', 'algorithm', 'alg', 'scope', 'scopes', 'at', 'in',
    'strength', 'status', 'state', 'source', 'provider', 'location', 'store', 'manager', 'version',
    'changed', 'updated', 'created', 'reset', 'set', 'exists', 'used', 'usage', 'limit', 'field',
))

_SEGMENT = re.compile(r'[.\[\]/:]+')
_WORD = re.compile(r'[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+')

# values: PEM blocks, URLs with a password, ``password=...`` pairs of a connection string
_PEM = re.compile(r'-----BEGIN [A-Z0-9 ]*(PRIVATE KEY|CERTIFICATE|PGP PRIVATE)')
_URL_CREDENTIALS = re.compile(r'://[^/\s:@]+:[^/\s@]+@')
_CREDENTIAL_PAIR = re.compile(r'(?i)(?:^|[;,&?\s])(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|'
                              r'client[_-]?secret)\s*[=:]\s*[^\s;,&]{3,}')
# ``Authorization: ...`` / ``Bearer <token>`` / ``Basic <base64 user:pass>``
_AUTHORIZATION = re.compile(r'(?i)^\s*(?:proxy-)?authorization\s*:\s*\S')
_BEARER = re.compile(r'(?i)(?:^|\s)(?:bearer|token)\s+([A-Za-z0-9._~+/=-]{8,})')
_BASIC = re.compile(r'(?i)(?:^|\s)basic\s+([A-Za-z0-9+/]{6,}={0,2})(?:\s|$)')
# well-known token formats
_JWT = re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}')
_AWS_KEY_ID = re.compile(r'\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b')
_TOKEN_PREFIX = re.compile(r'(?<![\w-])(?:hvs\.|hvb\.|ghp_|gho_|ghs_|ghu_|ghr_|github_pat_|glpat-|gldt-|xox[abprs]-|'
                           r'sk-|sk_live_|rk_live_|npm_|AIza|AKIA|ASIA|eyJ)[\w.-]{12,}')
# a long blob of base64 / token characters with lower and upper case letters and digits (no ``-``:
# ``ro-k8s-stg-team-12345`` names are not tokens)
_TOKEN_LIKE = re.compile(r'^[A-Za-z0-9+/_.=]{32,}$')


def _words(segment: str) -> list:
    return [word.lower() for word in _WORD.findall(segment)]


def _is_secret_word(words: list, index: int) -> bool:
    word = words[index]
    prev = words[index - 1] if index else ''
    nxt = words[index + 1] if index + 1 < len(words) else ''
    if word in SECRET_WORDS or any(part in word for part in SECRET_SUBSTRINGS):
        return True
    if word == 'key':
        return prev in KEY_PREFIXES
    if word == 'auth':
        return not nxt or nxt in GENERIC_WORDS
    if word in ('string', 'str'):
        return prev in ('connection', 'conn')
    return False


def is_secret_name(name) -> bool:
    """True when the (last segment of the) field name names a credential."""
    if not name:
        return False
    segments = [segment for segment in _SEGMENT.split(str(name)) if segment]
    for segment in reversed(segments[-2:]):
        words = _words(segment)
        for index, word in enumerate(words):
            if not _is_secret_word(words, index):
                continue
            if index and words[index - 1] in NOT_SECRET_PREFIXES:
                continue
            if any(rest in NOT_SECRET_SUFFIXES for rest in words[index + 1:]):
                continue
            return True
        if words and not all(word in GENERIC_WORDS for word in words):
            return False        # the previous segment counts only behind a generic one (``password.value``)
    return False


def _basic_credentials(blob: str) -> bool:
    try:
        decoded = base64.b64decode(blob + '=' * (-len(blob) % 4), validate=True).decode('utf-8')
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    return ':' in decoded and decoded.isprintable()


def looks_like_secret(value) -> bool:
    """True when the value looks like a credential (see the module doc)."""
    if value is None or isinstance(value, (bool, int, float)):
        return False
    text = str(value).strip()
    if len(text) < 8:
        return False
    if _PEM.search(text) or _URL_CREDENTIALS.search(text) or _CREDENTIAL_PAIR.search(text):
        return True
    if _AUTHORIZATION.match(text) or _JWT.search(text) or _AWS_KEY_ID.search(text) or _TOKEN_PREFIX.search(text):
        return True
    bearer = _BEARER.search(text)
    if bearer and (re.search(r'\d', bearer.group(1)) or len(bearer.group(1)) >= 20):
        return True
    basic = _BASIC.search(text)
    if basic and _basic_credentials(basic.group(1)):
        return True
    return bool(_TOKEN_LIKE.match(text) and re.search(r'\d', text) and re.search(r'[a-z]', text)
                and re.search(r'[A-Z]', text))
