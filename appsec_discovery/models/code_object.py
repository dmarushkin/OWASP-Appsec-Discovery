import hashlib

from pydantic import BaseModel, validator
from typing import List, Dict, Optional

from appsec_discovery.matching import Scorable
from appsec_discovery.models.rules import RuleHit
from appsec_discovery.models.secrets import is_secret_name, looks_like_secret

# limits of the documentation taken from the code: a comment is context, not a copy of the file
COMMENT_MAX = 1000
SAMPLES_MAX = 5
SAMPLE_MAX = 200


def clean_comment(value) -> Optional[str]:
    """Whitespace-normalised comment (lines kept), clipped; None when empty."""
    if value is None:
        return None
    lines = [' '.join(line.split()) for line in str(value).strip().splitlines()]
    text = '\n'.join(line for line in lines if line)
    if not text:
        return None
    return text if len(text) <= COMMENT_MAX else text[:COMMENT_MAX - 1] + '…'


def clean_samples(values, field_name: Optional[str] = None) -> Optional[List[str]]:
    """Distinct non-empty sample values as strings (at most ``SAMPLES_MAX``, each clipped); None when none.

    Never a secret: no samples for a field named like a credential (``field_name``), values that
    look like one are dropped (``appsec_discovery.models.secrets``)."""
    if values is None or (field_name is not None and is_secret_name(field_name)):
        return None
    if isinstance(values, (str, int, float, bool)):
        values = [values]
    result = []
    for value in values:
        if value is None:
            continue
        text = ('true' if value else 'false') if isinstance(value, bool) else str(value).strip()
        if looks_like_secret(text):
            continue
        text = text if len(text) <= SAMPLE_MAX else text[:SAMPLE_MAX - 1] + '…'
        if text and text not in result:
            result.append(text)
        if len(result) == SAMPLES_MAX:
            break
    return result or None


class CodeObjectField(BaseModel, Scorable):
    field_name: str
    field_type: str
    file: Optional[str]
    line: Optional[int]
    severity: Optional[str]
    tags: Optional[List[str]]
    # the code comment / description of the field and example values from the code (examples,
    # enum values, defaults) or from an external parser; None when the code has none
    comment: Optional[str]
    samples: Optional[List[str]]

    class Config:
        # ``field.samples = ...`` after construction is cleaned (and secret-filtered) as well
        validate_assignment = True

    _comment = validator('comment', pre=True, allow_reuse=True)(clean_comment)

    @validator('samples', pre=True)
    def _samples(cls, value, values):
        # ``field_name`` is declared (validated) before ``samples``: secret-named fields get none
        return clean_samples(value, values.get('field_name'))

class CodeObjectProp(BaseModel, Scorable):
    prop_name: str
    prop_value: str
    file: Optional[str]
    line: Optional[int]
    severity: Optional[str]
    tags: Optional[List[str]]

class CodeObject(BaseModel, Scorable):
    hash: str
    object_name: str
    object_type: str
    parser: str
    severity: Optional[str]
    tags: Optional[List[str]]
    file: str
    line: int
    properties: Dict[str, CodeObjectProp]
    fields: Dict[str, CodeObjectField]
    # the code comment / description of the object (message, type, struct, table...)
    comment: Optional[str]
    # rule hits (keyword and LLM rules) with their status; None until a rule hits
    # (kept None rather than [] so unscored objects serialise as before)
    hits: Optional[List[RuleHit]]

    _comment = validator('comment', pre=True, allow_reuse=True)(clean_comment)


def object_identity(parser: str, file: str, object_type: str, logical_name: str) -> str:
    """Stable identity (``CodeObject.hash``) of a code object (P1-8).

    md5 of ``'#'.join([parser, file, object_type, logical_name])`` where ``file``
    is the path relative to the scanned folder (``/sub/file``) and
    ``logical_name`` is the parser-specific name path of the object: the
    structure name for a DTO, ``METHOD path`` for a route, ``Type.field`` for
    GraphQL, ``/pkg.Service/Method`` for gRPC, ``request.resolver`` for JS GraphQL
    queries, the module label for terraform vm objects and ``type.name`` for terraform resources.

    Line numbers, fields, properties, severity and tags are deliberately NOT part
    of the identity: moving code or adding a field keeps the hash. Changing this
    function (or a parser's ``logical_name``) changes every stored hash and is a
    breaking change for consumers that persist hashes (the discovery service).
    """
    hash_str = "#".join([parser or '', file or '', object_type or '', logical_name or ''])
    return hashlib.md5(hash_str.encode('utf-8')).hexdigest()
