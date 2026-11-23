"""Loading of API specifications for the swagger parser.

* ``detect`` - is a document an OpenAPI 3.x or a Swagger 2.0 specification (top-level key);
* ``prepare`` - keys as strings, the ``description`` / ``title`` next to a schema ``$ref``
  kept (prance replaces the whole ``$ref`` object by its target); YAML aliases are expanded
  within ``MAX_DOCUMENT_NODES`` (an alias bomb fails the file);
* ``resolve`` - ``$ref``s inlined (local document and local files, never HTTP); a recursive
  schema is cut with an empty object instead of failing the file. Only regular files of at
  most ``MAX_SPEC_BYTES`` inside the scan root are read: a reference to anything else (outside
  the root, through a symlink leaving it, a device / FIFO, another scheme) becomes an empty
  object. The inlined content is bounded (``MAX_REF_NODES`` per reference written in the
  document, ``MAX_RESOLVED_NODES`` in all), beyond that references are cut like recursion;
* ``swagger2_to_openapi3`` - a resolved Swagger 2.0 document as OpenAPI 3.0 (``openapi_parser``
  only reads 3.x): ``in: body`` / ``formData`` -> ``requestBody``, parameter ``type`` / ``format``
  / ``items`` / ``enum`` / ``default`` -> ``schema``, response ``schema`` / ``examples`` ->
  ``content`` (media types from ``produces`` / ``consumes``);
* ``normalize`` - the paths of an OpenAPI 3 document in the shape ``openapi_parser`` accepts
  (schemas without ``type`` but with ``properties`` / ``items``, 3.1 type lists, ``type: file``,
  string discriminators, arrays without ``items``).

Everything works on plain dicts and never changes its input.
"""
import logging
import os
import re
import stat
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

# a specification file (the scanned one or a ``$ref``-ed one) larger than this is not read
MAX_SPEC_BYTES = 10 * 1024 * 1024
# nodes of a loaded document once its YAML aliases are expanded (a 400-byte alias bomb has 10^9)
MAX_DOCUMENT_NODES = 2_000_000
# nodes inlined by resolving the ``$ref``s: per reference written in a document (with all the
# references nested in its target) and for the whole document; a schema graph with fan-out
# (each schema referencing several others) grows exponentially with the depth otherwise
# (each dereference is also charged ``REF_COST``: prance's per-reference overhead dominates
# for small targets)
MAX_REF_NODES = 50_000
MAX_RESOLVED_NODES = 500_000
REF_COST = 10


class SpecTooLarge(ValueError):
    """The document expands beyond the node budget (YAML aliases)."""

# OpenAPI operations (Swagger 2.0 has no ``trace``)
METHODS = ('get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace')

# cheap content check before a file is parsed: a ``openapi:`` / ``swagger:`` key somewhere
SPEC_KEY_RX = re.compile(r'''(?<![\w$-])["']?(?:openapi|swagger)["']?\s*:''')

SCHEMA_TYPES = {'null', 'integer', 'number', 'string', 'boolean', 'array', 'object'}

# a ``$ref`` into one of these sections is not a schema: its siblings are left alone
NON_SCHEMA_REF = re.compile(r'/(?:parameters|responses|requestBodies|headers|examples|links|callbacks|'
                            r'pathItems|securitySchemes|securityDefinitions|paths)/')

# Swagger 2.0 parameter keys that describe its value (they form the OpenAPI 3 ``schema``)
PARAM_SCHEMA_KEYS = ('type', 'format', 'items', 'enum', 'default', 'minimum', 'maximum', 'exclusiveMinimum',
                     'exclusiveMaximum', 'pattern', 'maxLength', 'minLength', 'maxItems', 'minItems',
                     'uniqueItems', 'multipleOf')
# Swagger 2.0 parameter keys without an OpenAPI 3 counterpart on the parameter
PARAM_DROPPED_KEYS = PARAM_SCHEMA_KEYS + ('collectionFormat', 'schema')
OPERATION_KEYS = ('summary', 'description', 'operationId', 'deprecated', 'tags', 'externalDocs', 'security')
PARAMETER_LOCATIONS = ('query', 'header', 'path', 'cookie')
FORM_TYPES = ('application/x-www-form-urlencoded', 'multipart/form-data')
DEFAULT_MEDIA_TYPE = 'application/json'


# --- detection ---------------------------------------------------------------------------------

def looks_like_spec(text: str) -> bool:
    """Cheap pre-check: the text has an ``openapi`` / ``swagger`` key."""
    return bool(SPEC_KEY_RX.search(text))


def detect(document) -> Optional[int]:
    """3 for an OpenAPI 3.x document, 2 for Swagger 2.0, None for anything else.

    Decided by the top-level ``openapi`` / ``swagger`` key; a specification needs ``paths``.
    """
    if not isinstance(document, dict) or not isinstance(document.get('paths'), dict):
        return None
    if document.get('openapi') is not None and str(document['openapi']).strip().startswith('3'):
        return 3
    if document.get('swagger') is not None and str(document['swagger']).strip() in ('2', '2.0'):
        return 2
    return None


def load_document(text: str, path: str):
    """The parsed YAML / JSON document (prance's loader: YAML 1.2, ``on`` / ``off`` stay strings)."""
    from prance.util.formats import parse_spec
    return parse_spec(text, path)


# --- before resolving --------------------------------------------------------------------------

def _is_schema_ref(ref) -> bool:
    return isinstance(ref, str) and not NON_SCHEMA_REF.search(ref.split('#', 1)[-1] if '#' in ref else '')


def _copy(node, budget: List[int], rewrite_refs: bool):
    budget[0] -= 1
    if budget[0] < 0:
        raise SpecTooLarge(f'more than {MAX_DOCUMENT_NODES} nodes once the YAML aliases are expanded')
    if isinstance(node, dict):
        result = {str(key): _copy(value, budget, rewrite_refs) for key, value in node.items()}
        ref = result.get('$ref')
        if rewrite_refs and ref is not None and _is_schema_ref(ref):
            doc = next((result[key] for key in ('description', 'title')
                        if isinstance(result.get(key), str) and result[key].strip()), None)
            if doc is not None:
                return {'allOf': [{'$ref': ref}, {'description': doc}]}
        return result
    if isinstance(node, list):
        return [_copy(item, budget, rewrite_refs) for item in node]
    return node


def prepare(node, max_nodes: int = None):
    """Copy of ``node`` with string keys and ``{$ref, description|title}`` (schema refs) rewritten
    to ``{allOf: [{$ref}, {description}]}``, so the description written next to a reference
    survives the resolution (the title is used when there is no description).

    YAML aliases share nodes, the copy expands them: more than ``max_nodes`` (default
    ``MAX_DOCUMENT_NODES``) nodes raise ``SpecTooLarge``."""
    return _copy(node, [MAX_DOCUMENT_NODES if max_nodes is None else max_nodes], True)


def _cut_recursion(limit, parsed_url, recursions=()):
    """A recursive reference becomes an empty object (prance raises by default)."""
    return {'type': 'object', 'properties': {}}


def _count_nodes(node, limit: int) -> int:
    """Nodes of ``node`` (stops counting past ``limit``)."""
    count, stack = 0, [node]
    while stack and count <= limit:
        current = stack.pop()
        count += 1
        if isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return count


def _within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:  # different drives
        return False


def read_spec_file(path: str, root: str) -> Optional[str]:
    """Text of ``path`` when it may be read for a scan of ``root``: after following symlinks
    it is a regular file inside ``root`` of at most ``MAX_SPEC_BYTES``; None otherwise (the
    reason is logged, nothing is read)."""
    real = os.path.realpath(path)
    if not _within(real, os.path.realpath(root)):
        logger.warning(f"swagger: {path} is outside the scanned folder, not read")
        return None
    try:
        info = os.stat(real)
    except OSError as ex:
        logger.warning(f"swagger: cannot read {path}: {type(ex).__name__}")
        return None
    if not stat.S_ISREG(info.st_mode):
        logger.warning(f"swagger: {path} is not a regular file, not read")
        return None
    if info.st_size > MAX_SPEC_BYTES:
        logger.warning(f"swagger: {path} is larger than {MAX_SPEC_BYTES} bytes, not read")
        return None
    try:
        with open(real, 'rb') as handle:
            data = handle.read(MAX_SPEC_BYTES + 1)
    except OSError as ex:
        logger.warning(f"swagger: cannot read {path}: {type(ex).__name__}")
        return None
    if len(data) > MAX_SPEC_BYTES:
        logger.warning(f"swagger: {path} is larger than {MAX_SPEC_BYTES} bytes, not read")
        return None
    try:
        return data.decode('utf-8-sig')
    except UnicodeDecodeError:
        logger.warning(f"swagger: {path} is not UTF-8, not read")
        return None


def _resolver_class():
    from prance.util.resolver import RefResolver
    from prance.util.url import fetch_url, urlresource

    class ScopedRefResolver(RefResolver):
        """prance resolver that reads referenced files only inside ``root`` (``read_spec_file``)
        and bounds the inlined content (``MAX_REF_NODES`` / ``MAX_RESOLVED_NODES``).

        prance fetches a file only when it is not in the reference cache: an allowed file is
        loaded here (aliases bounded like ``prepare``) and put in the cache, a refused one is
        never handed to prance - its reference becomes an empty object.
        """

        def __init__(self, specs, url, *, root: str, **options):
            super().__init__(specs, url, **options)
            self._root = os.path.realpath(root)
            self._document = urlresource(self.parsed_url)
            self._cache = self._RefResolver__reference_cache
            self._strict = self._RefResolver__strict
            self._refused = set()
            self._total = 0
            self._spent = 0
            self._truncated = False

        def _external_allowed(self, ref_url) -> bool:
            if urlresource(ref_url) == self._document:
                return True
            key = (urlresource(ref_url), self._strict)
            if key in self._cache:
                return True
            if key in self._refused:
                return False
            loaded = None
            if ref_url.scheme == 'file':
                text = read_spec_file(ref_url.path, self._root)
                if text is not None:
                    try:
                        loaded = _copy(load_document(text, ref_url.path), [MAX_DOCUMENT_NODES], False)
                    except Exception as ex:
                        logger.warning(f"swagger: cannot load referenced {ref_url.path}: {type(ex).__name__}: {ex}")
                        loaded = None
                    if loaded is not None and not isinstance(loaded, (dict, list)):
                        loaded = None
            else:
                logger.warning(f"swagger: $ref scheme {ref_url.scheme!r} is not resolved: {ref_url.geturl()}")
            if loaded is None:
                self._refused.add(key)
                return False
            self._cache[key] = loaded
            return True

        def _dereference(self, ref_url, obj_path, recursions):
            if not self._external_allowed(ref_url):
                return {}
            if len(recursions) <= 1:
                self._spent = 0  # a reference written in the document: a new budget
            from prance.util.path import path_get
            try:
                raw = fetch_url(ref_url, self._cache, None, self._strict)
                raw = path_get(raw, obj_path) if obj_path else raw
            except (KeyError, IndexError, TypeError):
                raw = None  # prance raises its ResolutionError below
            if raw is not None:
                left = min(MAX_REF_NODES - self._spent, MAX_RESOLVED_NODES - self._total)
                size = _count_nodes(raw, max(left, 0)) + REF_COST
                if size > left:
                    if not self._truncated:
                        self._truncated = True
                        logger.info(f"swagger: {self.parsed_url.path}: $refs inline more than {MAX_REF_NODES} nodes per "
                                    f"reference / {MAX_RESOLVED_NODES} in all, the deeper ones are cut")
                    return _cut_recursion(None, ref_url)
                self._spent += size
                self._total += size
            return super()._dereference(ref_url, obj_path, recursions)

    return ScopedRefResolver


def resolve(document: dict, path: str, root: Optional[str] = None) -> dict:
    """``document`` (read from ``path``) with its ``$ref``s inlined.

    Only ``paths`` is resolved (the other sections are returned as they are). References into
    the document itself and into local files under ``root`` (default: the folder of ``path``)
    are resolved, HTTP ones are left as they are; a file outside ``root``,
    not a regular file or too large becomes an empty object (see ``read_spec_file``);
    recursion and too much inlined content are cut by ``_cut_recursion``. Raises on a broken
    reference.
    """
    from prance.util.resolver import RESOLVE_FILES, RESOLVE_INTERNAL
    from prance.util.url import absurl

    path = os.path.abspath(path)
    resolver = _resolver_class()(document, absurl(path),
                                 root=root if root is not None else os.path.dirname(path),
                                 recursion_limit_handler=_cut_recursion,
                                 resolve_types=RESOLVE_INTERNAL | RESOLVE_FILES,
                                 strict=False)
    # only ``paths`` is read afterwards: the other sections (``components``, ``definitions``)
    # are reached through the references of the paths. prance gathers all the substitutions
    # before applying any, so every reference reads the unresolved document either way
    paths = resolver.specs.get('paths') if isinstance(resolver.specs, dict) else None
    if paths is None:
        resolver.resolve_references()
        return resolver.specs
    return {**resolver.specs, 'paths': resolver._resolve_partial(resolver.parsed_url, paths, ())}


# --- schemas -----------------------------------------------------------------------------------

def normalize_schema(schema) -> dict:
    """``schema`` in the shape ``openapi_parser`` builds without errors (a copy).

    A 3.1 type list keeps its first non-null type, ``type: file`` is a binary string, an unknown
    type is dropped, a missing type is ``object`` / ``array`` when the schema has ``properties``
    / ``items``, an array without ``items`` gets an untyped one, a Swagger 2.0 string
    ``discriminator`` becomes ``{propertyName}``.
    """
    if not isinstance(schema, dict):
        return {}
    result = dict(schema)

    kind = result.get('type')
    if isinstance(kind, list):
        types = [str(item) for item in kind if item != 'null']
        kind = types[0] if types else ('null' if kind else None)
    if kind == 'file':
        kind = 'string'
        result.setdefault('format', 'binary')
    if kind is not None and kind not in SCHEMA_TYPES:
        kind = None
    if kind is None and not any(key in result for key in ('allOf', 'oneOf', 'anyOf')):
        if isinstance(result.get('properties'), dict) or 'additionalProperties' in result:
            kind = 'object'
        elif 'items' in result:
            kind = 'array'
    if kind is None:
        result.pop('type', None)
    else:
        result['type'] = kind

    if isinstance(result.get('discriminator'), str):
        result['discriminator'] = {'propertyName': result['discriminator']}

    if isinstance(result.get('properties'), dict):
        result['properties'] = {str(name): normalize_schema(value) for name, value in result['properties'].items()}
    elif 'properties' in result:
        del result['properties']

    if kind == 'array' or 'items' in result:
        items = result.get('items')
        if isinstance(items, list):  # tuple validation: the first item stands for all
            items = items[0] if items else {}
        result['items'] = normalize_schema(items)

    if isinstance(result.get('additionalProperties'), dict):
        result['additionalProperties'] = normalize_schema(result['additionalProperties'])
    if isinstance(result.get('not'), dict):
        result['not'] = normalize_schema(result['not'])
    for key in ('allOf', 'oneOf', 'anyOf'):
        if key in result:
            members = result[key] if isinstance(result[key], list) else []
            result[key] = [normalize_schema(member) for member in members if isinstance(member, dict)]
            if not result[key]:
                del result[key]
    return result


def _normalize_content(content) -> dict:
    if not isinstance(content, dict):
        return {}
    result = {}
    for media_type, media in content.items():
        if not isinstance(media, dict):
            continue
        media = dict(media)
        media['schema'] = normalize_schema(media.get('schema'))
        if not isinstance(media.get('examples'), dict):
            media.pop('examples', None)
        result[str(media_type)] = media
    return result


def _normalize_parameter(parameter) -> Optional[dict]:
    if not isinstance(parameter, dict) or not parameter.get('name') or parameter.get('in') not in PARAMETER_LOCATIONS:
        return None
    result = dict(parameter)
    if 'schema' in result:
        result['schema'] = normalize_schema(result['schema'])
    if 'content' in result:
        result['content'] = _normalize_content(result['content'])
    return result


def _normalize_parameters(parameters) -> List[dict]:
    if not isinstance(parameters, list):
        return []
    return [p for p in (_normalize_parameter(item) for item in parameters) if p is not None]


def _normalize_headers(headers) -> dict:
    if not isinstance(headers, dict):
        return {}
    result = {}
    for name, header in headers.items():
        if isinstance(header, dict):
            header = dict(header)
            if 'schema' in header:
                header['schema'] = normalize_schema(header['schema'])
            result[str(name)] = header
    return result


def _normalize_operation(operation: dict) -> dict:
    result = dict(operation)
    result['parameters'] = _normalize_parameters(operation.get('parameters'))
    body = operation.get('requestBody')
    if isinstance(body, dict):
        result['requestBody'] = {**body, 'content': _normalize_content(body.get('content'))}
    else:
        result.pop('requestBody', None)
    responses = {}
    for code, response in (operation.get('responses') if isinstance(operation.get('responses'), dict) else {}).items():
        if not isinstance(response, dict):
            continue
        response = dict(response)
        if 'content' in response:
            response['content'] = _normalize_content(response['content'])
        if 'headers' in response:
            response['headers'] = _normalize_headers(response['headers'])
        responses[str(code)] = response
    result['responses'] = responses or {'default': {'description': ''}}
    result.pop('callbacks', None)  # not read, and their shape is free-form
    return result


def normalize(document: dict) -> dict:
    """The paths of a resolved OpenAPI 3 document, normalised (see ``normalize_schema``), as a
    minimal document for ``openapi_parser`` (``openapi``, a stub ``info``, ``paths``): the other
    sections are not read by the parser and only add ways to fail."""
    paths = {}
    for url, item in (document.get('paths') or {}).items():
        if not isinstance(url, str) or not url.startswith('/') or not isinstance(item, dict):
            continue  # ``x-`` extensions of the paths object
        path_item = {key: value for key, value in item.items() if key in ('summary', 'description')}
        if item.get('parameters'):
            path_item['parameters'] = _normalize_parameters(item['parameters'])
        for method in METHODS:
            if isinstance(item.get(method), dict):
                path_item[method] = _normalize_operation(item[method])
        paths[url] = path_item
    return {'openapi': str(document.get('openapi') or '3.0.3'), 'info': {'title': '', 'version': ''}, 'paths': paths}


# --- Swagger 2.0 -> OpenAPI 3.0 ----------------------------------------------------------------

def _media_types(values, default: Iterable[str]) -> List[str]:
    if isinstance(values, list):
        found = [str(value) for value in values if isinstance(value, str) and value.strip()]
        if found:
            return found
    return list(default)


def _param_schema(parameter: dict) -> dict:
    """The OpenAPI 3 schema of a Swagger 2.0 non-body parameter (or header / items object)."""
    return {key: parameter[key] for key in PARAM_SCHEMA_KEYS if key in parameter}


def _convert_parameter(parameter: dict) -> dict:
    result = {key: value for key, value in parameter.items() if key not in PARAM_DROPPED_KEYS}
    schema = _param_schema(parameter)
    if schema:
        result['schema'] = schema
    if parameter.get('in') == 'path':
        result['required'] = True
    return result


def _form_body(parameters: List[dict], consumes: List[str]) -> dict:
    """``requestBody`` of the ``in: formData`` parameters: an object with one property each."""
    properties, required = {}, []
    for parameter in parameters:
        schema = _param_schema(parameter)
        for key in ('description', 'x-example', 'example'):
            if key in parameter:
                schema['example' if key == 'x-example' else key] = parameter[key]
        properties[str(parameter['name'])] = schema
        if parameter.get('required'):
            required.append(str(parameter['name']))
    schema = {'type': 'object', 'properties': properties}
    if required:
        schema['required'] = required
    media_types = [media for media in consumes if media in FORM_TYPES]
    if not media_types:
        has_file = any(parameter.get('type') == 'file' for parameter in parameters)
        media_types = ['multipart/form-data' if has_file else 'application/x-www-form-urlencoded']
    return {'content': {media: {'schema': schema} for media in media_types}}


def _merged_parameters(path_parameters, operation_parameters) -> List[dict]:
    """Operation parameters, then the path ones it does not override (by ``in`` + ``name``)."""
    own = [p for p in (operation_parameters or []) if isinstance(p, dict)] if isinstance(operation_parameters, list) else []
    shared = [p for p in (path_parameters or []) if isinstance(p, dict)] if isinstance(path_parameters, list) else []
    keys = {(p.get('in'), p.get('name')) for p in own}
    return own + [p for p in shared if (p.get('in'), p.get('name')) not in keys]


def _convert_response(response: dict, produces: List[str]) -> dict:
    result = {'description': str(response.get('description') or '')}
    if isinstance(response.get('headers'), dict):
        result['headers'] = {str(name): {**({'description': header['description']} if header.get('description') else {}),
                                         'schema': _param_schema(header)}
                             for name, header in response['headers'].items() if isinstance(header, dict)}
    schema = response.get('schema')
    if isinstance(schema, dict):
        examples = response.get('examples') if isinstance(response.get('examples'), dict) else {}
        content = {}
        for media in produces:
            content[media] = {'schema': schema}
            if media in examples:
                content[media]['example'] = examples[media]
        if examples and not any(media in examples for media in produces):
            # an example under another media type still documents the payload
            content[produces[0]]['example'] = next(iter(examples.values()))
        result['content'] = content
    return result


def _convert_operation(operation: dict, path_parameters, consumes: List[str], produces: List[str]) -> dict:
    result = {key: operation[key] for key in OPERATION_KEYS if key in operation}
    result.update({key: value for key, value in operation.items() if isinstance(key, str) and key.startswith('x-')})
    consumes = _media_types(operation.get('consumes'), consumes)
    produces = _media_types(operation.get('produces'), produces)

    parameters, body, form = [], None, []
    for parameter in _merged_parameters(path_parameters, operation.get('parameters')):
        location = parameter.get('in')
        if location == 'body':
            body = parameter
        elif location == 'formData':
            if parameter.get('name'):
                form.append(parameter)
        else:
            parameters.append(_convert_parameter(parameter))
    result['parameters'] = parameters

    if body is not None:
        result['requestBody'] = {
            'content': {media: {'schema': body.get('schema') if isinstance(body.get('schema'), dict) else {}}
                        for media in consumes},
            **({'description': body['description']} if body.get('description') else {}),
            **({'required': body['required']} if isinstance(body.get('required'), bool) else {}),
        }
    elif form:
        result['requestBody'] = _form_body(form, consumes)

    responses = operation.get('responses') if isinstance(operation.get('responses'), dict) else {}
    result['responses'] = {str(code): _convert_response(response, produces)
                           for code, response in responses.items() if isinstance(response, dict)}
    return result


def swagger2_to_openapi3(document: dict) -> dict:
    """A resolved (``$ref``-free) Swagger 2.0 document as OpenAPI 3.0 (paths only, see
    ``normalize``). Paths stay as written: ``basePath`` belongs to the servers in OpenAPI 3."""
    consumes = _media_types(document.get('consumes'), [DEFAULT_MEDIA_TYPE])
    produces = _media_types(document.get('produces'), [DEFAULT_MEDIA_TYPE])
    paths: Dict[str, Any] = {}
    for url, item in (document.get('paths') or {}).items():
        if not isinstance(item, dict):
            continue
        path_item = {}
        for method in METHODS:
            if isinstance(item.get(method), dict):
                path_item[method] = _convert_operation(item[method], item.get('parameters'), consumes, produces)
        paths[url] = path_item
    return {'openapi': '3.0.3', 'info': {'title': '', 'version': ''}, 'paths': paths}
