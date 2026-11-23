"""OpenAPI 3.x / Swagger 2.0 specifications: one ``route`` object per operation.

Identity and name: ``METHOD path`` (``GET /users/{id}``), the path as written in the
spec (no ``basePath`` / server prefix). Fields:

* ``<in>.param.<name>`` - parameters (``query`` / ``path`` / ``header`` / ``cookie``); an
  operation parameter overrides the path-level one of the same ``in`` + ``name``;
* ``input.<a>.<b>`` - request body properties (Swagger 2.0 ``in: body`` / ``formData``);
* ``output.<a>.<b>`` - response body properties (all responses; the first one defining a name
  wins); list items share the name of the list, a list of scalars ends with ``.``
  (``output.tags.``).

Comments: operation ``summary`` + ``description``; a field's ``description``, else its
``title``, where the description written next to a ``$ref`` wins over the referenced schema's
own one; a list of scalars is documented by the list, else by its items. Samples: ``example``,
``x-example``, ``examples``, ``enum`` and ``default`` of the parameter / schema (also of the
items of an array parameter) and the scalars of the media type examples.

Robustness: a file that is not a specification is skipped silently; a specification that cannot
be read is logged and skipped; an operation that ``openapi_parser`` rejects is dropped alone.
Untrusted input: only regular files inside the scanned folder of at most ``specs.MAX_SPEC_BYTES``
are read (also through ``$ref``), YAML aliases and ``$ref`` inlining are bounded (see ``spec``),
and a request / response body yields at most ``max_output_fields`` fields.
"""
import logging
import os
import stat
from typing import Any, Dict, Iterable, List, Optional, Tuple

from openapi_parser.enumeration import OperationMethod
from openapi_parser.parser import _create_parser

from appsec_discovery.parsers.base_parser import FileParser
from appsec_discovery.models import CodeObject, CodeObjectProp, CodeObjectField
from appsec_discovery.models.code_object import clean_comment, clean_samples
from appsec_discovery.parsers.swagger import spec as specs

logger = logging.getLogger(__name__)

# schemas without ``type`` are common (grpc-gateway ``protobufAny``, free-form objects):
# ``openapi_parser`` warns about each of them, which only floods the scan log
class _ImplicitTypeFilter(logging.Filter):
    def filter(self, record):
        return not str(record.msg).startswith('Implicit type assignment')


logging.getLogger('openapi_parser.builders.schema').addFilter(_ImplicitTypeFilter())

# nesting of schema properties followed for fields (recursive schemas are cut while resolving)
MAX_DEPTH = 20

# attribute of the parsed ``Specification`` with the resolved spec dict (raw parameters keep their
# ``example`` / ``examples`` that openapi_parser drops); absent when the spec came from elsewhere
RAW_ATTR = '_appsec_raw'
SCALARS = (str, int, float, bool)


def _scalars(value) -> List[Any]:
    """``value`` when it is a scalar, its scalar items when it is a list; [] otherwise."""
    if isinstance(value, SCALARS):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, SCALARS)]
    return []


def _examples(value) -> List[Any]:
    """Values of an ``examples`` member: an OpenAPI 3 map of ``{value: ...}`` or a plain list."""
    if isinstance(value, dict):
        values = []
        for example in value.values():
            if isinstance(example, dict) and 'value' in example:
                values.extend(_scalars(example['value']))
        return values
    return _scalars(value)


def schema_samples(schema) -> List[Any]:
    """``example``, ``x-example``, ``enum`` and ``default`` values of a parsed schema."""
    if schema is None:
        return []
    extensions = getattr(schema, 'extensions', None) or {}
    values = _scalars(getattr(schema, 'example', None))
    values += _scalars(extensions.get('example'))
    values += _examples(extensions.get('examples'))
    values += _scalars(getattr(schema, 'enum', None))
    values += _scalars(getattr(schema, 'default', None))
    return values


def schema_comment(schema) -> Optional[str]:
    """``description`` of a parsed schema, else its ``title``."""
    if schema is None:
        return None
    return getattr(schema, 'description', None) or getattr(schema, 'title', None)


def raw_parameter_samples(raw: Optional[dict]) -> List[Any]:
    """Example values of a raw parameter dict (OpenAPI 3 ``example`` / ``examples``, swagger 2
    ``x-example`` / ``enum`` / ``default`` at the parameter level)."""
    if not isinstance(raw, dict):
        return []
    values = _scalars(raw.get('example')) + _examples(raw.get('examples')) + _scalars(raw.get('x-example'))
    values += _scalars(raw.get('enum')) + _scalars(raw.get('default'))
    return values


def flatten_example(value, prefix: str) -> Iterable[Tuple[str, Any]]:
    """``(field path, scalar)`` pairs of an example document, named like ``resolve_fields``
    (list items share the name of the list)."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield from flatten_example(item, f"{prefix}.{key}")
    elif isinstance(value, list):
        for item in value:
            yield from flatten_example(item, prefix)
    elif isinstance(value, SCALARS):
        yield prefix, value


def _norm_field(name: str) -> str:
    """Field name without the empty segments ``resolve_fields`` leaves for list items."""
    return '.'.join(part for part in name.split('.') if part)

class SwaggerParser(FileParser):

    name = 'swagger'
    globs = ('*.yaml', '*.yml', '*.json')

    # properties visited per request / response body schema (each media type of each response):
    # a schema graph with fan-out yields exponentially many nested fields otherwise
    max_output_fields = 2000

    def find_files(self):
        """Candidate files, without the ones that may not be read (outside the folder through a
        symlink, not a regular file, larger than ``specs.MAX_SPEC_BYTES``)."""
        root = os.path.realpath(self.source_folder)
        allowed = []
        for path in super().find_files():
            try:
                real = os.path.realpath(path)
                info = os.stat(real)
            except OSError:
                continue
            if not specs._within(real, root) or not stat.S_ISREG(info.st_mode):
                logger.debug(f"{self.parser}: {self.relpath(path)} is not a regular file inside the folder, skipped")
                continue
            if info.st_size > specs.MAX_SPEC_BYTES:
                logger.info(f"{self.parser}: {self.relpath(path)} is larger than {specs.MAX_SPEC_BYTES} bytes, skipped")
                continue
            allowed.append(path)
        return allowed

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # document loaded by ``accept_file``, handed to the ``parse_file`` of the same path
        self._pending: Dict[str, Tuple[Any, int]] = {}

    def accept_file(self, path, text):
        """Only OpenAPI 3.x / Swagger 2.0 documents (top-level ``openapi`` / ``swagger`` key and
        ``paths``); any other YAML / JSON file is skipped silently."""
        self._pending.clear()
        if not specs.looks_like_spec(text):
            return False
        try:
            document = specs.load_document(text, path)
        except Exception as ex:
            logger.debug(f"{self.parser}: {self.relpath(path)} is not YAML / JSON: {type(ex).__name__}: {ex}")
            return False
        version = specs.detect(document)
        if version is None:
            logger.debug(f"{self.parser}: {self.relpath(path)} is not an OpenAPI 3 / Swagger 2.0 specification")
            return False
        self._pending[path] = (document, version)
        return True

    def parse_file(self, path, text):
        pending = self._pending.pop(path, None)
        if pending is None:
            document = specs.load_document(text, path)
            version = specs.detect(document)
            if version is None:
                raise ValueError('not an OpenAPI 3 / Swagger 2.0 specification')
        else:
            document, version = pending

        resolved = specs.resolve(specs.prepare(document), path, root=os.path.realpath(self.source_folder))
        if version == 2:
            resolved = specs.swagger2_to_openapi3(resolved)
        normalized = specs.normalize(resolved)

        spec = self._load_specification(normalized, self.relpath(path))
        try:
            # the resolved ($ref-free) dict: raw parameters keep their ``example`` / ``examples``
            setattr(spec, RAW_ATTR, normalized)
        except AttributeError:
            pass
        return spec

    @staticmethod
    def _load_specification(document: dict, label: str):
        """``openapi_parser`` specification of ``document``; when the whole document is rejected,
        each operation is loaded alone and the rejected ones are logged and dropped."""
        parser = _create_parser(strict_enum=False)
        try:
            return parser.load_specification(document)
        except Exception as ex:
            logger.debug(f"swagger: {label} rejected as a whole ({type(ex).__name__}: {ex}), loading operation by operation")

        spec = parser.load_specification({**document, 'paths': {}})
        methods = {method.value for method in OperationMethod}
        for url, item in document['paths'].items():
            shared = {key: value for key, value in item.items() if key not in methods}
            path = None
            for method in [key for key in item if key in methods]:
                try:
                    loaded = parser.load_specification({**document, 'paths': {url: {**shared, method: item[method]}}}).paths[0]
                except Exception as ex:
                    logger.warning(f"Failed to parse swagger operation {method.upper()} {url} in {label}: "
                                   f"{type(ex).__name__}: {ex}")
                    continue
                if path is None:
                    path = loaded
                else:
                    path.operations.extend(loaded.operations)
            if path is not None:
                spec.paths.append(path)
        return spec

    def resolve_fields(self, type, object, file, depth, budget=None):
        """Fields of a parsed schema; ``budget`` (default ``[max_output_fields]``) counts the
        visited properties of one body schema, past it the output is truncated (logged once)."""

        resolved_fields = {}

        if depth > MAX_DEPTH:
            return resolved_fields

        if budget is None:
            budget = [self.max_output_fields]

        # Object
        if hasattr(object, 'properties'):

            for prop in object.properties:

                if budget[0] <= 0:
                    if budget[0] == 0:
                        budget[0] = -1  # warn once per body schema
                        logger.info(f"{self.parser}: more than {self.max_output_fields} nested fields in a "
                                    f"{file} body schema, output truncated")
                    break
                budget[0] -= 1

                if not hasattr(prop.schema, 'items') and not hasattr(prop.schema, 'properties'):

                    resolved_fields[f"{type}.{prop.name}"] = CodeObjectField(
                        field_name=f"{type}.{prop.name}",
                        field_type=prop.schema.type.value,
                        file=file,
                        line=1,
                        comment=schema_comment(prop.schema),
                        samples=schema_samples(prop.schema)
                    )
                
                else:

                    res_fields = self.resolve_fields(prop.name, prop.schema, file, depth + 1, budget)

                    for field_name, field_data in res_fields.items():
                        resolved_fields[f"{type}.{field_name}"] = field_data
                        resolved_fields[f"{type}.{field_name}"].field_name = f"{type}.{field_name}"

        # List 
        elif hasattr(object, 'items'):

            if object.items is None:
                return resolved_fields

            res_fields = self.resolve_fields('', object.items, file, depth + 1, budget)

            for field_name, field_data in res_fields.items():
                if not field_name.strip('.'):
                    # a list of scalars: documented by the list, else by its items
                    field_data.comment = clean_comment(schema_comment(object)) or field_data.comment
                field_name = field_name.strip('.')
                resolved_fields[f"{type}.{field_name}"] = field_data
                resolved_fields[f"{type}.{field_name}"].field_name = f"{type}.{field_name}"
            
        else:
            resolved_fields[type] = CodeObjectField(
                field_name=type,
                field_type=object.type.value,
                file=file,
                line=1,
                comment=schema_comment(object),
                samples=schema_samples(object)
            )

        return resolved_fields

    @staticmethod
    def _raw_parameters(raw_spec: Optional[dict], path, method) -> Dict[Tuple[str, str], dict]:
        """Raw parameter dicts of the operation keyed by ``(in, name)`` (path level first,
        overridden by the operation level, as in OpenAPI)."""
        params: Dict[Tuple[str, str], dict] = {}
        try:
            raw_path = (raw_spec or {}).get('paths', {}).get(path.url) or {}
            raw_operation = raw_path.get(method.method.value) or {}
            for raw in list(raw_path.get('parameters') or []) + list(raw_operation.get('parameters') or []):
                if isinstance(raw, dict) and raw.get('name'):
                    params[(str(raw.get('in')), str(raw['name']))] = raw
        except (AttributeError, TypeError):
            pass
        return params

    @staticmethod
    def _add_content_examples(fields: Dict[str, CodeObjectField], content, prefix: str) -> None:
        """Scalars of the media type ``example`` / ``examples`` documents as samples of the fields."""
        documents = []
        if getattr(content, 'example', None) is not None:
            documents.append(content.example)
        for example in (getattr(content, 'examples', None) or {}).values():
            if isinstance(example, dict) and 'value' in example:
                documents.append(example['value'])
        if not documents:
            return
        by_name: Dict[str, List[Any]] = {}
        for document in documents:
            for name, value in flatten_example(document, prefix):
                by_name.setdefault(_norm_field(name), []).append(value)
        for field_name, field in fields.items():
            values = by_name.get(_norm_field(field_name))
            if values:
                field.samples = clean_samples((field.samples or []) + values)

    def _parse_operation(self, file, path, method, raw_spec: Optional[dict] = None) -> CodeObject:
        """One ``CodeObject`` for an operation (HTTP method) of ``path``."""

        summary = getattr(method, 'summary', None)
        description = getattr(method, 'description', None)
        comment = '\n'.join(text for text in (summary, description if description != summary else None) if text)

        code_object = CodeObject(
            # identity: "METHOD path"
            hash=self.identity(file, 'route', f"{method.method.name} {path.url}"),
            object_name=f"{method.method.name} {path.url}",
            object_type='route',
            parser=self.parser,
            file=file,
            line=1,
            properties={},
            fields={},
            comment=comment or None
        )

        raw_params = self._raw_parameters(raw_spec, path, method)

        code_object.properties['path'] = CodeObjectProp(
            prop_name='path',
            prop_value=path.url
        )

        code_object.properties['method'] = CodeObjectProp(
            prop_name='method',
            prop_value=method.method.name
        )

        for param in method.parameters:

            # parameters may have no schema (e.g. ``content`` instead of ``schema``)
            param_type = getattr(getattr(param, 'schema', None), 'type', None)
            param_type = getattr(param_type, 'value', param_type) or ''

            schema = getattr(param, 'schema', None)
            extensions = getattr(param, 'extensions', None) or {}
            samples = raw_parameter_samples(raw_params.get((param.location.value, param.name)))
            samples += _scalars(extensions.get('example')) + schema_samples(schema)
            # values of the items of an array parameter (``?status=a&status=b``)
            samples += schema_samples(getattr(schema, 'items', None))

            name = f"{param.location.value}.param.{param.name}"
            if name in code_object.fields:
                # operation parameters come first and override the path-level ones
                continue

            code_object.fields[name] = CodeObjectField(
                field_name=name,
                field_type=param_type,
                file=file,
                line=1,
                comment=getattr(param, 'description', None) or schema_comment(schema),
                samples=samples
            )

        if method.request_body :
            for content in method.request_body.content :

                res = self.resolve_fields('input', content.schema, file, 0)
                self._add_content_examples(res, content, 'input')

                for field_name, field in res.items():
                    code_object.fields.setdefault(field_name, field)

        if method.responses :
            for response in method.responses :
                if response.content:
                    for content in response.content :

                        res = self.resolve_fields('output', content.schema, file, 0)
                        self._add_content_examples(res, content, 'output')

                        # the first response (content) that defines a field wins
                        for field_name, field in res.items():
                            code_object.fields.setdefault(field_name, field)

        return code_object

    def build_objects(self, swagger_data) -> List[CodeObject]:

        parsed_objects: List[CodeObject] = []

        for file, file_spec in (swagger_data or {}).items():

            if file_spec is None:
                continue

            raw_spec = getattr(file_spec, RAW_ATTR, None)

            for path in file_spec.paths :

                for method in path.operations:

                    try:
                        parsed_objects.append(self._parse_operation(file, path, method, raw_spec))
                    except Exception as ex:
                        logger.error(f"Failed to parse {self.parser} operation {getattr(method.method, 'name', method.method)} {path.url} in {file}: {ex}")

        logger.info(f"For scan {self.parser} data parse {len(parsed_objects)} objects")

        return parsed_objects