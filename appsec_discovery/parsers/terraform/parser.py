"""Terraform (``*.tf``, ``*.tf.json``) -> one object per top-level block.

Native parser (no semgrep): ``hcl.parse`` recovers the blocks and attributes of each file.

* ``resource "type" "name"`` -> object_type ``resource``, name ``type.name``, props type/name;
* ``data "type" "name"`` -> ``data``, ``type.name``, props type/name;
* ``module "name"`` -> ``module``, ``name``, props source/version;
* ``variable`` / ``output`` / ``provider`` (``name.alias`` when aliased) -> ``x``.

Object names never contain the type word (it is ``object_type``); the identity is
``object_type`` + the logical name (the object name), so a resource and a data source with the
same address are distinct objects with the same name.

Fields are the attributes of the block, nested blocks flattened as ``block.attr`` (repeated nested
blocks are merged; ``dynamic "x" { content { a = ... } }`` gives ``x.a``). ``field_type`` is the
kind of the value: string / number / bool / list / map / reference / expression.

Comments: ``#`` / ``//`` / ``/* */`` above a block (object) and above or at the end of an
attribute line (field); the ``description`` of a variable / output comes first. Samples: literal
values (strings, numbers, bools, literal list items) - never for secrets: attributes or nested
blocks named like a password / token / key, the ``value`` of a ``name = "DB_PASSWORD"`` /
``value = ...`` pair (k8s ``env``, helm ``set``), the ``default`` / ``value`` of a variable / output
named so or marked ``sensitive = true`` (with everything under it: ``default.pw``), and values that
look like credentials (``models.secrets``: PEM blocks, URLs with a password, connection strings,
``Authorization`` headers, JWTs, long base64 blobs, well-known token prefixes). Fields that may hold a
secret are listed in the ``sensitive_fields`` property (tags are recomputed by scoring, a
property is not).

Compatibility with the former semgrep parser: a ``module "x"`` block with one of the ``vm_*``
attributes it tracked (string values) is an object_type ``vm`` object
named ``x[.<vm_domain>]`` (formerly ``Virtual machine x[...]``) with the same identity (``vm`` + the module name), line and
``vm_*`` properties as before (no ``sensitive_fields``), so stored objects and decisions keep their
keys; it has fields like any module.
"""
import json
import logging
import re
from collections import Counter
from typing import Dict, Iterable, List, Optional, Tuple

from appsec_discovery.models import CodeObject, CodeObjectField, CodeObjectProp
from appsec_discovery.models.code_object import SAMPLES_MAX
from appsec_discovery.models.secrets import is_secret_name as common_secret_name, looks_like_secret
from appsec_discovery.parsers.base_parser import FileParser
from appsec_discovery.parsers.comments import leading_comment
from appsec_discovery.parsers.common import DEFAULT_PRUNE_DIRS
from appsec_discovery.parsers.terraform import hcl

logger = logging.getLogger(__name__)

# attributes of a vm module, as tracked by the former semgrep rules (property name = attribute name)
VM_PROPS = ('vm_name', 'vm_domain', 'vm_template', 'vm_pool', 'vm_desc', 'vm_server_cluster_name',
            'vm_server_role', 'vm_server_owning_team', 'vm_server_maintaining_team', 'vm_prometheus_env',
            'vlan_id', 'dc')

# the attributes that hold the value of a ``sensitive = true`` variable / output
SENSITIVE_VALUES = ('default', 'value')

KINDS = ('resource', 'data', 'module', 'variable', 'output', 'provider')

# terraform names that hold key material besides the common credential names
# (``tls_cert``, ``ssh_key``, ``key = file(...)``): the common checks are ``models.secrets``
TF_SECRET_NAME = re.compile(r'cert|key$', re.IGNORECASE)
# a ``name = "..." value = "..."`` pair (k8s ``env``, helm ``set``, ECS ``environment``): the value is
# a secret when the name says so
PAIR_NAME, PAIR_VALUES = 'name', ('value',)

MAX_FILE_BYTES = 10 * 1024 * 1024


def is_secret_name(name: str) -> bool:
    return common_secret_name(name) or bool(TF_SECRET_NAME.search(name))


def looks_secret(value: str) -> bool:
    return looks_like_secret(value)


class _Field:
    __slots__ = ('name', 'type', 'line', 'comment', 'samples', 'secret')

    def __init__(self, name, field_type, line, comment, secret):
        self.name, self.type, self.line, self.comment, self.secret = name, field_type, line, comment, secret
        self.samples: List[str] = []

    def add_samples(self, values: Iterable[str]) -> None:
        if self.secret:         # a repeated block made it a secret (``env`` with a password name)
            return
        for value in values:
            if len(self.samples) >= SAMPLES_MAX:
                return
            if value not in self.samples and not looks_secret(value):
                self.samples.append(value)


class TerraformParser(FileParser):

    name = 'terraform'
    globs = ('*.tf', '*.tf.json')
    prune_dirs = DEFAULT_PRUNE_DIRS | {'.terraform'}
    # generated ``*.tf.json`` can be large; bigger files are skipped unread by ``FileParser``
    max_file_bytes = MAX_FILE_BYTES

    def parse_file(self, path: str, text: str) -> List[CodeObject]:
        rel = self.relpath(path)
        if path.endswith('.json'):
            return self._json_objects(rel, text)
        lines = text.splitlines()
        objects = []
        for block in hcl.parse(text):
            try:
                obj = self._block_object(rel, lines, block)
            except Exception as ex:     # one odd block never loses the file
                logger.debug(f"terraform: block {block.type} {block.labels} of {rel}:{block.line} failed: {ex}")
                continue
            if obj is not None:
                objects.append(obj)
        return objects

    def build_objects(self, parsed: dict) -> List[CodeObject]:
        objects: Dict[str, CodeObject] = {}
        for rel in sorted(parsed):
            for obj in parsed[rel] or []:
                objects.setdefault(obj.hash, obj)       # a duplicated block: the first one wins
        logger.info(f"terraform: {len(parsed)} files, {len(objects)} objects")
        return list(objects.values())

    # -- HCL ----------------------------------------------------------------------------------

    def _block_object(self, rel: str, lines: List[str], block: hcl.Block) -> Optional[CodeObject]:
        kind, labels = block.type, block.labels
        if kind not in KINDS or not labels or (kind in ('resource', 'data') and len(labels) < 2):
            return None

        sensitive = _is_true(block.attribute('sensitive'))
        fields: Dict[str, _Field] = {}
        self._collect(lines, block.body, '', sensitive, fields)
        if kind in ('variable', 'output') and is_secret_name(labels[0]):
            _mark_secret(fields, SENSITIVE_VALUES)
        if sensitive:
            _mark_secret(fields, SENSITIVE_VALUES)

        comment = _comment(lines, block.line)
        if kind in ('variable', 'output'):
            description = _string(block.attribute('description'))
            comment = '\n'.join(dict.fromkeys(part for part in (description, comment) if part)) or None
            if 'description' in fields:
                fields['description'].samples = []
            if kind == 'variable' and 'type' in fields:      # the type constraint: string, list(string)...
                fields['type'].samples = [hcl.expression_text(block.attribute('type').expr)]

        if kind == 'module':
            vm = self._vm_object(rel, block, fields, comment)
            if vm is not None:
                return vm

        props: Dict[str, str] = {}
        if kind in ('resource', 'data'):
            logical = f'{labels[0]}.{labels[1]}'
            props = {'type': labels[0], 'name': labels[1]}
        else:
            logical = labels[0]
            if kind == 'provider':
                alias = _string(block.attribute('alias'))
                logical = f'{logical}.{alias}' if alias else logical
            if kind == 'module':
                for prop in ('source', 'version'):
                    value = _text(block.attribute(prop))
                    if value:
                        props[prop] = value

        return self._make(rel, kind, logical, logical, block.line, comment, props, fields)

    def _vm_object(self, rel: str, block: hcl.Block, fields: Dict[str, _Field],
                   comment: Optional[str]) -> Optional[CodeObject]:
        """The ``vm`` object of the former semgrep rules: ``module "<name>"`` with string ``vm_*``
        attributes anywhere in its body (``vm_name`` counts only when it equals the module name)."""
        name = block.labels[0]
        found: List[Tuple[int, str, str]] = []
        for attr in _walk_attributes(block.body):
            if attr.name not in VM_PROPS:
                continue
            expr = [token for token in attr.expr if token.kind != 'nl']
            if len(expr) != 1 or expr[0].kind not in ('str', 'istr'):
                continue
            value = expr[0].value
            if attr.name == 'vm_name' and value != name:
                continue
            found.append((attr.line, attr.name, value))
        if not found:
            return None

        props = {'vm_name': name}
        line = found[0][0]
        for attr_line, prop, value in found:
            if value:
                props[prop] = value
            if prop == 'vm_name':
                line = attr_line
        # the name has no type word (the type is ``object_type``); the identity stays ``vm`` + module name
        object_name = f"{name}.{props['vm_domain']}" if props.get('vm_domain') else name
        return self._make(rel, 'vm', name, object_name, line, comment, props, fields)

    def _collect(self, lines: List[str], body: list, prefix: str, sensitive: bool,
                 fields: Dict[str, _Field], secret: bool = False, block_comment: Optional[str] = None,
                 iterators: frozenset = frozenset()) -> None:
        """Fields of ``body``; attributes of a nested block without a comment of their own take the
        comment of the block (unless the block is repeated: merged fields would get the comment of
        one of them), ``iterators`` are the names of the enclosing ``dynamic`` blocks."""
        segments = Counter(_segment(item) for item in body if isinstance(item, hcl.Block))
        pair_name = next((_string(item) for item in body
                          if isinstance(item, hcl.Attribute) and item.name == PAIR_NAME), None)
        pair_secret = bool(pair_name) and is_secret_name(pair_name)
        for item in body:
            if isinstance(item, hcl.Attribute):
                name = prefix + item.name
                value = hcl.classify(item.expr, iterators)
                is_secret = secret or is_secret_name(item.name) or (pair_secret and item.name in PAIR_VALUES)
                field = fields.get(name)
                if field is None:
                    comment = _comment(lines, item.line) or block_comment
                    field = fields[name] = _Field(name, value.kind, item.line, comment, is_secret)
                elif field.type != value.kind and field.type != 'expression':
                    field.type = 'expression'      # repeated nested blocks with different kinds of value
                if is_secret:
                    field.secret, field.samples = True, []
                elif not (sensitive and not prefix and item.name in SENSITIVE_VALUES):
                    field.add_samples(value.samples)
            else:
                inner_iterators = iterators
                segment = _segment(item)
                if item.type == 'dynamic' and item.labels:
                    children = []
                    iterator = item.attribute('iterator')
                    inner_iterators = iterators | {item.labels[0], hcl.expression_text(iterator.expr) if iterator else ''}
                    for child in item.body:
                        if isinstance(child, hcl.Block) and child.type == 'content':
                            children.extend(child.body)
                        else:
                            children.append(child)
                else:
                    children = item.body
                own_comment = _comment(lines, item.line) if segments[segment] == 1 else None
                self._collect(lines, children, f'{prefix}{segment}.', sensitive, fields,
                              secret or is_secret_name(item.type) or any(is_secret_name(x) for x in item.labels),
                              own_comment or block_comment, inner_iterators)

    def _make(self, rel: str, object_type: str, logical: str, object_name: str, line: int,
              comment: Optional[str], props: Dict[str, str], fields: Dict[str, _Field]) -> CodeObject:
        secret_fields = sorted(name for name, field in fields.items() if field.secret)
        if secret_fields and object_type != 'vm':      # vm objects keep exactly the former properties
            props = {**props, 'sensitive_fields': ', '.join(secret_fields)}
        return CodeObject(
            hash=self.identity(rel, object_type, logical),
            object_name=object_name,
            object_type=object_type,
            parser=self.parser,
            file=rel,
            line=line,
            comment=comment,
            properties={name: CodeObjectProp(prop_name=name, prop_value=value) for name, value in props.items()},
            fields={name: CodeObjectField(field_name=name, field_type=field.type, file=rel, line=field.line,
                                          comment=field.comment, samples=field.samples or None)
                    for name, field in fields.items()},
        )

    # -- JSON ---------------------------------------------------------------------------------

    def _json_objects(self, rel: str, text: str) -> List[CodeObject]:
        """``*.tf.json``: the same blocks in the JSON syntax (no comments, field lines = object line)."""
        try:
            data = json.loads(text)
        except ValueError as ex:
            logger.debug(f"terraform: {rel} is not valid JSON: {ex}")
            return []
        if not isinstance(data, dict):
            return []
        objects = []
        for kind in KINDS:
            section = data.get(kind)
            if not isinstance(section, dict):
                continue
            if kind in ('resource', 'data'):
                entries = [((rtype, name), body) for rtype, names in section.items() if isinstance(names, dict)
                           for name, body in names.items()]
            else:
                entries = [((name,), body) for name, body in section.items()]
            for labels, bodies in entries:
                for body in bodies if isinstance(bodies, list) else [bodies]:
                    if isinstance(body, dict):
                        objects.append(self._json_object(rel, text, kind, labels, body))
        return objects

    def _json_object(self, rel: str, text: str, kind: str, labels: tuple, body: dict) -> CodeObject:
        match = re.search(r'"%s"\s*:' % re.escape(labels[-1]), text)
        line = text.count('\n', 0, match.start()) + 1 if match else 1
        sensitive = body.get('sensitive') is True
        fields: Dict[str, _Field] = {}
        _json_fields(body, '', line, sensitive, fields)
        if kind in ('variable', 'output') and (sensitive or is_secret_name(labels[0])):
            _mark_secret(fields, SENSITIVE_VALUES)
        comment = body.get('description') if isinstance(body.get('description'), str) else None
        if kind in ('resource', 'data'):
            logical = f'{labels[0]}.{labels[1]}'
            props = {'type': labels[0], 'name': labels[1]}
        else:
            logical, props = labels[0], {}
            if kind == 'provider' and isinstance(body.get('alias'), str):
                logical = f"{logical}.{body['alias']}"
            if kind == 'module':
                props = {p: str(body[p]) for p in ('source', 'version') if isinstance(body.get(p), (str, int, float))}
        return self._make(rel, kind, logical, logical, line, comment, props, fields)


def _json_fields(body: dict, prefix: str, line: int, sensitive: bool, fields: Dict[str, _Field],
                 secret: bool = False) -> None:
    pair_name = body.get(PAIR_NAME)
    pair_secret = isinstance(pair_name, str) and is_secret_name(pair_name)
    for key, value in body.items():
        name = prefix + key
        is_secret = secret or is_secret_name(key) or (pair_secret and key in PAIR_VALUES)
        # the value of a ``sensitive`` variable / output is secret down to its leaves (``default.pw``)
        sensitive_value = sensitive and not prefix and key in SENSITIVE_VALUES
        items = value if isinstance(value, list) and value and all(isinstance(v, dict) for v in value) else None
        if isinstance(value, dict) or items:
            for nested in items or [value]:
                _json_fields(nested, f'{name}.', line, sensitive, fields, is_secret or sensitive_value)
            continue
        kind, samples = _json_value(value)
        field = fields.get(name)
        if field is None:
            field = fields[name] = _Field(name, kind, line, None, is_secret)
        if is_secret:
            field.secret, field.samples = True, []
        elif not sensitive_value:
            field.add_samples(samples)


def _mark_secret(fields: Dict[str, _Field], roots: Iterable[str]) -> None:
    """``roots`` and every field under them (``default``, ``default.pw``...) are secrets."""
    for name, field in fields.items():
        if any(name == root or name.startswith(root + '.') for root in roots):
            field.secret, field.samples = True, []


def _json_value(value) -> Tuple[str, List[str]]:
    if isinstance(value, bool):
        return 'bool', ['true' if value else 'false']
    if isinstance(value, (int, float)):
        return 'number', [str(value)]
    if isinstance(value, str):
        if '${' in value:
            return ('reference' if hcl.TEMPLATE_REFERENCE.match(value) else 'expression'), []
        return 'string', [value]
    if isinstance(value, list):
        return 'list', [_json_value(item)[1][0] for item in value
                        if isinstance(item, (str, int, float, bool)) and _json_value(item)[1]]
    return 'expression', []


# -- helpers -------------------------------------------------------------------------------------

def _segment(block: hcl.Block) -> str:
    """The field name part of a nested block: ``type.label``, the label of a ``dynamic`` block."""
    if block.type == 'dynamic' and block.labels:
        return block.labels[0]
    return '.'.join([block.type, *block.labels])


def _walk_attributes(body: list) -> Iterable[hcl.Attribute]:
    """Attributes of a body and of its nested blocks, in source order."""
    for item in body:
        if isinstance(item, hcl.Attribute):
            yield item
        else:
            yield from _walk_attributes(item.body)


def _comment(lines: List[str], line: int) -> Optional[str]:
    try:
        return leading_comment(lines, line)
    except Exception:       # documentation is best effort
        return None


def _string(attr: Optional[hcl.Attribute]) -> Optional[str]:
    """The value of a string literal attribute."""
    if attr is None:
        return None
    expr = [token for token in attr.expr if token.kind != 'nl']
    if len(expr) == 1 and expr[0].kind in ('str', 'heredoc'):
        return expr[0].value.strip() or None
    return None


def _text(attr: Optional[hcl.Attribute]) -> Optional[str]:
    """A string literal's value, else the expression text."""
    if attr is None:
        return None
    return _string(attr) or hcl.expression_text(attr.expr) or None


def _is_true(attr: Optional[hcl.Attribute]) -> bool:
    if attr is None:
        return False
    expr = [token for token in attr.expr if token.kind != 'nl']
    return len(expr) == 1 and expr[0].value == 'true'
