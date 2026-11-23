"""GraphQL operations of JS / TS clients (``gql`...``` tagged templates).

Every ``gql`...``` template in ``.js/.jsx/.ts/.tsx/.mjs/.cjs`` files is extracted (``${...}``
interpolations, usually fragments, are skipped) and parsed with graphql-core. Each root field of
a query / mutation / subscription (a resolver call) becomes one object:

* ``input.<arg>`` (``input.<arg>.<key>`` for object values): the arguments the client sends,
  typed from the operation's variable definitions (``ID!``, ``CardInput``) or ``literal``;
* ``output.<a>.<b>``: the requested selection, fragment spreads (from any file) and inline
  fragments included; leaves have type ``selection`` (a client has no schema).

Comments: the JS comment above the template and the ``#`` comments of the operation / root
field (object), the ``#`` comments of selections (fields). Samples: literal argument values
and the defaults of the operation variables.

The identity and properties are those of the former semgrep parser, so stored objects and
decisions keep their keys. The name is ``<request>.<resolver>`` (formerly ``JS GQL Resolver
<resolver> in <kind> <request>``; the kind is ``object_type`` ``js-gql-<kind>``).
"""

import logging
import re
from typing import Dict, List

import graphql

from appsec_discovery.models import CodeObject, CodeObjectField, CodeObjectProp
from appsec_discovery.parsers.base_parser import FileParser
from appsec_discovery.parsers.comments import leading_comment
from appsec_discovery.parsers.graphql.parser import node_comment

logger = logging.getLogger(__name__)

GQL_TAG = re.compile(r"\bgql\s*`")


def gql_templates(text: str):
    """``(line, body)`` of every ``gql`...``` template; ``${...}`` replaced by a blank."""
    for match in GQL_TAG.finditer(text):
        i, out, depth = match.end(), [], 0
        line = text.count('\n', 0, match.start()) + 1
        while i < len(text):
            char = text[i]
            if depth:
                depth += {'{': 1, '}': -1}.get(char, 0)
                i += 1
                continue
            if char == '\\':
                out.append(text[i:i + 2])
                i += 2
                continue
            if char == '`':
                yield line, ''.join(out)
                break
            if text.startswith('${', i):
                depth = 1
                out.append(' ')
                i += 2
                continue
            out.append(char)
            i += 1


def _type_name(type_node) -> str:
    return graphql.print_ast(type_node) if type_node is not None else ''


class JsGqlParser(FileParser):

    name = 'javascript'
    globs = ('*.js', '*.jsx', '*.ts', '*.tsx', '*.mjs', '*.cjs')
    prune_dirs = frozenset({'node_modules', 'vendor', 'dist', 'coverage', '.next'})
    # fragments are defined in other files than the operations using them
    objects_span_files = True

    max_output_depth = 8
    max_output_fields = 2000

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._lines: Dict[str, List[str]] = {}

    def accept_file(self, path, text):
        return 'gql' in text and GQL_TAG.search(text) is not None

    def parse_file(self, path, text):
        self._lines[self.relpath(path)] = text.splitlines()
        documents = []
        for line, body in gql_templates(text):
            try:
                documents.append((line, body, graphql.parse(body)))
            except graphql.GraphQLError as e:
                logger.debug(f"{self.parser}: skip an unparsable gql template at {path}:{line}: {e.message}")
        return documents

    # -- fields ----------------------------------------------------------------------------------

    def _argument_fields(self, field_node, variables: Dict[str, tuple]) -> Dict[str, tuple]:
        """``{'input.<arg>[.<key>]': (type, samples)}`` of the resolver's arguments."""
        result = {}

        def walk(prefix, value):
            kind = value.kind
            if kind == 'variable':
                type_, default = variables.get(value.name.value, ('variable', None))
                samples = (result.get(prefix, (None, None))[1] or []) + ([default] if default is not None else [])
                result[prefix] = (type_, samples or None)
            elif kind == 'object_value':
                if not value.fields:
                    result[prefix] = ('object', None)
                for item in value.fields:
                    walk(f"{prefix}.{item.name.value}", item.value)
            elif kind == 'list_value':
                if not value.values:
                    result[prefix] = ('list', None)
                for item in value.values:
                    walk(prefix, item)
            else:
                type_, samples = result.get(prefix, ('literal', []))
                result[prefix] = (type_ if type_ != 'variable' else 'literal', (samples or []) + [graphql.print_ast(value)])

        for argument in field_node.arguments or ():
            walk(f"input.{argument.name.value}", argument.value)
        return result

    def _selection_fields(self, selection_set, fragments, prefix='output', depth=0, seen=(), budget=None) -> Dict[str, tuple]:
        """``{'output.a.b': ('selection', comment)}`` of a selection set, fragments expanded."""
        budget = budget if budget is not None else [self.max_output_fields]
        result = {}
        for selection in (selection_set.selections if selection_set else ()):
            if budget[0] <= 0:
                break
            if selection.kind == 'field':
                key = f"{prefix}.{selection.alias.value if selection.alias else selection.name.value}"
                budget[0] -= 1
                if selection.selection_set and depth < self.max_output_depth:
                    nested = self._selection_fields(selection.selection_set, fragments, key, depth + 1, seen, budget)
                    _merge(result, nested or {key: ('selection', node_comment(selection))})
                else:
                    _merge(result, {key: ('selection', node_comment(selection))})
            elif selection.kind == 'fragment_spread':
                name = selection.name.value
                fragment = fragments.get(name)
                if fragment is not None and name not in seen:
                    _merge(result, self._selection_fields(fragment.selection_set, fragments, prefix, depth,
                                                          seen + (name,), budget))
            elif selection.kind == 'inline_fragment':
                _merge(result, self._selection_fields(selection.selection_set, fragments, prefix, depth, seen, budget))
        return result

    # -- objects ---------------------------------------------------------------------------------

    def build_objects(self, parsed) -> List[CodeObject]:
        fragments: Dict[str, graphql.language.FragmentDefinitionNode] = {}
        for documents in (parsed or {}).values():
            for _, _, doc in documents or ():
                for definition in doc.definitions:
                    if definition.kind == 'fragment_definition':
                        fragments.setdefault(definition.name.value, definition)

        objects: Dict[str, CodeObject] = {}
        for file, documents in (parsed or {}).items():
            for line, body, doc in documents or ():
                for definition in doc.definitions:
                    if definition.kind == 'operation_definition':
                        self._add_operation(objects, file, line, body, definition, fragments)

        result = list(objects.values())
        logger.info(f"For scan {self.parser} data parse {len(result)} objects")
        return result

    def _add_operation(self, objects, file, line, body, operation, fragments) -> None:
        kind = operation.operation.value
        request_name = operation.name.value if operation.name else 'anonymous'
        variables = {v.variable.name.value: (_type_name(v.type), graphql.print_ast(v.default_value)
                                             if v.default_value is not None else None)
                     for v in operation.variable_definitions or ()}
        template_comment = leading_comment(self._lines.get(file, ()), line, trailing=False)

        for selection in operation.selection_set.selections:
            if selection.kind != 'field':
                continue
            field_name = selection.name.value
            resolver_name = f"{selection.alias.value}: {field_name}" if selection.alias else field_name
            object_type = f"js-gql-{kind}"
            # identity: request and resolver names, not the raw query text
            obj_hash = self.identity(file, object_type, f"{request_name}.{resolver_name}")

            fields = {name: (type_, None, samples)
                      for name, (type_, samples) in self._argument_fields(selection, variables).items()}
            if selection.selection_set:
                fields.update({name: (type_, comment, None) for name, (type_, comment)
                               in self._selection_fields(selection.selection_set, fragments).items()})
            else:
                fields['output'] = ('selection', None, None)

            if obj_hash in objects:
                # the same resolver once more in the file (two anonymous ``query { me {...} }``,
                # one operation name in two templates): one object, the first one's identity,
                # name and properties, with the fields and samples of both selections
                _merge_object(objects[obj_hash], fields, file, line)
                continue
            comment = '\n'.join(filter(None, (template_comment, node_comment(operation), node_comment(selection))))

            loc = selection.loc
            resolver_text = body[loc.start:loc.end] if loc is not None else field_name
            code_object = CodeObject(
                hash=obj_hash, object_name=f"{request_name}.{resolver_name}",
                object_type=object_type, parser=self.parser, file=file, line=line, properties={}, fields={},
                comment=comment or None,
            )
            for prop, value in (('request_name', request_name), ('request_text', body.strip()),
                                ('resolver_name', resolver_name), ('resolver_text', resolver_text)):
                code_object.properties[prop] = _prop(prop, value, file, line)
            for name, (type_, field_comment, samples) in fields.items():
                code_object.fields[name] = CodeObjectField(field_name=name, field_type=type_, file=file, line=line,
                                                           comment=field_comment, samples=samples)
            objects[obj_hash] = code_object


def _merge(result: Dict[str, tuple], fields: Dict[str, tuple]) -> None:
    """Add selected fields; a field selected twice (directly and through a fragment) keeps the
    comment one of the selections has."""
    for key, (type_, comment) in fields.items():
        result[key] = (type_, comment or (result.get(key) or (None, None))[1])


def _merge_object(code_object: CodeObject, fields: Dict[str, tuple], file, line) -> None:
    """Add the fields (and samples) of another occurrence of the same resolver to its object."""
    for name, (type_, field_comment, samples) in fields.items():
        existing = code_object.fields.get(name)
        if existing is None:
            code_object.fields[name] = CodeObjectField(field_name=name, field_type=type_, file=file, line=line,
                                                       comment=field_comment, samples=samples)
            continue
        if samples:
            merged = list(existing.samples or [])
            merged += [sample for sample in samples if sample not in merged]
            existing.samples = merged
        if field_comment and not existing.comment:
            existing.comment = field_comment


def _prop(name, value, file, line):
    return CodeObjectProp(prop_name=name, prop_value=value, file=file, line=line)
