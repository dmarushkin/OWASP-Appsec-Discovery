import logging
import posixpath
import re
from typing import List
import graphql

from appsec_discovery.parsers.base_parser import FileParser
from appsec_discovery.parsers.comments import is_documentation
from appsec_discovery.models import CodeObject, CodeObjectField, CodeObjectProp

logger = logging.getLogger(__name__)

def _node_line(node) -> int:
    """1-based source line of an AST node (``loc`` is kept by ``no_location=False``)."""
    loc = getattr(node, 'loc', None)
    start_token = getattr(loc, 'start_token', None)
    return getattr(start_token, 'line', None) or 1


def _named_type(type_node) -> str:
    """Name of a (possibly ``[...]``/``!``-wrapped) type reference, ``''`` if there is none."""
    while type_node is not None:
        name = getattr(type_node, 'name', None)
        if name is not None:
            return name.value
        type_node = getattr(type_node, 'type', None)
    return ''


def _comments_above(token) -> List[str]:
    """The ``#`` comment lines right above ``token``: no blank line in between (a section header
    separated by one belongs to no field), not the trailing comment of the previous token."""
    comments = []
    following = token
    while following is not None and following.prev is not None and following.prev.kind == graphql.TokenKind.COMMENT:
        comment = following.prev
        if following.line - comment.line > 1:
            break               # a blank line
        before = comment.prev
        if before is not None and before.kind != graphql.TokenKind.COMMENT and before.line == comment.line:
            break               # ``a # note`` above: the trailing comment of the previous node
        comments.insert(0, comment.value)
        following = comment
    return [comment for comment in comments if is_documentation(comment.strip())]


def node_comment(node):
    """Description (``"..."``) of a node, the ``#`` comments above it and between its description
    and its name, and a ``#`` comment at the end of its last line."""
    parts = []
    loc = getattr(node, 'loc', None)
    start = getattr(loc, 'start_token', None)
    if start is not None:
        parts.extend(_comments_above(start))
    description = getattr(node, 'description', None)
    if description is not None:
        parts.append(description.value)
        name_loc = getattr(getattr(node, 'name', None), 'loc', None)
        if name_loc is not None:
            parts.extend(_comments_above(name_loc.start_token))
    end = getattr(loc, 'end_token', None)
    following = getattr(end, 'next', None)
    if (following is not None and following.kind == graphql.TokenKind.COMMENT and following.line == end.line
            and is_documentation(following.value.strip())):
        parts.append(following.value)
    return '\n'.join(part.strip() for part in parts if part and part.strip()) or None


def _default(node):
    value = getattr(node, 'default_value', None)
    return graphql.print_ast(value) if value is not None else None


def _nodes(value):
    """Optional node lists: graphql-core 3.2 gives ``()``/``[]``, 3.3 gives ``None``."""
    return value or ()


def _samples(default, type_name, types):
    """Example values of a leaf: its default value, then the values of its enum type."""
    values = [default] if default is not None else []
    values += (types.get(type_name) or {}).get('values') or []
    return values or None


ROOT_KINDS = ('query', 'mutation', 'subscription')
NAMESPACE_NAME = re.compile(r'(Quer(y|ies)|Mutations?|Subscriptions?|Namespace|Api)$')
OBJECT_KINDS = ('object_type_definition', 'object_type_extension', 'interface_type_definition',
                'interface_type_extension')
# definitions that a single schema has once: the same name defined (not extended) in two
# directories means two schemas (two services of a monorepo); scalars are often repeated
CONFLICTING_KINDS = ('object_type_definition', 'interface_type_definition', 'input_object_type_definition',
                     'enum_type_definition', 'union_type_definition')


class GraphqlParser(FileParser):
    """GraphQL SDL (``*.graphql``, ``*.gql``) -> one object per operation (resolver).

    Schemas: the files of a directory are one schema, and a directory joins the schema of its
    parent unless both define (not extend) a type of the same name, so a schema split over
    subdirectories is one schema while two services of a monorepo (``svc-a/schema.graphql`` and
    ``svc-b/schema.graphql``, each with its ``type Query`` and ``type User``) are two. A type
    defined in only one schema (shared ``common/`` types) is visible to all of them.

    Operations are the fields of the root types: only those declared in ``schema { ... }`` when
    the schema has one (a business ``type Subscription`` is then an entity), else ``Query`` /
    ``Mutation`` / ``Subscription`` (a ``Subscription`` used as a field type is an entity even then),
    and the fields of *namespace* types: object types
    reached from a root (or another namespace) by an argument-less field and referenced from
    nowhere else, e.g. ``Mutation.wallet: WalletMutations`` + ``type WalletMutations { create(...) }``
    gives ``WalletMutations.create`` (object_type ``mutation``). Fields of types extended with ``extend type``
    (resolvers added to an entity, e.g. ``extend type Client { accounts(...) }``) are operations
    too, always of kind query (whatever returns the entity). The kind (query / mutation /
    subscription) of other operations comes from the root they are reached from. Fields: the
    arguments by name (``id``, ``input.card.number`` for ``input: CardInput``; an argument named
    ``output`` is ``input.output``, not to clash with the result), and the result,
    flattened less deep (up to 5 levels, ``output.a.b.c.d.e``; each object type expanded once, at its shallowest place); directives of the operation (``@skipAuthenticate``)
    are kept in the ``directives`` property.
    """

    name = 'graphql'
    globs = ('*.graphql', '*.gql')
    # types/messages of one file are used by objects of other files
    objects_span_files = True

    # nesting levels flattened below an argument / the result, and the cap of visited fields
    # per argument / result (guards against combinatorial explosion of big response graphs)
    max_input_depth = 7
    max_output_depth = 4            # 5 levels: output.a.b.c.d.e
    max_resolved_fields = 2000

    def accept_file(self, path, text):
        return bool(text.strip())      # empty files are skipped silently

    def parse_file(self, path, text):
        return graphql.parse(text, no_location=False)

    def expansion_points(self, type_name, types_dict, max_depth):
        """For a result: ``{object type: field path}`` where each type is expanded, its shallowest
        occurrence (the first in field order at that depth, breadth first). Elsewhere in the
        result the type stays a leaf, so a type repeated all over a big response graph
        (``Person``, ``Issue``) is listed once instead of once per occurrence."""
        chosen = {type_name: ()}
        level = [(type_name, ())]
        depth = 0
        while level and depth < max_depth:
            nxt = []
            for current, path in level:
                for field_name, field in types_dict[current]['fields'].items():
                    out = field['output']
                    if out in types_dict and types_dict[out]['fields'] and out not in chosen:
                        chosen[out] = path + (field_name,)
                        nxt.append((out, path + (field_name,)))
            level = nxt
            depth += 1
        return chosen

    def resolve_fields(self, type_name, types_dict, depth, path: tuple, budget=None, max_depth=None,
                       expand_at=None, field_path=()):
        """Flatten ``type_name`` fields into ``{'a.b.c': {...}}`` down to ``max_depth``.

        ``path`` holds the types on the way from the root (cycle guard); it is a tuple,
        so expanding one field does not prevent its siblings of the same type from
        being expanded. ``expand_at`` (results, see ``expansion_points``): a type is
        expanded only at its chosen field path, elsewhere it is a leaf.
        """

        max_depth = self.max_input_depth if max_depth is None else max_depth
        resolved_fields = {}

        if depth > max_depth:
            return resolved_fields

        if budget is None:
            budget = [self.max_resolved_fields]

        for field_name, field in types_dict[type_name]['fields'].items():

            if budget[0] <= 0:
                if budget[0] == 0:
                    budget[0] = -1  # warn once per root
                    logger.info(f"{self.parser}: more than {self.max_resolved_fields} nested fields visited under "
                                f"{path[0] if path else type_name}, output truncated")
                break

            # every visited field counts, not only leaves: a deep schema whose nested
            # fields are all object types would otherwise never use up the budget
            budget[0] -= 1

            out_type = field['output']

            here = field_path + (field_name,)
            if (out_type in types_dict and types_dict[out_type]['fields'] and out_type not in path
                    and depth < max_depth and (expand_at is None or expand_at.get(out_type) == here)):

                out_resolved = self.resolve_fields(out_type, types_dict, depth + 1, path + (out_type,), budget,
                                                   max_depth, expand_at, here)

                for out_field_name, out_field in out_resolved.items():
                    resolved_fields[f"{field_name}.{out_field_name}"] = out_field

            else:

                resolved_fields[f"{field_name}"] = {
                    'type': out_type,
                    'file': field['file'],
                    'line': field['line'],
                    'comment': field.get('comment'),
                    'samples': _samples(field.get('default'), out_type, types_dict),
                }

        return resolved_fields

    # -- schema ----------------------------------------------------------------------------------

    @staticmethod
    def _defined_names(file_gql, kinds=CONFLICTING_KINDS):
        return {d.name.value for d in _nodes(getattr(file_gql, 'definitions', None))
                if d.kind in kinds and getattr(d, 'name', None) is not None}

    def _schema_groups(self, gql_data) -> List[List[str]]:
        """Files grouped by schema (see the class docstring), in ``gql_data`` order.

        Every directory starts as its own group; deepest directories first (then by name),
        a group is merged into its parent directory's group unless the two define a type of
        the same name. Deterministic: the first sibling (by name) joins the parent."""
        parent_of = {}                              # union-find over directories
        names = {}                                  # group root dir -> defined type names

        def find(d):
            while parent_of[d] != d:
                d = parent_of[d]
            return d

        def add_dir(d):
            if d not in parent_of:
                parent_of[d] = d
                names[d] = set()

        for file, file_gql in gql_data.items():
            d = posixpath.dirname(file) or '/'
            add_dir(d)
            names[find(d)] |= self._defined_names(file_gql)
        # the ancestors too: siblings meet in a directory without schema files of its own
        for d in list(parent_of):
            while d != posixpath.dirname(d):
                d = posixpath.dirname(d)
                add_dir(d)

        for d in sorted(parent_of, key=lambda d: (-d.count('/'), d)):
            up = posixpath.dirname(d)
            if up == d:
                continue
            child, parent = find(d), find(up)
            if child != parent and not names[child] & names[parent]:
                parent_of[child] = parent
                names[parent] |= names.pop(child)

        groups: dict = {}
        for file in gql_data:
            groups.setdefault(find(posixpath.dirname(file) or '/'), []).append(file)
        return list(groups.values())

    def _collect(self, gql_data):
        types, extended, roots = {}, set(), {}
        has_schema = False
        for file, file_gql in (gql_data or {}).items():
            for type_def in _nodes(getattr(file_gql, 'definitions', None)):
                if type_def.kind in ('schema_definition', 'schema_extension'):
                    has_schema = True
                    for op in _nodes(getattr(type_def, 'operation_types', None)):
                        roots[op.operation.value] = op.type.name.value
                    continue
                if not hasattr(type_def, 'name') or type_def.name is None:
                    continue
                type_name = type_def.name.value
                if type_def.kind.endswith('_extension'):
                    extended.add(type_name)
                entry = types.setdefault(type_name, {
                    'name': type_name, 'type': type_def.kind.replace('_extension', '_definition'),
                    'file': file, 'line': _node_line(type_def), 'fields': {},
                })
                if not type_def.kind.endswith('_extension'):
                    entry['comment'] = entry.get('comment') or node_comment(type_def)
                for value_def in _nodes(getattr(type_def, 'values', None)):        # enum values
                    entry.setdefault('values', []).append(value_def.name.value)
                for field_def in _nodes(getattr(type_def, 'fields', None)):
                    if getattr(field_def, 'name', None) is None:
                        continue
                    field = entry['fields'].setdefault(field_def.name.value, {
                        'name': field_def.name.value, 'file': file, 'line': _node_line(field_def),
                        'inputs': {}, 'output': _named_type(field_def.type),
                        'directives': [f"@{d.name.value}" for d in _nodes(getattr(field_def, 'directives', None))],
                        'comment': node_comment(field_def), 'default': _default(field_def),
                        'input_docs': {},
                    })
                    for input_def in _nodes(getattr(field_def, 'arguments', None)):
                        if getattr(input_def, 'name', None) is not None and input_def.name.value not in field['inputs']:
                            field['inputs'][input_def.name.value] = _named_type(input_def.type)
                            field['input_docs'][input_def.name.value] = {
                                'comment': node_comment(input_def), 'default': _default(input_def), 'line': _node_line(input_def)}
        if not has_schema:
            # no ``schema { ... }``: the default names are the roots (GraphQL spec), except a
            # ``type Subscription`` used as a field type somewhere - then it is a business entity
            # (e.g. a client's product subscription), not the subscription root
            roots = {kind: kind.capitalize() for kind in ROOT_KINDS}
            used_as_type = {f['output'] for t in types.values() for f in t['fields'].values()}
            if 'Subscription' in used_as_type:
                roots.pop('subscription')
        # with ``schema { ... }`` only the declared operation types are roots
        return types, extended, {kind: name for kind, name in roots.items() if name in types}

    @staticmethod
    def _namespace_like(type_name, types, extended) -> bool:
        """A namespace, not a data type: extended (``type X`` + ``extend type X {...}``), named
        like one (``...Mutations``, ``...Queries``, ``...Namespace``) or mostly fields with
        arguments (resolvers)."""
        if type_name in extended or NAMESPACE_NAME.search(type_name):
            return True
        fields = types[type_name]['fields'].values()
        return sum(1 for f in fields if f['inputs']) * 2 > len(fields)

    @classmethod
    def _namespaces(cls, types, roots, extended=frozenset()):
        """``{namespace type: kind}``: object types reached by an argument-less field of a root
        or namespace, used nowhere else and namespace-like (see ``_namespace_like``); a
        fixpoint, so nested namespaces are found."""
        parents = {}
        for type_name, type_dict in types.items():
            if type_dict['type'] not in OBJECT_KINDS:
                continue
            for field in type_dict['fields'].values():
                parents.setdefault(field['output'], set()).add(type_name)
        root_names = set(roots.values())
        namespaces = {}
        inherited = {}          # namespace -> directives of the fields leading to it (e.g. auth)
        changed = True
        while changed:
            changed = False
            for kind, root in roots.items():
                queue = [(root, kind)]
                seen = {root}
                while queue:
                    current, current_kind = queue.pop()
                    for field in types[current]['fields'].values():
                        out = field['output']
                        if (field['inputs'] or out in root_names or out not in types or out in seen
                                or types[out]['type'] not in OBJECT_KINDS or not types[out]['fields']):
                            continue
                        if not parents.get(out, set()) <= root_names | set(namespaces) | {current}:
                            continue
                        if not cls._namespace_like(out, types, extended):
                            continue
                        seen.add(out)
                        if namespaces.get(out) is None:
                            namespaces[out] = current_kind
                            inherited[out] = inherited.get(current, []) + field['directives']
                            changed = True
                        queue.append((out, namespaces[out]))
        return namespaces, inherited

    def _operations(self, types, extended, roots):
        """``[(parent type, field name, kind, directives inherited from the namespace path)]``."""
        namespaces, inherited = self._namespaces(types, roots, extended)
        root_kind = {name: kind for kind, name in roots.items()}
        ops, seen = [], set()

        def add(type_name, kind):
            for field_name, field in types[type_name]['fields'].items():
                if field['output'] in namespaces and not field['inputs']:
                    continue            # the namespace's own fields are the operations
                if (type_name, field_name) not in seen:
                    seen.add((type_name, field_name))
                    ops.append((type_name, field_name, kind, inherited.get(type_name, [])))

        for kind, root in roots.items():
            add(root, kind)
        for namespace, kind in namespaces.items():
            add(namespace, kind)
        for type_name in types:
            if type_name in extended and type_name not in root_kind and type_name not in namespaces \
                    and types[type_name]['type'] in OBJECT_KINDS:
                # field resolvers of an entity: always 'query', the kind is part of the identity
                # and must not change when e.g. a mutation returning the entity is added
                add(type_name, 'query')
        return ops, root_kind

    # -- objects ---------------------------------------------------------------------------------

    def _schemas(self, gql_data):
        """``[(types, extended, roots)]``, one per schema group; a type defined in a single
        schema (and not its root) is added to the other schemas that lack it."""
        gql_data = gql_data or {}
        schemas = []
        for files in self._schema_groups(gql_data):
            schemas.append(self._collect({file: gql_data[file] for file in files}) + (files,))
        if len(schemas) > 1:
            owners = {}
            for types, _, roots, files in schemas:
                own = set().union(*(self._defined_names(gql_data[f], CONFLICTING_KINDS + (
                    'scalar_type_definition',)) for f in files)) - set(roots.values())
                for name in own:
                    owners.setdefault(name, []).append(types)
            for types, _, _, _ in schemas:
                for name, [owner] in ((n, o) for n, o in owners.items() if len(o) == 1):
                    if owner is not types and name not in types:
                        types[name] = owner[name]
        return [schema[:3] for schema in schemas]

    def build_objects(self, gql_data) -> List[CodeObject]:

        parsed_objects: List[CodeObject] = []
        for types, extended, roots in self._schemas(gql_data):
            parsed_objects.extend(self._schema_objects(types, extended, roots))

        logger.info(f"For scan {self.parser} data parse {len(parsed_objects)} objects")

        return parsed_objects

    def _schema_objects(self, types, extended, roots) -> List[CodeObject]:

        operations, root_kind = self._operations(types, extended, roots)
        parsed_objects: List[CodeObject] = []

        for type_name, field_name, kind, inherited in operations:

            field = types[type_name]['fields'][field_name]
            gql_name = field_name if type_name in root_kind else f"{type_name}.{field_name}"

            result_fields = {}

            for input_name, input_type in field['inputs'].items():
                doc = field['input_docs'].get(input_name, {})
                # arguments are named as they are (``id``), but ``output`` is the result's key
                key = 'input.output' if input_name == 'output' else input_name
                if input_type in types and types[input_type]['fields']:
                    inputs_resolved = self.resolve_fields(input_type, types, 0, (input_type,),
                                                          max_depth=self.max_input_depth)
                    for input_resolved_name, input_resolved in inputs_resolved.items():
                        result_fields.setdefault(f"{key}.{input_resolved_name}", input_resolved)
                else:
                    result_fields[key] = {
                        'type': input_type, 'file': field['file'], 'line': doc.get('line', field['line']),
                        'comment': doc.get('comment'), 'samples': _samples(doc.get('default'), input_type, types)}

            if field['output'] in types and types[field['output']]['fields']:
                expand_at = self.expansion_points(field['output'], types, self.max_output_depth)
                outputs_resolved = self.resolve_fields(field['output'], types, 0, (field['output'],),
                                                       max_depth=self.max_output_depth, expand_at=expand_at)
                for output_resolved_name, output_resolved in outputs_resolved.items():
                    result_fields[f"output.{output_resolved_name}"] = output_resolved
            else:
                result_fields["output"] = {'type': field['output'], 'file': field['file'], 'line': field['line'],
                                           'samples': _samples(None, field['output'], types)}

            properties = {}
            # the namespace path's directives apply too (e.g. `wallet: WalletMutations! @auth`)
            directives = list(dict.fromkeys(inherited + field['directives']))
            if directives:
                properties['directives'] = CodeObjectProp(prop_name='directives', prop_value=' '.join(directives),
                                                          file=field['file'], line=field['line'])

            code_object = CodeObject(
                # identity: Type.field; the name has no kind word (the kind is the object type)
                hash=self.identity(field['file'], kind, f"{type_name}.{field_name}"),
                object_name=gql_name,
                object_type=kind,
                parser=self.parser,
                file=field['file'],
                line=field['line'],
                properties=properties,
                fields={},
                comment=field.get('comment'),
            )

            for result_field_name, result_field in result_fields.items():
                code_object.fields[result_field_name] = CodeObjectField(
                    field_name=result_field_name,
                    field_type=result_field['type'],
                    file=result_field['file'],
                    line=result_field['line'],
                    comment=result_field.get('comment'),
                    samples=result_field.get('samples'),
                )

            parsed_objects.append(code_object)

        return parsed_objects
