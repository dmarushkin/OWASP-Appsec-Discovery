import logging
import re
from typing import Dict, List, Optional, Tuple
import proto_schema_parser.parser as pb_parser
from proto_schema_parser.ast import Enum, EnumValue, Package, Service, Message, Method, Field, OneOf, MapField

from appsec_discovery.parsers.base_parser import FileParser
from appsec_discovery.parsers.comments import leading_comment, trailing_comment
from appsec_discovery.models import CodeObject, CodeObjectField

logger = logging.getLogger(__name__)

SCOPE_OPEN = re.compile(r'\b(message|enum|service|oneof|extend)\s+([\w.]+)\s*\{|\brpc\s+(\w+)|([{}])')
FIELD_DECL = re.compile(r'(?:^|;)\s*(?:repeated\s+|optional\s+|required\s+)?(?:map\s*<[^>]*>|[\w.]+)\s+(\w+)\s*=\s*\d+')


def _blank_options(lines: List[str]) -> List[str]:
    """``[...]`` field options (nested and multi-line ones too) blanked out: their braces are not scopes."""
    result, depth = [], 0
    for line in lines:
        chars = []
        for char in line:
            if char == '[':
                depth += 1
            if depth:
                chars.append(' ')
            else:
                chars.append(char)
            if char == ']' and depth:
                depth -= 1
        result.append(''.join(chars))
    return result


def proto_positions(text: str) -> Dict[tuple, int]:
    """1-based lines of the declarations of a ``.proto`` file (the proto AST has none):
    ``('message', 'Outer.Inner')``, ``('field', 'Outer.Inner', name)``, ``('rpc', 'Service', name)``.
    Comments, strings and ``[options]`` are blanked first; nesting is tracked by braces."""
    text = re.sub(r'/\*.*?\*/', lambda m: re.sub(r'[^\n]', ' ', m.group()), text, flags=re.S)
    lines = [re.sub(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', '""', re.sub(r'//.*$', '', line))
             for line in text.splitlines()]
    lines = _blank_options(lines)
    positions, stack = {}, []          # stack: (kind, name) for message / enum / service / oneof / extend / {}
    for number, line in enumerate(lines, 1):
        start = 0
        # the text between scope tokens holds the fields of the scope open at that point
        for match in list(SCOPE_OPEN.finditer(line)) + [None]:
            messages = [name for kind, name in stack if kind == 'message']
            if stack and stack[-1][0] in ('message', 'oneof') and messages:
                for k, field in enumerate(FIELD_DECL.finditer(line[start:match.start() if match else len(line)])):
                    key = ('field', '.'.join(messages), field.group(1))
                    if key not in positions:
                        positions[key] = number
                        positions[('last field', number)] = key     # a trailing comment is its own
                        if start > 0 or k > 0:
                            # after a ``message X {`` / another field on its line: the comment
                            # above the line is not this field's
                            positions[('inline',) + key[1:]] = True
            if match is None:
                break
            start = match.end()
            kind, name, rpc, brace = match.groups()
            if kind:
                stack.append((kind, name))
                if kind == 'message':
                    positions.setdefault(('message', '.'.join(messages + [name])), number)
            elif rpc:
                services = [n for k, n in stack if k == 'service']
                if services:
                    positions.setdefault(('rpc', services[-1], rpc), number)
            elif brace == '{':
                stack.append(('', ''))
            elif stack:
                stack.pop()
    return positions

class ProtobufParser(FileParser):

    name = 'protobuf'
    globs = ('*.proto',)
    # types/messages of one file are used by objects of other files
    objects_span_files = True

    def parse_file(self, path, text):
        # the source lines and declaration positions give the comments (the AST has none)
        self._sources[self.relpath(path)] = (text.splitlines(), proto_positions(text))
        return pb_parser.Parser().parse(text)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._sources: Dict[str, Tuple[List[str], Dict[tuple, int]]] = {}

    def _comment(self, file, key) -> Optional[str]:
        lines, positions = self._sources.get(file, ((), {}))
        line = positions.get(key)
        if not line:
            return None
        last = key[0] != 'field' or positions.get(('last field', line)) == key
        if positions.get(('inline',) + key[1:]):
            return trailing_comment(lines[line - 1]) if last else None
        return leading_comment(lines, line, trailing=last)

    # nesting levels flattened below a request / response message, and the cap of visited
    # fields per request / response (guards against the combinatorial explosion of a message
    # whose fields reuse the same nested messages: 8 fields x 6 levels = 8^6 leaves)
    max_depth = 5
    max_resolved_fields = 2000

    # -- name resolution (protobuf scoping rules) -------------------------------------------------

    @staticmethod
    def _resolve(type_name, scope, messages):
        """Full name of message ``type_name`` used in ``scope`` (a package or message full name):
        ``.pkg.Msg`` is absolute; otherwise the innermost scope is searched first, then its
        parents, so ``Inner``, ``Outer.Inner``, ``pkg.Msg`` and messages of other packages
        (``common.Money``) all resolve. None for scalars, enums and unknown types."""
        if not type_name:
            return None
        if type_name.startswith('.'):
            return type_name[1:] if type_name[1:] in messages else None
        parts = scope.split('.') if scope else []
        for i in range(len(parts), -1, -1):
            candidate = '.'.join(parts[:i] + [type_name])
            if candidate in messages:
                return candidate
        return None

    @staticmethod
    def _message_fields(message):
        """Fields of a message in order: plain fields, the members of ``oneof`` groups and map fields."""
        for el in message.elements:
            if isinstance(el, OneOf):
                for member in el.elements:
                    if isinstance(member, Field):
                        yield member
            elif isinstance(el, (Field, MapField)):
                yield el

    @staticmethod
    def _definition(full_name, messages, prefer_file=None):
        """``(Message, file)`` of ``full_name``; a name defined in several files (a duplicate,
        e.g. two copies of an API in one package) resolves to the copy in ``prefer_file``, the
        file of the service / message that uses it, else to the first one."""
        definitions = messages[full_name]
        for definition in definitions:
            if definition[1] == prefer_file:
                return definition
        return definitions[0]

    @staticmethod
    def _local_name(full_name, package):
        return full_name[len(package) + 1:] if package and full_name.startswith(package + '.') else full_name

    def resolve_fields(self, full_name, messages, depth=0, path=(), prefer_file=None, budget=None):
        """Flatten the fields of message ``full_name`` (``messages``: full name -> [(Message,
        file)]) into ``{'Type.field.SubType.sub': CodeObjectField}``; ``path`` holds the
        messages on the way (a recursive message is not expanded again). ``budget`` (a one-item
        list shared by the whole request / response) caps the visited fields at
        ``max_resolved_fields``; the rest is dropped with a log message."""
        message, file = self._definition(full_name, messages, prefer_file)
        type_name = message.name
        resolved_fields = {}

        if depth > self.max_depth:
            return {}

        if budget is None:
            budget = [self.max_resolved_fields]
        if budget[0] <= 0:
            return {}

        path = path + (full_name,)

        for el in self._message_fields(message):
            if budget[0] <= 0:
                if budget[0] == 0:
                    budget[0] = -1      # log once per request / response
                    logger.info(f"{self.parser}: more than {self.max_resolved_fields} nested fields visited under "
                                f"{path[0]}, output truncated")
                break
            # every visited field counts, not only leaves (see the graphql parser)
            budget[0] -= 1

            key = f"{type_name}.{el.name}"
            if any(name == key or name.startswith(key + '.') for name in resolved_fields):
                continue

            comment = self._comment(file, ('field', self._local_name(full_name, self._packages.get(full_name, '')),
                                           el.name))
            if isinstance(el, MapField):
                resolved_fields[key] = CodeObjectField(field_name=key, field_type=f"map<{el.key_type},{el.value_type}>",
                                                       file=file, line=None, comment=comment)
                continue

            target = self._resolve(el.type, full_name, messages)
            if target is not None and target not in path:
                nested = self.resolve_fields(target, messages, depth + 1, path, prefer_file=file, budget=budget)
                if nested:
                    for field_name, field in nested.items():
                        resolved_fields[f"{key}.{field_name}"] = field
                    continue
                if budget[0] <= 0:
                    continue            # truncated inside: no leaf for the half-visited message

            enum = self._resolve(el.type, full_name, self._enums)
            resolved_fields[key] = CodeObjectField(
                field_name=key,
                field_type=el.type,
                file=file,
                # the proto AST has no source positions (el.number is the field tag)
                line=None,
                comment=comment,
                # an enum field: its values (the ``0`` default, usually ``*_UNSPECIFIED``, last)
                samples=self._enums[enum] if enum else None,
            )

        if not resolved_fields and not any(True for _ in self._message_fields(message)):
            resolved_fields[type_name] = CodeObjectField(field_name=type_name, field_type='Empty', file=file, line=1)

        return resolved_fields

    def _collect_file(self, file, file_proto, packages, messages) -> None:
        """Add the services of one parsed ``.proto`` file to ``packages`` and all its messages
        (nested ones too) to ``messages`` by full name."""

        # the last ``package`` statement wins; files without one go to the '' package
        cur_package = ''
        for el in file_proto.file_elements:
            if isinstance(el, Package):
                cur_package = el.name

        package = packages.setdefault(cur_package, {'services': {}, 'service_files': {}})

        def add_enum(enum, scope):
            values = [v for v in enum.elements if isinstance(v, EnumValue)]
            self._enums.setdefault(f"{scope}.{enum.name}" if scope else enum.name,
                                   [v.name for v in sorted(values, key=lambda v: v.number == 0)])

        def add_message(message, scope):
            full_name = f"{scope}.{message.name}" if scope else message.name
            messages.setdefault(full_name, []).append((message, file))
            self._packages.setdefault(full_name, cur_package)
            for el in message.elements:
                if isinstance(el, Message):
                    add_message(el, full_name)
                elif isinstance(el, Enum):
                    add_enum(el, full_name)

        for el in file_proto.file_elements:

            if isinstance(el, Service) and el.name not in package['services']:
                package['services'][el.name] = {}
                package['service_files'][el.name] = file

                for service_method in el.elements:
                    if isinstance(service_method, Method) and service_method.name not in package['services'][el.name]:
                        package['services'][el.name][service_method.name] = {
                            'input': service_method.input_type.type,
                            'output': service_method.output_type.type
                        }

            if isinstance(el, Message):
                add_message(el, cur_package)
            elif isinstance(el, Enum):
                add_enum(el, cur_package)

    def build_objects(self, proto_data) -> List[CodeObject]:

        parsed_objects: List[CodeObject] = []

        packages = {}
        messages = {}
        self._enums: Dict[str, List[str]] = {}      # enum full name -> value names
        self._packages: Dict[str, str] = {}         # message full name -> its package

        for file, file_proto in (proto_data or {}).items():
            try:
                self._collect_file(file, file_proto, packages, messages)
            except Exception as ex:
                logger.error(f"Failed to parse {self.parser} for file {file}: {ex}")

        for package_name, package in packages.items():

            for service_name, service in package['services'].items():

                # the file that defines the service (not the first file of the package)
                service_file = package['service_files'][service_name]

                for method_name, method in service.items():

                    # gRPC path: /package.Service/Method, or /Service/Method without a package
                    full_service_name = f"{package_name}.{service_name}" if package_name else service_name
                    rpc_path = f"/{full_service_name}/{method_name}"

                    code_object = CodeObject(
                        hash=self.identity(service_file, 'rpc', rpc_path),
                        object_name=rpc_path,
                        object_type='rpc',
                        parser=self.parser,
                        file=service_file,
                        line=self._sources.get(service_file, ((), {}))[1].get(('rpc', service_name, method_name), 1),
                        properties={},
                        fields={},
                        comment=self._comment(service_file, ('rpc', service_name, method_name)),
                    )

                    for side in ('input', 'output'):
                        target = self._resolve(method[side], package_name, messages)
                        if target is not None:
                            for field_name, field in self.resolve_fields(target, messages,
                                                                         prefer_file=service_file).items():
                                # field_name is the full path, like the dict key (as for every
                                # parser): the service stores fields by field_name, so the leaf
                                # name alone (``Doc.number``) merged the leaves of different branches
                                full_name = f"{side}.{field_name}"
                                code_object.fields[full_name] = field.copy(update={'field_name': full_name})
                        else:
                            code_object.fields[side] = CodeObjectField(
                                field_name=side,
                                field_type=method[side],
                                file=service_file,
                                line=1
                            )

                    parsed_objects.append(code_object)

        logger.info(f"For scan {self.parser} data parse {len(parsed_objects)} objects")

        return parsed_objects
