"""``ParserFactory``: name -> parser class, a thin shim over ``REGISTRY`` (P1-5)."""
import logging
import warnings
from importlib import import_module
from typing import Dict, List, Type

from appsec_discovery.errors import UnknownParserError
from appsec_discovery.parsers.base_parser import REGISTRY, Parser

logger = logging.getLogger(__name__)

__all__ = ["BUILTIN_PARSERS", "ParserFactory", "is_deprecated", "load_builtin_parsers"]

# built-in parser modules ``appsec_discovery.parsers.<name>.parser`` (each registers its class)
BUILTIN_PARSERS = ('client', 'db', 'golang', 'graphql', 'java', 'javascript', 'migrations', 'protobuf', 'python', 'swagger', 'terraform')

_loaded = False
_import_errors: Dict[str, BaseException] = {}


def load_builtin_parsers() -> None:
    """Import every built-in parser module once; a module that fails to import is logged
    and its error re-raised by ``ParserFactory.get_parser`` for that name."""
    global _loaded
    if _loaded:
        return
    for module_name in BUILTIN_PARSERS:
        try:
            import_module(f"appsec_discovery.parsers.{module_name}.parser")
        except Exception as ex:
            _import_errors[module_name] = ex
            logger.exception(f"failed to load parser {module_name}")
    _loaded = True


def is_deprecated(name: str) -> bool:
    cls = REGISTRY.get(name)
    return bool(cls is not None and cls.deprecated)


class ParserFactory:

    @staticmethod
    def get_parser(parser_type: str) -> Type[Parser]:
        """Return the parser class registered as ``parser_type``.

        Raises ``UnknownParserError`` if no such parser exists; the import error of a
        built-in parser module that failed to load is re-raised unchanged. A deprecated
        parser is returned with a warning.
        """
        load_builtin_parsers()

        if isinstance(parser_type, str) and parser_type in REGISTRY:
            cls = REGISTRY[parser_type]
            if cls.deprecated:
                message = (f"parser {parser_type!r} is deprecated and finds nothing; "
                           f"it will be removed in a future release, drop it from 'parsers'")
                logger.warning(message)
                warnings.warn(message, DeprecationWarning, stacklevel=2)
            return cls

        if isinstance(parser_type, str) and parser_type in _import_errors:
            raise _import_errors[parser_type]

        raise UnknownParserError(f"Parser for type {parser_type!r} not found")

    @staticmethod
    def get_parser_types() -> List[str]:
        """Names of all registered parsers (deprecated ones included), sorted.

        A built-in parser whose module failed to import is listed too: it stays part of
        ``parsers: [all]`` and of an explicit parser list, so the run reports it as a failed
        parser (``get_parser`` re-raises the import error) and the scan is partial. Dropping it
        silently would make the scan look complete without that parser's objects, and a
        consumer that replaces its snapshot with a complete scan would delete them.
        """
        load_builtin_parsers()
        return sorted(set(REGISTRY) | set(_import_errors))

    @staticmethod
    def import_errors() -> Dict[str, BaseException]:
        """``{built-in parser name: import error}`` of the parser modules that failed to load."""
        load_builtin_parsers()
        return dict(_import_errors)
