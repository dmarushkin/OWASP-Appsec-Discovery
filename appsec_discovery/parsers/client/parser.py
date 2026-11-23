from appsec_discovery.parsers.base_parser import SemgrepParser


class ClientParser(SemgrepParser):
    """Deprecated: ships no rules and always returns [].

    The name is still accepted in parsers (with a warning) for one more
    release; it is not part of parsers: [all].
    """

    name = 'client'
    deprecated = True
    file_patterns = ()         # reads nothing
