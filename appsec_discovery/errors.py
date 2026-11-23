"""Exceptions raised by the appsec_discovery core library."""


class AppsecDiscoveryError(Exception):
    """Base class for all appsec_discovery errors."""


class ConfigError(AppsecDiscoveryError, ValueError):
    """The scoring config could not be parsed or validated."""


class SemgrepError(AppsecDiscoveryError, RuntimeError):
    """semgrep failed: missing binary, timeout, fatal exit code or unparsable output."""


class UnknownParserError(AppsecDiscoveryError, LookupError):
    """No parser with the requested name exists."""
