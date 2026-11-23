import importlib.metadata

# Single version source: [project].version in pyproject.toml, read from the installed metadata.
try:
    __version__ = importlib.metadata.version('appsec-discovery')
except importlib.metadata.PackageNotFoundError:  # running from a source tree that is not installed
    __version__ = '0+unknown'

# Public API (imported after __version__: appsec_discovery.reports reads it).
from appsec_discovery.api import (  # noqa: E402
    REPORT_FORMATS,
    AiScorer,
    ScanPipeline,
    apply_hit_statuses,
    ScanResult,
    load_config,
    load_config_file,
    render_report,
    run_parsers,
    scan,
)
from appsec_discovery.changes import affected_parsers, parser_file_patterns  # noqa: E402
from appsec_discovery.errors import (  # noqa: E402
    AppsecDiscoveryError,
    ConfigError,
    SemgrepError,
    UnknownParserError,
)

__all__ = [
    "__version__",
    "scan", "load_config", "load_config_file", "run_parsers", "render_report", "REPORT_FORMATS",
    "ScanPipeline", "ScanResult", "AiScorer", "apply_hit_statuses",
    "affected_parsers", "parser_file_patterns",
    "AppsecDiscoveryError", "ConfigError", "SemgrepError", "UnknownParserError",
]
