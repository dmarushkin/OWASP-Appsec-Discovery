import click
import logging
from typing import Iterable, Optional

from appsec_discovery.api import ScanPipeline, load_config
from appsec_discovery.errors import ConfigError
from appsec_discovery.matching import RANK, Severity, max_severity
from appsec_discovery.models import CodeObject, ScoreConfig
from appsec_discovery.reports import render_report

LOG_FORMAT = "[%(levelname)-8s] %(message)s"

# Exit codes
EXIT_OK = 0
EXIT_FAILED = 1         # parser failure (all parsers, or any with --fail-on-error) or --fail-on-severity hit
EXIT_USAGE = 2          # invalid arguments or config (click.BadParameter / UsageError)

GATE_SEVERITIES = [s.value for s in Severity if s is not Severity.info]


def log_level(verbosity: int) -> int:
    """0 -> WARNING (default), 1 (-v) -> INFO, 2+ (-vv) -> DEBUG."""
    if verbosity <= 0:
        return logging.WARNING
    if verbosity == 1:
        return logging.INFO
    return logging.DEBUG


def setup_logging(verbosity: int) -> None:
    """Always configure logging: a stderr handler on the root logger at the chosen level."""
    level = log_level(verbosity)
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(format=LOG_FORMAT, level=level)
    root.setLevel(level)


def severity_gate_hit(objects: Iterable[CodeObject], threshold: Optional[str]) -> Optional[Severity]:
    """Highest object severity if it is at or above ``threshold``, else ``None``."""
    if not threshold:
        return None
    highest = max_severity(obj.severity for obj in objects)
    if highest is not None and RANK[highest] >= RANK[Severity(threshold)]:
        return highest
    return None


@click.command()
@click.option('--source', required=True, type=click.Path(exists=True), help='Source code folder')
@click.option('--config', required=False, show_default=True, default=None, type=click.File('r'), help='Scoring config file')
@click.option('--output', required=False, show_default=True, default=None, type=click.File('w'), help='Output file')
@click.option('--output-type', required=False, show_default=True, default='yaml', type=click.Choice(['json', 'sarif', 'yaml'], case_sensitive=False), help='Report type')
@click.option("--only-scored-objects", is_flag=True, show_default=True, default=False, help="Show only scored objects")
@click.option("--fail-on-error", is_flag=True, show_default=True, default=False, help="Exit with code 1 if any parser failed (by default only if all parsers failed)")
@click.option("--fail-on-severity", required=False, default=None, type=click.Choice(GATE_SEVERITIES, case_sensitive=False),
              help="Exit with code 1 if any reported object has this severity or higher (CI gate)")
@click.option('-v', '--verbose', count=True, help='Log verbosity: default WARNING, -v INFO, -vv DEBUG')
def main(source, config, output, output_type, only_scored_objects, fail_on_error, fail_on_severity, verbose):
    """Discover sensitive objects in project code.

    Exit codes: 0 - success; 1 - every parser failed, any parser failed
    with --fail-on-error, or an object at/above --fail-on-severity was
    reported; 2 - invalid arguments or config.
    """

    setup_logging(verbose)

    try:
        score_config = load_config(config) if config else ScoreConfig()
        pipeline = ScanPipeline(score_config, only_scored=only_scored_objects)
    except ConfigError as e:
        raise click.BadParameter(str(e), param_hint="'--config'") from e

    result = pipeline.run(source)
    scanned_objects = result.objects

    report = render_report(scanned_objects, output_type)
    if output:
        # click owns (and closes) the output file
        output.write(report)
    else:
        click.echo(report)

    exit_code = EXIT_OK

    if result.errors:

        for parser_name, error in result.errors.items():
            click.echo(f"Parser {parser_name} failed: {error}", err=True)

        if result.all_failed or fail_on_error:
            exit_code = EXIT_FAILED

    hit = severity_gate_hit(scanned_objects, fail_on_severity.lower() if fail_on_severity else None)
    if hit is not None:
        click.echo(f"Found objects with severity {hit.value} (--fail-on-severity {fail_on_severity.lower()})", err=True)
        exit_code = EXIT_FAILED

    if exit_code != EXIT_OK:
        raise click.exceptions.Exit(exit_code)

if __name__ == '__main__':
    main()
