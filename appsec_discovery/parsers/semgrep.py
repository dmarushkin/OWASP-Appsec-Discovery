"""semgrep integration: one runner for every semgrep-based parser and a typed view of a finding."""
import json
import logging
import subprocess
from typing import Any, Dict, Iterable, List, Optional, Sequence

from appsec_discovery.errors import SemgrepError
from appsec_discovery.parsers.common import DEFAULT_PRUNE_DIRS, relative_source_path

logger = logging.getLogger(__name__)

__all__ = ["DEFAULT_SEMGREP_TIMEOUT", "DEFAULT_RULE_TIMEOUT", "Finding", "SemgrepRunner"]

# whole semgrep process, seconds; None disables the timeout
DEFAULT_SEMGREP_TIMEOUT = 3600
# semgrep --timeout: max seconds for one rule on one file
DEFAULT_RULE_TIMEOUT = 30


class Finding:
    """Read-only view of one semgrep result.

    Rules declare what they produce in ``metadata`` (``parser``, ``object_type``,
    ``framework``, ...), so parsers dispatch on metadata instead of rule-id prefixes.
    """

    __slots__ = ('raw',)

    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw or {}

    @property
    def path(self) -> str:
        return self.raw.get('path') or ''

    @property
    def line(self) -> int:
        return (self.raw.get('start') or {}).get('line', 0)

    @property
    def check_id(self) -> str:
        return self.raw.get('check_id') or ''

    @property
    def rule_id(self) -> str:
        """The rule ``id`` without the config-path prefix semgrep adds to ``check_id``."""
        return self.check_id.split('.')[-1]

    @property
    def extra(self) -> Dict[str, Any]:
        return self.raw.get('extra') or {}

    @property
    def metadata(self) -> Dict[str, Any]:
        return self.extra.get('metadata') or {}

    @property
    def parser(self) -> Optional[str]:
        return self.metadata.get('parser')

    @property
    def object_type(self) -> Optional[str]:
        return self.metadata.get('object_type')

    @property
    def framework(self) -> str:
        return self.metadata.get('framework') or ''

    def _metavar(self, name: str) -> Dict[str, Any]:
        return (self.extra.get('metavars') or {}).get(name) or {}

    def mv(self, name: str, strip_quotes: bool = True) -> str:
        """``abstract_content`` of metavariable ``name`` (``''`` when unbound).

        ``strip_quotes`` drops surrounding ``"`` then ``'`` characters.
        """
        value = self._metavar(name).get('abstract_content', '') or ''
        if strip_quotes:
            value = value.strip('"').strip("'")
        return value

    def mv_line(self, name: str) -> Optional[int]:
        """Start line of metavariable ``name``, ``None`` when unbound."""
        return (self._metavar(name).get('start') or {}).get('line')


MAX_TARGET_BYTES = 5_000_000


class SemgrepRunner:
    """Runs semgrep once with one or more rule folders over a source folder.

    The command keeps the old flags (``--json --metrics=off --no-git-ignore``)
    and adds a per-rule ``--timeout`` and ``--exclude`` of vendored directories.
    """

    def __init__(self, timeout: Optional[float] = DEFAULT_SEMGREP_TIMEOUT,
                 rule_timeout: Optional[int] = DEFAULT_RULE_TIMEOUT,
                 exclude: Iterable[str] = tuple(sorted(DEFAULT_PRUNE_DIRS))):
        self.timeout = timeout
        self.rule_timeout = rule_timeout
        self.exclude = list(exclude)
        self.max_target_bytes = MAX_TARGET_BYTES

    def command(self, source_folder: str, rules_dirs: Sequence[str]) -> List[str]:
        cmd = ["semgrep", "scan"]
        for rules_dir in rules_dirs:
            cmd += ["--config", str(rules_dir)]
        cmd += ["--json", "--metrics=off", "--no-git-ignore"]
        # semgrep skips files over 1 MB by default: generated code (*.pb.go) holds most DTOs
        cmd += ["--max-target-bytes", str(self.max_target_bytes)]
        if self.rule_timeout is not None:
            cmd += ["--timeout", str(self.rule_timeout)]
        for pattern in self.exclude:
            cmd += ["--exclude", pattern]
        cmd.append(source_folder)
        return cmd

    def run(self, source_folder: str, rules_dirs: Sequence[str], label: str = 'semgrep') -> List[dict]:
        """semgrep results (possibly empty) with ``path`` relative to ``source_folder``.

        Raises ``SemgrepError`` if semgrep is missing, times out, exits with a
        fatal code or prints unparsable output. Never returns ``None``.
        """
        logger.info(f"Start {label} scan for {source_folder}")

        cmd = self.command(source_folder, rules_dirs)

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except FileNotFoundError as ex:
            raise SemgrepError(f"semgrep executable not found: {ex}") from ex
        except subprocess.TimeoutExpired as ex:
            raise SemgrepError(f"semgrep timed out after {self.timeout}s for {source_folder}") from ex

        if proc.returncode not in (0, 1):
            raise SemgrepError(f"semgrep exited with code {proc.returncode}: {(proc.stderr or '')[-2000:]}")

        try:
            data = json.loads(proc.stdout)
        except (json.JSONDecodeError, TypeError) as ex:
            raise SemgrepError(f"semgrep produced invalid JSON: {(proc.stderr or '')[-2000:]}") from ex

        if not isinstance(data, dict):
            raise SemgrepError(f"semgrep produced unexpected JSON of type {type(data).__name__}")

        for err in data.get('errors') or []:
            message = err.get('message') if isinstance(err, dict) else err
            logger.warning(f"semgrep ({label}): {message}")

        results = data.get('results') or []

        for finding in results:
            # keep the path relative to the scanned folder: file, hashes and DB keys depend on it
            finding['path'] = relative_source_path(finding.get('path', ''), source_folder)

        logger.info(f"End {label} scan for {source_folder}, found {len(results)} rule hits")

        return results
