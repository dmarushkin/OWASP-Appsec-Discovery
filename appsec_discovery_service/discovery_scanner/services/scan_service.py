"""Scan flow (storage design, AGREED REVISIONS).

* ``scan_branch(branch)``  main branch: core scan -> object records (keys from the core's
  object identity, ``CodeObject.hash``; lines are never part of a key) -> one transaction:
  objects/fields, snapshot diff-apply, keyword hits, scanned_commit, pruned MR deltas.
* ``scan_mr(mr)``          makes sure the target snapshot is current (scans the target main
  if needed), scans the source, stores only the delta vs the target, runs the LLM rule on
  the delta.
* ``llm_score_branch(branch)``  LLM rules on a main branch: only subjects without a verdict,
  or with a machine verdict / unreviewed proposal from an older rule version, other core
  prompts or on another content of the subject (decided hits are not re-asked, except by an
  object rule when the object's field names changed: ``db_service.LLM_CANDIDATE_COND``).

Rules come from the ``rules`` table per project (P1-6): keyword rules are mapped to the
core's ``ScoreConfig.score_rules`` (``exclude`` ones become core exclusions) and evaluated by
the core scan, which records a ``RuleHit`` per match; ``score_tags`` hits go to the
built-in keyword rules ``kw-fields`` / ``kw-props`` (disabled by default: no score_tags hit is recorded then). Hit status: mode auto -> match, review ->
pending_review. LLM rules (``kind = llm``, any number) run after the save on candidates.
Scan markers carry the rules' versions, so a rule edit makes the branches rescan once and
pending hits are re-evaluated.

Failures (``services.failures``): a step that cannot go on raises ``ScanError`` with its reason
(the git ``fatal:`` line of a clone, the parser's error, the per-rule summary of an LLM run);
the job handler adds the subject and the reason ends up in ``jobs.last_error`` and the UI.
``False`` from ``scan_branch`` / ``scan_mr`` means "nothing to scan" (not an error).

Diff-based skip (``services.diff_service``, SCAN_DIFF_SKIP): before a main branch (or an MR) is cloned, the
GitLab compare API says which files changed since the snapshot's commit; when no parser of the scan reads
any of them the snapshot is moved to the new commit (``db_service.skip_branch_scan``) and the job ends
``skipped`` without a clone, a parse or an LLM run.
"""

import hashlib
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from types import SimpleNamespace
from typing import Callable, Dict, Iterable, List, Optional, Tuple

import appsec_discovery
from appsec_discovery.matching import Pattern, max_severity
from appsec_discovery.models import ScoreConfig, ScoreRule
from appsec_discovery.parsers import ParserFactory

from discovery_common.mapping import (
    ObjectRecord, compute_delta, dedupe, from_code_object, hit_row, marks_fields, restrict_delta,
)
from discovery_common import jobs, keys, lifecycle
from discovery_common.llm_work import job_phase
from discovery_common.models import CORE_FIELD_RULE, CORE_OBJECT_RULE
from discovery_common.redact import ErrorLog, describe
from models import Scan

from services.gl_service import (
    clone_gitlab_project_code,
    get_gitlab_project_lang,
    get_mr_changed_files,
)
from services.failures import ScanError, parser_failures, scan_error
from services import diff_service
from services.workspace import checkout_dir
from services.db_service import (
    PARTIAL_SUFFIX,
    ensure_rule,
    get_branch_by_id,
    get_llm_candidates,
    get_reserved_llm_objects,
    take_over_llm_objects,
    get_object_docs,
    get_object_fields,
    get_project,
    get_rules,
    get_scan,
    insert_scan,
    load_branch_snapshot,
    finish_ingest_batch,
    latest_ingest_batch,
    load_snapshot_files,
    save_main_scan,
    save_mr_delta,
    scan_lock,
    skip_branch_scan,
    upsert_llm_hits,
)

from services.score_service import (
    LlmObject, get_llm_backend, llm_configured, llm_rule_verdicts,
    llm_score_objects,
)

from config import get_settings
from logger import get_logger

logger = get_logger(__name__)

SCANNER = 'discovery'
# 2.0.0: storage v2 (object identity keys, branch deltas, rule hits). Bumping it makes every
# branch rescan once even if its commit did not change.
RULES_VERSION = '2.0.0'


# Progress of the running scan_branch job (``discovery_common.llm_work.CURRENT_PROGRESS``, set by
# ``job_handlers.scan_branch_job``): phases clone -> parse -> save -> done | skipped | partial |
# failed, with object counts per parser, in ``jobs.progress``. A no-op outside such a job.
# The phase boundaries clone / parse / save are where a stopping worker hands the scan back
# (``RequeueJob``: nothing of the scan is saved yet, the job is run again without using an attempt).
STOP_PHASES = ("clone", "parse", "save")


def _phase(name, **extra):
    if name in STOP_PHASES and jobs.stop_requested():
        job_phase("waiting", reason=f"requeued before {name}: the scanner is stopping")
        raise jobs.stopping(f"scan requeued before {name}")
    job_phase(name, **extra)


def _lang_allowed(settings, project_path, branch_name) -> bool:
    """SCAN_LANGS gate (was hard-coded to 'go'); GitLab is not asked when the gate is off."""

    langs = [lang.lower() for lang in settings.scan_langs]
    if not langs or 'all' in langs:
        return True

    project_lang = get_gitlab_project_lang(project_path, branch_name)
    allowed = settings.scans_lang(project_lang)

    if not allowed:
        logger.info(f"Skip scan of {project_path}, branch {branch_name}: language {project_lang} is not in SCAN_LANGS")

    return allowed


def rules_fingerprint(rules) -> str:
    """Short digest of (id, version, enabled, mode) of ``rules``: part of the scan markers, so a
    rule edit / enable / disable / mode switch makes branches rescan once."""
    parts = sorted(f"{r.id}:{r.version}:{r.enabled is not False}:{r.mode}" for r in rules or [])
    return hashlib.md5(",".join(parts).encode()).hexdigest()[:12]


class InventoryRules(list):
    """The (empty) keyword rules of a project in ``inventory`` scan mode: objects and fields
    are stored, but nothing is categorised (no default ``score_tags`` scoring, no keyword or
    LLM rules); people label them by hand (``manual:labels`` hits, REST / MCP)."""


def project_rules(project_id):
    """Keyword rules for a scan of ``project_id``: the enabled DB rules, or ``InventoryRules``
    when the project's ``scan_mode`` is ``inventory``."""
    if is_inventory(project_id):
        return InventoryRules()
    return get_rules('keyword')


def is_inventory(project_id) -> bool:
    project = get_project(project_id) if project_id is not None else None
    return getattr(project, 'scan_mode', None) == 'inventory'


def _scan_marker(scanner, project_id, branch_id, project_path, branch_name, commit, parsers, rules=None) -> Scan:
    if isinstance(rules, InventoryRules):       # switching the mode rescans the branch once
        rules_version = f"{RULES_VERSION}+inventory"
    else:
        rules_version = RULES_VERSION if rules is None else f"{RULES_VERSION}+kw.{rules_fingerprint(rules)}"
    return Scan(
        scanner=scanner, rules_version=rules_version, parsers=parsers, project_id=project_id,
        branch_id=branch_id, branch_commit=commit, project_path=project_path, branch_name=branch_name,
        scanned_at=datetime.now(),
    )


def _fingerprint(scan: Scan) -> str:
    """The scan configuration of a snapshot made by ``scan`` (``diff_service.scan_fingerprint``)."""
    return diff_service.scan_fingerprint(scan.rules_version, scan.parsers)


def _skip_parsers(settings) -> List[str]:
    """The parsers whose files decide a diff-based skip: the configured ones (unknown names dropped, as the
    scan drops them)."""
    return _known_parsers(settings.parsers)


def _try_skip(branch, commit: str, scan: Scan, settings, *, what: str) -> Optional[diff_service.Decision]:
    """The diff-based skip of a full main branch scan at ``commit``: the decision (None when the shortcut is off),
    the snapshot moved when it says skip (``skip_branch_scan``; ``decision.skip`` is reset when the move failed)."""
    if not settings.scan_diff_skip:
        return None
    decision = diff_service.decide_main(branch, commit, _fingerprint(scan), _skip_parsers(settings), settings)
    if decision.skip and not skip_branch_scan(branch, commit, scan):
        decision = diff_service.Decision(False, "the branch is not a main branch any more")
    if decision.skip:
        logger.info(f"Skipped {what} at {commit}: {decision.reason} ({decision.changed_files} changed files)")
    else:
        logger.info(f"Full {what} at {commit}: {decision.reason}")
    return decision


#######################################
##  Main branches                   ###
#######################################

def _parser_scope(parsers) -> Optional[List[str]]:
    """A ``parse`` parser subset, normalised (sorted, unique); None: the PARSERS setting."""
    return sorted(set(parsers)) if parsers else None


def scan_main(branch, commit: str, rules, parsers=None) -> Tuple[List[ObjectRecord], str]:
    """Scan a cloned main branch at ``commit`` and save the snapshot (one transaction).
    ``parsers``: only these parsers; only their objects in the snapshot are replaced."""

    settings = get_settings()
    parsers = _parser_scope(parsers)

    records, status = run_discovery_scan(branch.project_path, branch.project_id, branch.id, branch.branch_name, commit,
                                         rules, parsers=parsers)
    hits = keyword_hits(records, rules, branch.project_path)
    scan = _scan_marker(SCANNER, branch.project_id, branch.id, branch.project_path, branch.branch_name, commit,
                        parsers or settings.parsers, rules)

    save_main_scan(branch, commit, records, hits, scan, complete=(status == 'scanned'), parsers=parsers,
                   fingerprint=_fingerprint(scan))
    if not isinstance(rules, InventoryRules):
        record_llm_coverage(branch.id)          # the snapshot changed: what the LLM rules have answered of it

    return records, status


def _clone(project_path, branch_name, project_id, branch_id, commit, *, shallow: bool, what: str) -> None:
    """``clone_gitlab_project_code`` with the context ``what`` (``cannot clone source branch 'x'``) in
    front of git's reason; a False return (no details) is a failure too."""
    try:
        ok = clone_gitlab_project_code(project_path, branch_name, project_id, branch_id, commit, shallow=shallow)
    except ScanError as e:
        raise e.prefixed(what) from e
    if not ok:
        raise ScanError(f"{what}: git clone failed (no details)")


def scan_branch(branch, force: bool = False, parsers=None) -> bool:
    """Scan a main branch at its known commit, unless a scan with the same rules and parsers
    exists (``force``: scan anyway). ``parsers``: a ``parse`` by a parser subset. Returns False
    when there is nothing to scan (not a main branch); raises ``ScanError`` with the reason when
    the clone or a parser failed."""

    project_path = getattr(branch, 'project_path', None)
    branch_name = getattr(branch, 'branch_name', None)

    try:

        settings = get_settings()

        if not branch.is_main:
            logger.warning(f"scan_branch called for non-main branch {branch_name} of {project_path}, skipped")
            return False

        if _lang_allowed(settings, project_path, branch_name):

            rules = project_rules(branch.project_id)
            parsers = _parser_scope(parsers)
            scan = _scan_marker(SCANNER, branch.project_id, branch.id, project_path, branch_name, branch.commit,
                                parsers or settings.parsers, rules)

            # already scanned (e.g. as the target of an MR): no clone, no second scan
            if force or not get_scan(scan):
                decision = _try_skip(branch, branch.commit, scan, settings,
                                     what=f"scan of {project_path}, branch {branch_name}") \
                    if not force and parsers is None else None
                if decision is not None and decision.skip:
                    # no parser file changed since the snapshot: moved to the commit, nothing cloned or parsed
                    _phase("skipped", **decision.progress)
                    logger.info(f"Project {project_path}, branch {branch_name} processed")
                    return True
                _phase("clone", commit=branch.commit,
                       **({"full_scan_reason": decision.reason} if decision is not None else {}))
                # a failed clone is a failed scan: the job is retried (P2-4), unless the branch is gone
                _clone(project_path, branch_name, branch.project_id, branch.id, branch.commit, shallow=True,
                       what=f"cannot clone branch '{branch_name}'")
                _, status = scan_main(branch, branch.commit, rules, parsers=parsers)
                if status != 'scanned':
                    # a parser failed: the partial result is saved (nothing deleted, no
                    # scanned_commit); a failed scan, so the job is retried with backoff
                    reason = f"partial scan at {branch.commit}: {parser_failures(getattr(status, 'errors', None))}"
                    logger.error(f"Partial scan of {project_path}, branch {branch_name}: {reason}")
                    _phase("partial", error=reason[:300])
                    raise ScanError(reason)
                _phase("done")
            else:
                logger.info(f"Already exist scan {scan.scanner} (ver {scan.rules_version} parsers {str(scan.parsers)} for {project_path}, branch {branch_name}")
                _phase("skipped", reason="already scanned with the same rules and parsers")
        else:
            _phase("skipped", reason="language not in SCAN_LANGS")

        logger.info(f"Project {project_path}, branch {branch_name} processed")

        return True

    except jobs.RequeueJob:
        raise

    except ScanError as e:
        if not str(e).startswith("partial scan"):       # the partial phase is written above
            _phase("failed", error=e.reason[:300])
        raise

    except Exception as e:
        # anything else (GitLab, DB, a bug): the reason travels to the job's last_error too
        error = scan_error(e)
        logger.error(f"Failed to scan project {project_path}, branch {branch_name}: {error.reason}")
        _phase("failed", error=error.reason[:300])
        raise error from e


#######################################
##  Merge requests                  ###
#######################################

def _target_snapshot(mr, target_branch, rules, parsers=None) -> Tuple[Dict, Optional[Dict], str]:
    """``({object_key: content_hash}, files, commit)`` of the MR target at ``mr.target_branch_commit``
    (``commit``: the one the snapshot is at, recorded as the delta's ``delta_target_commit``).

    A main target is read from ``branch_objects``. It is scanned first only when its
    snapshot is missing or at another commit than both the MR's target commit and the
    branch's known head (a newer snapshot is never replaced by an older one). This runs
    under the target's ``scan_lock``: a concurrent ``scan_branch`` job or the other MRs of
    the same target wait for the running scan and then reuse its snapshot instead of
    cloning and scanning the same main again. ``files`` is None for a main target (file
    paths are read from the stored objects when needed).

    Other targets are not stored (only mains and MR deltas are), so they are cloned and
    scanned in memory; ``files`` then maps their object keys to files. ``parsers``: only the
    objects of these parsers (a missing main snapshot is still scanned by every parser)."""

    commit = mr.target_branch_commit
    project_path = mr.project_path
    settings = get_settings()

    if target_branch.is_main:
        with scan_lock(target_branch.id):
            branch = get_branch_by_id(target_branch.id) or target_branch      # re-read after waiting
            scanned = branch.scanned_commit
            partial = None
            if scanned is None or (scanned != commit and scanned != branch.commit):
                partial = _partial_scan_of(branch, (commit, branch.commit), rules)
            if partial is not None:
                # a parser keeps failing on this commit (the scan_branch job retries it): do not
                # clone and scan the main again for every MR, use the partial snapshot
                logger.warning(f"Target {branch.branch_name} of {project_path}: only a partial snapshot at "
                               f"{partial} (a parser failed), used as is")
                scanned = partial
            elif scanned is None or (scanned != commit and scanned != branch.commit):
                marker = _scan_marker(SCANNER, branch.project_id, branch.id, project_path, branch.branch_name, commit,
                                      settings.parsers, rules)
                decision = _try_skip(branch, commit, marker, settings,
                                     what=f"scan of the target {branch.branch_name} of {project_path}")
                if decision is None or not decision.skip:
                    logger.info(f"Target {branch.branch_name} of {project_path} is at {commit}, snapshot at "
                                f"{scanned}: scanning the target first")
                    _clone(project_path, branch.branch_name, mr.project_id, branch.id, commit, shallow=True,
                           what=f"cannot clone target branch '{branch.branch_name}'")
                    scan_main(branch, commit, rules)
                scanned = commit
            elif scanned != commit:
                logger.info(f"Target {branch.branch_name} of {project_path}: using the snapshot at the branch head "
                            f"{scanned} (MR target commit {commit})")
            return load_branch_snapshot(branch.id, parsers), None, scanned

    _clone(project_path, mr.target_branch, mr.project_id, target_branch.id, commit, shallow=True,
           what=f"cannot clone target branch '{mr.target_branch}'")
    records, _ = run_discovery_scan(project_path, mr.project_id, target_branch.id, target_branch.branch_name, commit, rules,
                                    parsers=parsers)
    return ({record.object_key: record.content_hash for record in records},
            {record.object_key: record.file for record in records}, commit)


def _partial_scan_of(branch, commits, rules) -> Optional[str]:
    """The first of ``commits`` with a partial main scan (``save_main_scan`` records one when
    a parser failed) by the current rules and parsers, or None."""
    settings = get_settings()
    for commit in dict.fromkeys(c for c in commits if c):
        marker = _scan_marker(SCANNER, branch.project_id, branch.id, branch.project_path, branch.branch_name, commit,
                              settings.parsers, rules)
        marker.rules_version += PARTIAL_SUFFIX
        if get_scan(marker):
            return commit
    return None


def scan_mr(mr, parsers=None, llm: bool = True) -> bool:
    """Scan a merge request: store the source delta vs the target.

    `mr` is an `MR` row; it carries project, source/target branch ids, names and commits.
    ``parsers``: a ``parse`` by a parser subset (only their delta rows are replaced);
    ``llm=False``: no LLM rules on the delta. Returns False when there is nothing to scan
    (branches not tracked, source is main); raises ``ScanError`` with the reason on a failure
    (a deleted source branch is permanent: the job is not retried).
    """

    project_id = getattr(mr, 'project_id', None)
    mr_id = getattr(mr, 'mr_id', None)

    try:

        settings = get_settings()

        project_path = mr.project_path

        if mr.source_branch_id is None or mr.target_branch_id is None:
            logger.info(f"MR {mr_id} of {project_path} has no tracked source/target branch, skipped")
            return False

        if _lang_allowed(settings, project_path, mr.target_branch):

            source_branch = get_branch_by_id(mr.source_branch_id)
            target_branch = get_branch_by_id(mr.target_branch_id)

            if source_branch is None or target_branch is None:
                logger.info(f"Branches of MR {mr_id} of {project_path} are not tracked any more, skipped")
                return False

            if source_branch.is_main:
                logger.info(f"MR {mr_id} of {project_path} comes from the main branch, skipped")
                return False

            rules = project_rules(project_id)
            parsers = _parser_scope(parsers)

            scan = _scan_marker(SCANNER, project_id, source_branch.id, project_path, mr.source_branch,
                                mr.source_branch_commit, parsers or settings.parsers, rules)

            # diff-based skip (SCAN_DIFF_SKIP_MRS): the stored delta stays when neither the source nor the
            # target moved in parser files; else the compare of the merge base gives the MR's changed files
            # (the delta filter) without a history clone
            changed_files = decision = None
            if settings.scan_diff_skip and parsers is None:
                decision = diff_service.decide_mr(mr, source_branch, _fingerprint(scan), _skip_parsers(settings), settings)
                if decision.skip and skip_branch_scan(source_branch, mr.source_branch_commit, scan,
                                                      target_commit=mr.target_branch_commit):
                    logger.info(f"Skipped scan of MR {mr_id} of {project_path}: {decision.reason} "
                                f"({decision.changed_files} changed files)")
                    _phase("skipped", **decision.progress)
                    return True
                logger.info(f"Full scan of MR {mr_id} of {project_path}: {decision.reason}")
                changed_files = diff_service.mr_changed_files(mr, settings)

            _phase("clone", commit=mr.source_branch_commit,
                   **({"full_scan_reason": decision.reason} if decision is not None else {}))
            # the source keeps its history for the git diff with the target unless the compare API gave the files
            _clone(project_path, mr.source_branch, project_id, mr.source_branch_id, mr.source_branch_commit,
                   shallow=changed_files is not None, what=f"cannot clone source branch '{mr.source_branch}'")

            # a failed target clone raises: a failed scan, the job is retried (P2-4)
            target, target_files, target_commit = _target_snapshot(mr, target_branch, rules, parsers)

            records, status = run_discovery_scan(project_path, project_id, source_branch.id, mr.source_branch,
                                                 mr.source_branch_commit, rules, parsers=parsers)
            complete = status == 'scanned'

            delta = compute_delta(records, target, complete=complete)
            delta = _only_mr_changes(mr, source_branch, target_branch, delta, target_files, changed_files)
            changed = [record for _, _, record in delta if record is not None]
            hits = keyword_hits(changed, rules, project_path)

            save_mr_delta(source_branch, mr.source_branch_commit, delta, hits, scan, complete=complete, parsers=parsers,
                          fingerprint=_fingerprint(scan), target_commit=target_commit)

            logger.info(f"MR {mr_id} of {project_path}: {sum(1 for d in delta if d[0] == 'added')} added, "
                        f"{sum(1 for d in delta if d[0] == 'modified')} modified, "
                        f"{sum(1 for d in delta if d[0] == 'removed')} removed objects")

            if not isinstance(rules, InventoryRules):
                if changed and llm:
                    # the delta is small and changed in the MR: its stale verdicts are asked again too (rule
                    # rollouts migrate the main snapshots only)
                    run_llm_rules(source_branch.id, project_path, is_main=False, migration=True)
                # a (configured) LLM run records the coverage of the new delta; else it is recorded here
                if not (changed and llm and llm_configured(settings)):
                    record_llm_coverage(source_branch.id)

        return True

    except jobs.RequeueJob:
        raise

    except ScanError as e:
        _phase("failed", error=e.reason[:300])
        raise

    except Exception as e:
        error = scan_error(e)
        logger.error(f"Failed to scan project {project_id}, mr {mr_id}: {error.reason}")
        _phase("failed", error=error.reason[:300])
        raise error from e


def _only_mr_changes(mr, source_branch, target_branch, delta, target_files, changed_files=None):
    """Restrict the delta (source vs target head) to the files the MR itself changes since
    its merge-base with the target: a source behind the target would otherwise report every
    later target change as an MR change (added / modified / removed noise). ``changed_files``:
    the files from the compare API (``diff_service.mr_changed_files``); else the git diff in
    the source checkout."""

    if changed_files is None:
        changed_files = get_mr_changed_files(mr.project_id, source_branch.id, mr.source_branch_commit,
                                             mr.target_branch, mr.target_branch_commit)
    if changed_files is None:
        logger.warning(f"MR {mr.mr_id} of {mr.project_path}: changed files unknown, the delta is vs the target head")
        return delta

    removed = [object_key for change, object_key, _ in delta if change == 'removed']
    if target_files is None:
        target_files = load_snapshot_files(target_branch.id, removed)

    kept = restrict_delta(delta, changed_files, target_files)
    if len(kept) != len(delta):
        logger.info(f"MR {mr.mr_id} of {mr.project_path}: {len(delta) - len(kept)} of {len(delta)} delta objects are "
                    f"outside the {len(changed_files)} files changed since the merge-base, dropped")
    return kept


#######################################
##  Rules -> hits                   ###
#######################################

def _scope_matches(scope: dict, project_path, record: Optional[ObjectRecord] = None, field=None) -> bool:

    def ok(key, value):
        raw = (scope or {}).get(key)
        return not raw or Pattern.of(raw).matches(value)

    if not ok('project_re', project_path):
        return False
    if record is not None and not (ok('object_re', record.name) and ok('object_type_re', record.type)):
        return False
    if field is not None and not (ok('field_re', field.name) and ok('field_type_re', field.type)):
        return False
    return True


def _is_exclude(rule) -> bool:
    return (rule.scope or {}).get('action') == 'exclude'


def _is_core(rule) -> bool:
    return rule.name in (CORE_FIELD_RULE, CORE_OBJECT_RULE)


def _hit_status(rule) -> str:
    return 'match' if rule.mode == 'auto' else 'pending_review'


def _merge(hits):
    """Severity (max) and category (tags in order, comma separated) of several core hits."""
    severity = max_severity(h.severity for h in hits)
    tags = list(dict.fromkeys(tag for h in hits for tag in h.tags))
    return getattr(severity, 'value', severity), ','.join(tags) or None


def keyword_hits(records: Iterable[ObjectRecord], rules, project_path) -> List[dict]:
    """Hit rows for the keyword hits the core recorded on ``records`` (``ObjectRecord.hits``):

    * ``score_tags`` hits -> ``kw-fields`` (one per field) and
      ``kw-props`` (one per object, for the property hits), several keywords
      merged (max severity, tags in order);
    * hits of the DB keyword rules (``rule_id``) -> that rule (field or object subject).

    The status follows the DB rule's mode; disabled rules produce nothing."""

    if isinstance(rules, InventoryRules):       # inventory mode: nothing is categorised
        return []

    records = list(records)
    rules = [rule for rule in rules if rule.kind == 'keyword' and rule.enabled is not False]
    by_name = {rule.name: rule for rule in rules}
    by_id = {str(rule.id): rule for rule in rules if not _is_core(rule)}
    hits: List[dict] = []

    core_field = by_name.get(CORE_FIELD_RULE)
    core_object = by_name.get(CORE_OBJECT_RULE)
    core_hits = [h for record in records for h in record.hits if h.rule_id is None]
    known = {rule.name for rule in rules}
    # re-created when missing (migration 0002 creates them); a disabled one stays disabled
    if core_field is None and CORE_FIELD_RULE not in known and any(h.subject == 'field' for h in core_hits):
        core_field = ensure_rule(CORE_FIELD_RULE)
    if core_object is None and CORE_OBJECT_RULE not in known and any(h.subject == 'prop' for h in core_hits):
        core_object = ensure_rule(CORE_OBJECT_RULE)

    for record in records:

        tag_fields: Dict[str, list] = {}
        tag_props: list = []

        for hit in record.hits:

            if hit.rule_id is None:                      # score_tags keyword
                if hit.subject == 'field' and hit.field_name in record.fields:
                    tag_fields.setdefault(hit.field_name, []).append(hit)
                elif hit.subject == 'prop':
                    tag_props.append(hit)
                continue

            rule = by_id.get(str(hit.rule_id))
            if rule is None or _is_exclude(rule):
                continue
            field_name = hit.field_name if hit.subject == 'field' else None
            hits.append(hit_row(rule, record.project_id, record.object_key, field_name, _hit_status(rule),
                                severity=hit.severity or rule.severity, category=rule.category,
                                fields=hit.fields if field_name is None else None))

        if core_field is not None and core_field.enabled is not False:
            for field_name, field_hits in tag_fields.items():
                severity, category = _merge(field_hits)
                hits.append(hit_row(core_field, record.project_id, record.object_key, field_name,
                                    _hit_status(core_field), severity=severity, category=category))

        if core_object is not None and core_object.enabled is not False and tag_props:
            severity, category = _merge(tag_props)
            hits.append(hit_row(core_object, record.project_id, record.object_key, None, _hit_status(core_object),
                                severity=severity, category=category))

    return hits


def _llm_status(rule, verdict) -> str:
    if verdict.positive:
        return _hit_status(rule)
    if getattr(verdict, 'need_more_info', False):
        return 'need_more_info'
    return 'no_match'


def _hashes(batch: 'LlmRuleBatch', object_key, field_name: Optional[str]) -> Dict[str, str]:
    """``names_hash`` / ``subject_hash`` of what the model saw (``discovery_common.keys``): the
    version of the object in the batch (the candidate row), its fields, comments and samples."""
    row = batch.objects[object_key]['row']
    fields = batch.fields_by_hash.get(row['content_hash'], [])
    if field_name is None:
        return {'names_hash': keys.names_hash(row['name'], [name for name, _ in fields]),
                'subject_hash': keys.object_subject_hash(row['content_hash'])}
    docs = batch.docs_by_hash.get(row['content_hash'], (None, {}))[1].get(field_name) or (None, None)
    return {'names_hash': keys.names_hash(row['name'], [field_name]),
            'subject_hash': keys.field_subject_hash(field_name, dict(fields).get(field_name), docs[0], docs[1])}


def _field_marks(rule, verdicts, project_of, fields_by_hash, objects, batch=None) -> List[dict]:
    """``mark_fields`` object rules: one field hit per field a positive / need_more_info object
    verdict named (fields of the object only), with the object verdict's proposal."""
    if not marks_fields(rule):
        return []
    hits = []
    for v in verdicts:
        if v.field_name is not None or not (v.positive or getattr(v, 'need_more_info', False)):
            continue
        known = {name for name, _ in fields_by_hash.get(objects[v.object_key]['row']['content_hash'], [])}
        for name in dict.fromkeys(getattr(v, 'fields', None) or []):
            if name in known:
                hits.append(hit_row(rule, project_of[v.object_key], v.object_key, name, _llm_status(rule, v),
                                    severity=v.severity, category=v.category, model=v.model,
                                    reason=getattr(v, 'reason', None),
                                    **(_hashes(batch, v.object_key, name) if batch is not None else {})))
    return hits


class LlmRuleIncomplete(RuntimeError):
    """Some objects of an LLM rule run got no verdict (LLM unavailable, a broken answer); the
    message names the rule, how many of its objects failed and why (``summary``: the error
    classes with counts, e.g. ``LlmError: LLM answer truncated at max_tokens=8192 (2), APITimeoutError (1)``)."""

    def __init__(self, rule_name, verdicts: int, failed: int, total: Optional[int] = None, summary: str = ""):
        of = f" of {total}" if total is not None else ""
        super().__init__(f"LLM rule '{rule_name}': {failed}{of} objects failed" + (f": {summary}" if summary else "")
                         + f" ({verdicts} verdicts stored)")
        self.verdicts, self.failed, self.summary = verdicts, failed, summary


@dataclass
class LlmRuleBatch:
    """The candidates of one LLM rule on one branch, as the model sees them: ``objects`` =
    ``{object_key: {'row', 'candidates'}}``, ``llm_objects`` (prompt input) in candidate order."""
    rule: object
    branch_id: int
    objects: Dict
    llm_objects: List
    fields_by_hash: Dict
    docs_by_hash: Dict = field(default_factory=dict)

    def __len__(self):
        return len(self.llm_objects)

    def only(self, object_keys) -> 'LlmRuleBatch':
        wanted = set(object_keys)
        return LlmRuleBatch(self.rule, self.branch_id, {k: v for k, v in self.objects.items() if k in wanted},
                            [o for o in self.llm_objects if o.object_key in wanted], self.fields_by_hash,
                            self.docs_by_hash)


def llm_rule_batch(rule, branch_id: int, project_path: str, skip_reserved: bool = True,
                   migration: Optional[bool] = None, max_objects: Optional[int] = None) -> Optional[LlmRuleBatch]:
    """Candidate selection of an LLM rule (the same for the service and the external executor):
    subjects without a current verdict of the rule, in the rule's scope (``db_service.get_llm_candidates``:
    ``migration`` also the stale verdicts of older versions; None: LLM_REASK_INLINE). None when the rule does not
    apply or has no candidates. ``max_objects`` (a rollout slice): at most that many objects, the stale
    need_more_info verdicts first, then the positive ones, then no_match (fresh subjects before them).

    ``skip_reserved``: objects with open work items of the external executor for this rule
    version (pending / leased / answered) are left to it, so a service run and an external run
    never ask the model about the same object; applying the answers passes False."""

    if rule.enabled is False or getattr(rule, 'deleted_at', None) is not None \
            or not _scope_matches(rule.scope, project_path):
        return None

    candidates = get_llm_candidates(branch_id, rule) if migration is None \
        else get_llm_candidates(branch_id, rule, migration)
    if candidates and skip_reserved:
        reserved = get_reserved_llm_objects(rule.id, rule.version)
        if reserved:
            candidates = [row for row in candidates if row['object_key'] not in reserved]
        if candidates:
            changed = take_over_llm_objects(rule.id, rule.version, list({row['object_key'] for row in candidates}))
            if changed:
                from discovery_common.llm_work import refresh_progress
                refresh_progress(changed)
                logger.info(f"LLM rule {rule.name}: lapsed external reservations taken over (jobs {changed})")
    if not candidates:
        return None

    objects: Dict = {}
    for row in candidates:
        record = SimpleNamespace(name=row['name'], type=row['type'])
        field = SimpleNamespace(name=row['field_name'], type=row['field_type']) if row['field_name'] is not None else None
        if not _scope_matches(rule.scope, project_path, record, field):
            continue
        entry = objects.setdefault(row['object_key'], {'row': row, 'candidates': set()})
        if row['field_name'] is not None:
            entry['candidates'].add(row['field_name'])

    if not objects:
        return None
    if max_objects is not None and len(objects) > max_objects:
        buckets: Dict = {}
        for row in candidates:
            if row['object_key'] in objects:
                buckets[row['object_key']] = min(buckets.get(row['object_key'], 9), row.get('hit_bucket', -1))
        keep = sorted(objects, key=lambda k: (buckets.get(k, -1), str(k)))[:max(0, int(max_objects))]
        objects = {k: objects[k] for k in keep}
        if not objects:
            return None

    fields_by_hash = get_object_fields(entry['row']['content_hash'] for entry in objects.values())
    docs_by_hash = get_object_docs(entry['row']['content_hash'] for entry in objects.values())

    llm_objects = [
        LlmObject(object_key=key, name=entry['row']['name'],
                  fields=fields_by_hash.get(entry['row']['content_hash'], []), candidates=entry['candidates'],
                  type=entry['row'].get('type'), parser=entry['row'].get('parser'), file=entry['row'].get('file'),
                  props=entry['row'].get('props'),
                  comment=docs_by_hash.get(entry['row']['content_hash'], (None, {}))[0],
                  docs=docs_by_hash.get(entry['row']['content_hash'], (None, {}))[1])
        for key, entry in objects.items()
    ]
    return LlmRuleBatch(rule, branch_id, objects, llm_objects, fields_by_hash, docs_by_hash)


def llm_rule_object_verdicts(rule, llm_objects, backend=None, on_object=None):
    """The model calls and answer parsing of a rule (per object): the classifier rule (field
    target, no category) through ``classify``, the others through the core rule prompts."""
    if rule.target != 'object' and not rule.category:
        return llm_score_objects(llm_objects, backend=backend, prompt=rule.prompt, severity=rule.severity,
                                 **({'on_object': on_object} if on_object is not None else {}))
    return llm_rule_verdicts(rule, llm_objects, backend or get_llm_backend(),
                             **({'on_object': on_object} if on_object is not None else {}))


def store_llm_verdicts(rule, verdicts, batch: LlmRuleBatch, is_main: bool, rollout_id: Optional[int] = None) -> int:
    """Hit rows of the verdicts (plus the ``mark_fields`` field hits of object rules) in one
    transaction; human decisions are never overwritten (``upsert_llm_hits``; object hits re-asked
    because the field names changed are carried over or sent back to review). The hits record what
    the model saw (``names_hash`` / ``subject_hash``, ``_hashes``)."""
    objects = batch.objects
    project_of = {key: entry['row']['project_id'] for key, entry in objects.items()}
    hits = [
        hit_row(rule, project_of[v.object_key], v.object_key, v.field_name, _llm_status(rule, v),
                severity=v.severity, category=v.category, model=v.model, reason=getattr(v, 'reason', None),
                fields=getattr(v, 'fields', None), **_hashes(batch, v.object_key, v.field_name))
        for v in verdicts
    ]
    if rule.target == 'object':
        hits += _field_marks(rule, verdicts, project_of, batch.fields_by_hash, objects, batch)
    # object rules: the field marks of the objects asked again are replaced by these
    asked = [v.object_key for v in verdicts if v.field_name is None] if rule.target == 'object' else None
    object_fields = {key: {name for name, _ in batch.fields_by_hash.get(entry['row']['content_hash'], [])}
                     for key, entry in objects.items()} if rule.target == 'object' else None
    extra = {'rollout_id': rollout_id} if rollout_id is not None else {}
    upsert_llm_hits(hits, is_main=is_main, rule_id=rule.id, asked_objects=asked, object_fields=object_fields,
                    prompt_version=lifecycle.code_core_version(rule), **extra)
    return len(hits)


# A service run re-reads the external executor's reservations before each chunk of this many
# objects of a rule: objects reserved by an external run prepared while the service run is in
# progress (the service selects the candidates of every rule up front) are left to it. The
# remaining overlap is at most one chunk per rule (objects already sent to the model when the
# reservation appeared); the apply then expires those items (no longer candidates).
RESERVED_RECHECK_EVERY = 25


def _ask_chunk(rule, chunk: List, backend, concurrency: int, stop: Callable[[], bool]) -> Tuple[List, List]:
    """The model calls of one chunk: ``[(obj, result)]`` in chunk order for the objects asked, and the objects not
    asked because ``stop()`` turned true meanwhile. With ``concurrency`` > 1 the objects are asked from a thread pool
    (at most that many calls in flight; the backend is thread-safe); results are collected and stored by the caller
    in chunk order, so the verdict writes do not depend on which call finished first. A stop lets the calls in
    flight finish (their answers are kept) and asks no new object."""
    if concurrency <= 1 or len(chunk) <= 1:
        asked, left = [], list(chunk)
        while left:
            obj = left.pop(0)
            asked.append((obj, llm_rule_object_verdicts(rule, [obj], backend)))
            if stop() and left:
                break
        return asked, left

    from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait as wait_futures
    results: Dict[int, object] = {}
    left = list(chunk)
    running = {}
    with ThreadPoolExecutor(max_workers=min(concurrency, len(chunk)), thread_name_prefix="llm-call") as pool:
        while left or running:
            while left and len(running) < concurrency and not (stop() and running):
                index = len(chunk) - len(left)
                obj = left.pop(0)
                running[pool.submit(llm_rule_object_verdicts, rule, [obj], backend)] = index
            if not running:
                break
            done, _ = wait_futures(list(running), return_when=FIRST_COMPLETED)
            for future in done:
                results[running.pop(future)] = future.result()
            if stop():
                # finish what is in flight, ask nothing new
                for future in list(running):
                    results[running.pop(future)] = future.result()
                break
    asked = [(chunk[i], results[i]) for i in sorted(results)]
    return asked, left


def _unreserved(rule, llm_objects: List) -> Tuple[List, int]:
    """``llm_objects`` without the ones the external executor holds now, and how many were dropped."""
    reserved = get_reserved_llm_objects(rule.id, rule.version)
    if not reserved:
        return llm_objects, 0
    kept = [o for o in llm_objects if o.object_key not in reserved]
    return kept, len(llm_objects) - len(kept)


def run_llm_rule(rule, branch_id: int, project_path: str, is_main: bool, backend=None, progress=None,
                 batch: Optional[LlmRuleBatch] = None, skip_reserved: bool = True, migration: Optional[bool] = None,
                 max_objects: Optional[int] = None, rollout_id: Optional[int] = None) -> int:
    """Run one LLM rule on the candidate subjects of a branch; returns the number of verdicts.
    Raises ``LlmRuleIncomplete`` (after storing the verdicts it got) when some objects failed.

    Classifier rule (field target, no category): every candidate field gets a verdict from
    ``classify`` (category = the classifier's). Other rules: ``llm_rule_verdicts`` with the
    rule's prompt, target and category. ``progress`` (``JobProgress``): counts the objects;
    ``batch``: candidates already selected (``llm_rule_batch``).

    The objects go to the model in chunks of ``RESERVED_RECHECK_EVERY``; before each chunk
    the objects reserved by the external executor meanwhile are dropped (``skip_reserved``;
    counted as done, ``skipped_objects`` in the progress) and the verdicts of each chunk are
    stored at once. Within a chunk up to LLM_CONCURRENCY model calls are in flight (``_ask_chunk``,
    one object per call); the verdicts are stored in chunk order whatever order the calls finish
    in, and the shared rate limit (LLM_RATE_PER_MIN, ``discovery_common.llm_rate``) is applied by
    the backend.

    Graceful stop (``jobs.stop_requested()``, the worker got SIGTERM): the chunk ends after the
    object being asked, its verdicts are stored and ``RequeueJob`` is raised - no answer the
    model already gave is lost, the job goes on (without using an attempt) with the subjects
    still without a verdict."""

    if batch is None:
        batch = llm_rule_batch(rule, branch_id, project_path, skip_reserved=skip_reserved, migration=migration,
                               max_objects=max_objects)
        if batch is not None and progress is not None:
            progress.add_total(len(batch))
    if batch is None:
        return 0

    settings = get_settings()
    concurrency = max(1, int(getattr(settings, "llm_concurrency", 1) or 1))
    stored = failed = skipped = 0
    errors = ErrorLog()                 # why objects failed: the job's progress and the error message
    pending = list(batch.llm_objects)
    while pending:
        if jobs.stop_requested():
            if progress is not None:
                progress.flush(force=True)
            raise jobs.stopping(f"LLM rule {rule.name} on branch {branch_id}: {stored} verdicts stored, "
                                f"{len(pending)} objects left")
        chunk, pending = pending[:RESERVED_RECHECK_EVERY], pending[RESERVED_RECHECK_EVERY:]
        if skip_reserved:
            chunk, dropped = _unreserved(rule, chunk)
            if dropped:
                skipped += dropped
                if progress is not None:
                    progress.skip(dropped)
            if not chunk:
                continue
        verdicts, asked = [], []
        # one object per call, LLM_CONCURRENCY calls in flight; a stop waits for the calls in flight only
        answered, not_asked = _ask_chunk(rule, chunk, backend, concurrency, jobs.stop_requested)
        stop = bool(not_asked) or jobs.stop_requested()
        for obj, result in answered:        # progress and errors in chunk order, from this thread only
            asked.append(obj.object_key)
            if result:
                verdicts.extend(result)
            if getattr(result, 'failed', 0):
                failed += result.failed
                reason = (getattr(result, 'errors', None) or {}).get(obj.object_key) or "no verdict (the call or the answer failed)"
                errors.add(reason, rule_id=rule.id, rule_name=rule.name, object_name=obj.name, object_key=obj.object_key)
                if progress is not None:
                    progress.error(reason, rule=rule, obj=obj)
                    progress.step(False)
            elif progress is not None and not getattr(result, 'deferred', 0):
                progress.step(True)
        if verdicts:
            store_llm_verdicts(rule, verdicts, batch.only(asked), is_main, rollout_id=rollout_id)
            stored += len(verdicts)
            positives = sum(1 for v in verdicts if v.positive)
            logger.info(f"LLM rule {rule.name} v{rule.version} on branch {branch_id}: {len(verdicts)} verdicts, "
                        f"{positives} positive")
        if stop:
            if progress is not None:
                progress.flush(force=True)
            raise jobs.stopping(f"LLM rule {rule.name} on branch {branch_id}: {stored} verdicts stored after a chunk, "
                                f"{len(chunk) - len(asked) + len(pending)} objects left")

    if skipped:
        logger.info(f"LLM rule {rule.name} v{rule.version} on branch {branch_id}: {skipped} objects reserved by "
                    f"an external run meanwhile, left to it")
    if failed:
        # the verdicts got so far are stored; the failed objects are still candidates
        logger.info(f"LLM rule {rule.name} v{rule.version} on branch {branch_id}: {failed} objects failed: "
                    f"{errors.summary()}")
        raise LlmRuleIncomplete(rule.name, stored, failed, total=len(batch), summary=errors.summary())
    return stored


def _rule_batches(rules, branch_id: int, project_path: str, progress=None, skip_reserved: bool = True,
                  migration: Optional[bool] = None, max_objects: Optional[int] = None
                  ) -> List[Tuple[object, Optional[LlmRuleBatch]]]:
    """Candidates of every rule first, so the progress total is known before the first call."""
    batches = []
    extra = {k: v for k, v in (('migration', migration), ('max_objects', max_objects)) if v is not None}
    for rule in rules:
        try:
            batches.append((rule, llm_rule_batch(rule, branch_id, project_path, skip_reserved=skip_reserved,
                                                 **extra)))
        except Exception as e:
            logger.error(f"LLM rule {rule.name}: candidates of branch {branch_id} not selected: {describe(e)}")
            if progress is not None:
                progress.error(e, rule=rule, where="candidate selection")
            batches.append((rule, e))
    if progress is not None:
        progress.start(sum(len(b) for _, b in batches if isinstance(b, LlmRuleBatch)))
    return batches


def llm_rules(settings=None) -> List:
    """Enabled LLM rules (all of them made in the UI / REST / MCP: there is no env-managed rule any more)."""
    return get_rules('llm')


def run_llm_rules(branch_id: int, project_path: str, is_main: bool, migration: Optional[bool] = None) -> int:
    """Every enabled LLM rule on the candidate subjects of a branch (errors isolated per rule); ``migration``: the
    stale verdicts of older rule versions too (an MR delta: few objects, asked again on the MR's activity)."""
    return _run_llm_rules(branch_id, project_path, is_main, migration=migration)[0]


def _candidates_failure(rule, exc: Exception) -> str:
    return f"LLM rule '{rule.name}': candidates not selected: {describe(exc)}"


def _rule_failure(rule, exc: Exception) -> str:
    """One line per rule that failed or is incomplete, for the job's last_error."""
    if isinstance(exc, LlmRuleIncomplete):
        return str(exc)
    return f"LLM rule '{rule.name}' failed: {describe(exc)}"


def _run_llm_rules(branch_id: int, project_path: str, is_main: bool, progress=None,
                   migration: Optional[bool] = None) -> Tuple[int, List[str]]:
    """``(verdicts, failures)``: one line per rule that failed or is incomplete, saying why
    (``LLM rule 'x': 3 of 120 objects failed: LlmError: ... (2), APITimeoutError (1)``)."""

    settings = get_settings()

    if not llm_configured(settings):
        return 0, []

    total, failed = 0, []
    rules = llm_rules(settings)
    for rule, batch in _rule_batches(rules, branch_id, project_path, progress, migration=migration):
        if isinstance(batch, Exception):
            failed.append(_candidates_failure(rule, batch))
            continue
        try:
            total += run_llm_rule(rule, branch_id, project_path, is_main, progress=progress, batch=batch) \
                if batch is not None else 0
        except jobs.RequeueJob:
            raise                       # stopping: the verdicts got so far are stored
        except LlmRuleIncomplete as e:
            total += e.verdicts
            failed.append(_rule_failure(rule, e))
            logger.error(f"LLM rule {rule.name} incomplete on branch {branch_id}: {e}")
        except Exception as e:
            failed.append(_rule_failure(rule, e))
            if progress is not None:
                progress.error(e, rule=rule, where="rule run")
            logger.error(f"LLM rule {rule.name} failed on branch {branch_id}: {describe(e)}")
    record_llm_coverage(branch_id, rules, after_run=True)
    return total, failed


def record_llm_coverage(branch_id: int, rules=None, after_run: bool = False) -> None:
    """Recount what the LLM rules (default: every enabled one) have answered of a branch's
    snapshot (``services.llm_coverage_service``, table ``llm_coverage``; no model call). Called
    after an LLM run of the rules on the branch (``after_run``: what is left unanswered and not
    held by an external run failed in that run) and after a snapshot save. Best effort: the
    ``llm_coverage`` job recomputes rows that stayed stale."""
    try:
        from services import llm_coverage_service
        llm_coverage_service.refresh(branch_id, rules=rules, after_run=after_run)
    except Exception as e:
        logger.warning(f"LLM coverage of branch {branch_id} not recorded: {e}")


def selected_llm_rules(branch, rule_ids) -> Optional[List]:
    """The enabled LLM rules among ``rule_ids``; None when the project is in inventory mode."""
    project_path = getattr(branch, 'project_path', None)
    if is_inventory(branch.project_id):
        logger.info(f"Project {project_path} is in inventory mode: no LLM rules")
        return None
    wanted = {int(r) for r in rule_ids}
    rules = [rule for rule in llm_rules() if rule.id in wanted]
    if not rules:
        logger.info(f"LLM rules {sorted(wanted)} are gone or disabled, nothing to run on {project_path}")
    return rules


def run_selected_llm_rules(branch, rule_ids, progress=None, migration: Optional[bool] = None,
                           max_objects: Optional[int] = None, rollout_id: Optional[int] = None) -> bool:
    """Run only the LLM rules ``rule_ids`` on one branch: a main snapshot or an MR source
    delta (``POST /llm_rules/{id}/run``, e.g. a new rule over projects already scanned).
    Only subjects without a verdict of the rule's current version go to the model, so a
    second run costs nothing; no scan marker is involved. Inventory projects are skipped.
    A slice of a rule rollout (``rollout_id``): ``migration`` (the stale verdicts too), at most ``max_objects``
    objects of the rule. Returns True; raises ``ScanError`` naming the rules that failed and why
    (the verdicts of the other rules, and of the objects that succeeded, are stored)."""

    project_path = getattr(branch, 'project_path', None)
    settings = get_settings()

    if not llm_configured(settings):
        logger.info(f"LLM is not configured, rules {rule_ids} not run on {project_path}")
        return True
    rules = selected_llm_rules(branch, rule_ids)
    if not rules:
        if progress is not None:
            progress.start(0)
        return True

    failed: List[str] = []
    for rule, batch in _rule_batches(rules, branch.id, project_path, progress, migration=migration,
                                     max_objects=max_objects):
        if isinstance(batch, Exception):
            failed.append(_candidates_failure(rule, batch))
            continue
        if batch is None:
            continue
        try:
            verdicts = run_llm_rule(rule, branch.id, project_path, is_main=branch.is_main, progress=progress,
                                    batch=batch, rollout_id=rollout_id)
            logger.info(f"LLM rule {rule.name} v{rule.version} on {project_path}, branch {branch.branch_name}: "
                        f"{verdicts} new verdicts")
        except jobs.RequeueJob:
            raise
        except Exception as e:
            failed.append(_rule_failure(rule, e))
            if progress is not None and not isinstance(e, LlmRuleIncomplete):
                progress.error(e, rule=rule, where="rule run")
            logger.error(f"LLM rule {rule.name} failed on {project_path}, branch {branch.branch_name}: {describe(e)}")
    record_llm_coverage(branch.id, rules, after_run=True)
    if failed:
        raise ScanError("; ".join(failed))
    return True


def llm_score_branch(branch, progress=None) -> bool:
    """Every enabled LLM rule on a main branch (``llm_score`` jobs). Returns True; raises
    ``ScanError`` naming the rules that failed or are incomplete and why (no scan marker then: the
    job is retried and only the subjects still without a verdict go to the model again)."""

    project_path = getattr(branch, 'project_path', None)
    branch_name = getattr(branch, 'branch_name', None)

    try:

        settings = get_settings()

        if not llm_configured(settings):
            return True

        if is_inventory(branch.project_id):
            logger.info(f"Project {project_path} is in inventory mode: no LLM rules")
            return True

        commit = branch.scanned_commit or branch.commit
        rules = llm_rules(settings)

        scan = _scan_marker('llm-scorer', branch.project_id, branch.id, project_path, branch_name, commit, [])
        # the rules' versions (their numbers change on every activation, a new core prompts / model version too);
        # the core prompts of the code are not in it: a deploy does not re-ask the branches (rule rollouts do)
        scan.rules_version = f"{RULES_VERSION}+llm.{rules_fingerprint(rules)}"

        if not get_scan(scan):

            scored, failed = _run_llm_rules(branch.id, project_path, is_main=True, progress=progress)

            logger.info(f"Project {project_path}, branch {branch_name} llm scored {scored} subjects")

            if failed:
                # no marker: the job is retried (with backoff) and a later llm_score of this
                # commit runs again; only subjects still without a verdict go to the model
                logger.error(f"LLM rules failed on {project_path}, branch {branch_name}, not marked as scored: "
                             + "; ".join(failed))
                raise ScanError("; ".join(failed))

            insert_scan(scan)

        else:
            logger.info(f"Already exist scan {scan.scanner} (ver {scan.rules_version}) for {project_path}, branch {branch_name}")

        return True

    except (jobs.RequeueJob, ScanError):
        raise

    except Exception as e:
        error = scan_error(e)
        logger.error(f"Failed to score project {project_path}, branch {branch_name}: {error.reason}")
        raise error from e


#######################################
##  Discovery                       ###
#######################################

def _known_parsers(configured: Iterable[str]) -> List[str]:
    """PARSERS setting without unknown names (they are skipped with a warning, as before,
    so that a typo does not turn every scan into a partial one that is retried forever)."""

    configured = list(configured)

    if 'all' in configured:
        return ['all']

    available = ParserFactory.get_parser_types()
    known = [parser for parser in configured if parser in available]

    unknown = [parser for parser in configured if parser not in available]
    if unknown:
        logger.warning(f"Unknown parsers in PARSERS are skipped: {unknown}")

    return known


def to_core_score_rule(rule) -> Optional[ScoreRule]:
    """A ``rules`` row of kind keyword as the core's ``ScoreRule`` (P1-6). The project scope
    (``project_re``, a regex) is applied by the caller; None (with a warning) when the row is
    not a valid core rule (e.g. no matcher, or no category for a scoring rule)."""

    scope = rule.scope or {}
    action = scope.get('action') or 'score'
    # the core needs a tag to score with: category, else the rule name (exclude: any tag)
    tag = scope.get('tag') or rule.category or (None if action == 'exclude' else rule.name)
    try:
        return ScoreRule(
            id=rule.id, name=rule.name, mode=rule.mode or 'auto', enabled=rule.enabled is not False,
            parser=scope.get('parser') or None, object_name=scope.get('object_re') or None,
            object_type=scope.get('object_type_re') or None, field_name=scope.get('field_re') or None,
            field_type=scope.get('field_type_re') or None, severity=rule.severity or 'medium',
            tag=tag, action=action, fields_all=scope.get('fields_all') or [],
            fields_none=scope.get('fields_none') or [], min_groups=scope.get('min_groups'),
            tags=getattr(rule, 'tags', None) or [],
        )
    except Exception as e:
        logger.warning(f"Keyword rule {rule.id} ({rule.name}) is not a valid core rule, skipped: {e}")
        return None


def build_score_config(settings, rules, project_path, parsers=None) -> ScoreConfig:
    """Per-project core ``ScoreConfig`` (P1-6): default keyword scoring (``score_tags``), the
    PARSERS setting and the enabled keyword rules whose ``project_re`` matches
    ``project_path`` as ``score_rules`` (``exclude`` rules become core exclusions).

    The built-in ``kw-fields`` / ``kw-props`` rules are not mapped: they stand for ``score_tags`` (both disabled:
    the core does no ``score_tags`` scoring at all).
    No AI settings are put in the config: LLM rules run separately, on candidates only.
    """

    parser_names = _known_parsers(parsers or settings.parsers)

    if isinstance(rules, InventoryRules):
        # inventory mode: parse only, no categorisation
        return ScoreConfig(parsers=parser_names, score_tags={})

    score_rules: List[ScoreRule] = []

    for rule in rules or []:

        if rule.kind != 'keyword' or rule.enabled is False or _is_core(rule):
            continue
        if getattr(rule, 'deleted_at', None) is not None:
            continue
        if not _scope_matches(rule.scope, project_path):
            continue

        core_rule = to_core_score_rule(rule)
        if core_rule is not None:
            score_rules.append(core_rule)

    if rules is not None and not any(_is_core(rule) and rule.enabled is not False for rule in rules):
        # the built-in keyword rules are disabled (the default): no score_tags keyword scoring
        return ScoreConfig(parsers=parser_names, score_rules=score_rules, score_tags={})
    return ScoreConfig(
        parsers=parser_names,
        score_rules=score_rules,
    )


class ScanStatus(str):
    """The status of a core scan: ``'scanned'`` or ``'partial'`` (compares as a str); ``errors``
    is the core's ``{parser: error}`` of a partial one."""
    errors: Dict[str, str]

    def __new__(cls, value: str, errors: Optional[Dict[str, str]] = None):
        status = super().__new__(cls, value)
        status.errors = dict(errors or {})
        return status


def run_discovery_scan(project_path, project_id, branch_id, branch_name, branch_commit, rules,
                       parsers=None) -> Tuple[List[ObjectRecord], str]:
    """Scan the cloned branch with the core pipeline (parsers -> exclude_scan -> keyword
    scoring, with the per-project config) and map the objects to storage records.

    Returns ``(records, status)``: ``'scanned'`` only when every parser succeeded; a partial
    scan (``ScanStatus`` with the parsers' ``errors``) does not delete anything and is not
    recorded, so the branch is retried. No known parser configured is a permanent ``ScanError``.
    """

    # The checkout of the running job's workspace (``./code/...`` outside a job)
    code_folder = checkout_dir(project_id, branch_id, branch_commit)

    config = build_score_config(get_settings(), rules, project_path, parsers=parsers)

    if not config.parsers:
        logger.error(f"No known parsers configured, nothing to scan for {project_path}, branch {branch_name}")
        raise ScanError("no known parser is configured (PARSERS setting), nothing to scan", permanent=True)

    _phase("parse", parsers=list(config.parsers))
    result = appsec_discovery.scan(code_folder, config)

    for parser, error in result.errors.items():
        logger.error(f"Parser {parser} failed for {project_path}, branch {branch_name}: {error}")

    logger.info(f"Parsers {result.parsers} found {len(result.objects)} objects in {project_path}, branch {branch_name}")

    records = [from_code_object(obj, project_id) for obj in result.objects]
    unique = dedupe(records)
    if len(unique) != len(records):
        logger.warning(f"{len(records) - len(unique)} objects with a duplicate identity in {project_path}, branch {branch_name} were dropped")

    status = ScanStatus('partial' if result.errors else 'scanned', result.errors)
    _phase("save", objects=len(unique), by_parser=dict(Counter(r.parser for r in unique)),
           failed_parsers=sorted(result.errors),
           **({"parser_errors": {p: describe(e) if isinstance(e, BaseException) else str(e)[:300]
                                 for p, e in result.errors.items()}} if result.errors else {}))

    return unique, status



#######################################
##  External parsers (POST /ingest) ###
#######################################

def external_code_objects(parser: str, objects: Iterable[dict]):
    """A pushed batch as core ``CodeObject``s (identity: parser, location, type and name)."""
    from appsec_discovery.models import CodeObject, CodeObjectField, CodeObjectProp
    from appsec_discovery.models.code_object import object_identity

    result = []
    for o in objects:
        file = o.get("file") or ""
        line = int(o.get("line") or 0)
        result.append(CodeObject(
            hash=object_identity(parser, file, o["type"], o["name"]), object_name=o["name"], object_type=o["type"],
            parser=parser, file=file, line=line,
            properties={k: CodeObjectProp(prop_name=k, prop_value=str(v), file=file, line=line)
                        for k, v in (o.get("props") or {}).items()},
            fields={f["name"]: CodeObjectField(field_name=f["name"], field_type=f.get("type") or "",
                                               file=file, line=f.get("line"), comment=f.get("comment"),
                                               samples=f.get("samples"))
                    for f in o.get("fields") or []},
            comment=o.get("comment"),
        ))
    return result


def ingest_branch(branch, parser: str, force: bool = False) -> Optional[dict]:
    """Process the latest committed / processed state of ``parser`` for an external project:
    keyword rules (core scoring, exclusions; nothing in inventory mode), then the snapshot of
    that parser's objects is replaced like a parse. A state already processed with the same
    rules is skipped unless ``force``. Returns stats (``skipped`` / None when nothing to do)."""
    batch = latest_ingest_batch(branch.project_id, parser)
    if batch is None:
        logger.info(f"No pushed state of {parser} for {branch.project_path}, nothing to ingest")
        return None

    settings = get_settings()
    rules = project_rules(branch.project_id)
    scan = _scan_marker('ingest', branch.project_id, branch.id, branch.project_path, branch.branch_name,
                        f"batch-{batch['id']}", [parser], rules)
    if not force and batch["status"] == "processed" and get_scan(scan):
        logger.info(f"{parser} state {batch['id']} of {branch.project_path} already processed with these rules")
        return {"skipped": True, "batch_id": batch["id"]}

    config = build_score_config(settings, rules, branch.project_path)
    pipeline = appsec_discovery.ScanPipeline(config)
    objects = pipeline.score(pipeline.filter(external_code_objects(parser, batch["objects"])))

    records = [from_code_object(obj, branch.project_id) for obj in objects]
    unique = dedupe(records)
    if len(unique) != len(records):
        logger.warning(f"{len(records) - len(unique)} duplicate {parser} objects in state {batch['id']} of "
                       f"{branch.project_path} were dropped")
    hits = keyword_hits(unique, rules, branch.project_path)
    stats = save_main_scan(branch, scan.branch_commit, unique, hits, scan, complete=True, parsers=[parser])
    stats = {**(stats or {}), "objects": len(unique), "hits": len(hits), "batch_id": batch["id"],
             "snapshot": batch["snapshot"]}
    removed = finish_ingest_batch(batch["id"], branch.project_id, parser, branch.id, stats)
    if not isinstance(rules, InventoryRules):
        record_llm_coverage(branch.id)
    logger.info(f"Ingested {len(unique)} {parser} objects into {branch.project_path} (state {batch['id']}, "
                f"snapshot {batch['snapshot']}, {len(hits)} keyword hits, {removed} older states removed)")
    return {**stats, "llm": batch["llm"]}
