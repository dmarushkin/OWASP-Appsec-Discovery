"""Diff-based scan skip (services.diff_service, SCAN_DIFF_SKIP): which changed files matter to which parser, when a
main branch / MR scan is skipped and when a full scan is forced, the MR changed files from the compare API, and the
old behaviour with the shortcut off. GitLab is a fake; the DB is stubbed (the Postgres part is at the end)."""

from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

NOW = datetime.now(timezone.utc)


def compare_of(*paths, timeout=False, renames=(), overflow=False):
    """A GitLab compare answer: one diff entry per path (``renames``: ``(old, new)`` pairs)."""
    diffs = [{"old_path": p, "new_path": p, "new_file": False, "renamed_file": False, "deleted_file": False}
             for p in paths]
    diffs += [{"old_path": old, "new_path": new, "new_file": False, "renamed_file": True, "deleted_file": False}
              for old, new in renames]
    answer = {"commit": {"id": "new"}, "commits": [], "diffs": diffs, "compare_timeout": timeout,
              "compare_same_ref": False}
    if overflow:
        answer["overflow"] = True
    return answer


def branch(**overrides):
    data = dict(id=10, project_id=1, project_path="grp/proj", branch_name="main", is_main=True, commit="c2",
                scanned_commit="c1", scan_fingerprint=None, full_scanned_at=NOW - timedelta(hours=1),
                delta_target_commit=None)
    data.update(overrides)
    return SimpleNamespace(**data)


@pytest.fixture
def diff(scanner):
    """``services.diff_service`` with a fake GitLab: ``gl.compares`` answers ``(from, to, straight)`` lookups,
    ``gl.bases`` the merge base of ``(a, b)``; the calls are recorded."""
    gl = SimpleNamespace(compares={}, bases={}, calls=[])

    def get_gitlab_compare(project, from_commit, to_commit, straight=True):
        gl.calls.append(("compare", project, from_commit, to_commit, straight))
        answer = gl.compares.get((from_commit, to_commit, straight), gl.compares.get((from_commit, to_commit)))
        if isinstance(answer, Exception):
            raise answer
        if answer is None:
            raise AssertionError(f"no compare for {from_commit}..{to_commit} straight={straight}")
        return answer

    def get_gitlab_merge_base(project, commits):
        gl.calls.append(("merge_base", project, tuple(commits)))
        answer = gl.bases.get(tuple(commits), commits[0])      # default: the first one is the ancestor
        if isinstance(answer, Exception):
            raise answer
        return answer

    scanner.gl_service.get_gitlab_compare = get_gitlab_compare
    scanner.gl_service.get_gitlab_merge_base = get_gitlab_merge_base
    module = scanner.load("services.diff_service")
    fingerprint = module.scan_fingerprint("2.0.0+kw.abc", ["all"])
    return SimpleNamespace(module=module, gl=gl, scanner=scanner, fingerprint=fingerprint,
                           decide=lambda b, to="c2", **kw: module.decide_main(
                               b, to, kw.pop("fingerprint", fingerprint), kw.pop("parsers", ["all"]), scanner.settings()))


# ---- patterns per parser -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("parser, path", [
    ("protobuf", "api/v1/users.proto"),
    ("graphql", "schema/root.graphql"), ("graphql", "schema/types.gql"),
    ("javascript", "src/queries.ts"), ("javascript", "src/app.jsx"), ("javascript", "lib/index.cjs"),
    ("migrations", "db/migrations/0002_users.up.sql"),
    ("golang", "internal/model/user.go"),
    ("java", "src/main/java/com/acme/UserEntity.java"),
    ("python", "app/models/user.py"),
    ("swagger", "docs/openapi.yaml"), ("swagger", "api/spec.json"),
    ("terraform", "infra/main.tf"), ("terraform", "infra/vm.tf.json"),
])
def test_each_parser_declares_the_files_it_reads(diff, parser, path):
    """A change to a file the parser reads forces a full scan of a scan with that parser, and only of it."""
    settings = diff.scanner.settings()
    assert diff.module.relevant_changes([path], [parser], settings) == f"1 of 1 changed files are read by parsers {parser}"
    others = [p for p in ("protobuf", "graphql", "javascript", "migrations", "golang", "java", "python", "swagger",
                          "terraform") if p != parser]
    reason = diff.module.relevant_changes([path], others, settings)
    assert reason is None or parser in ("graphql", "swagger", "terraform"), reason   # *.json: swagger and terraform


def test_non_parser_files_do_not_matter(diff):
    settings = diff.scanner.settings()
    paths = ["README.md", "docs/design.md", ".gitlab-ci.yml.bak", "Makefile", "scripts/run.sh", "go.mod",
             "assets/logo.png", "config/app.toml"]
    assert diff.module.relevant_changes(paths, ["all"], settings) is None
    # every yaml / json file is a swagger candidate (the parser decides on the content)
    assert diff.module.relevant_changes(["package.json"], ["all"], settings).endswith("read by parsers swagger")
    assert diff.module.relevant_changes(["package.json"], ["golang", "protobuf"], settings) is None
    assert diff.module.relevant_changes([], ["all"], settings) is None
    assert diff.module.relevant_changes(["README.md", "a/b.proto", "c/d.go"], ["all"], settings) \
        == "2 of 3 changed files are read by parsers golang, protobuf"


def test_always_rescan_globs_and_the_language_gate_files(diff):
    diff.scanner.setenv(SCAN_ALWAYS_RESCAN_GLOBS="Makefile, config/*.toml")
    settings = diff.scanner.settings()
    assert settings.scan_always_rescan_globs == ["Makefile", "config/*.toml"]
    assert diff.module.relevant_changes(["README.md", "config/app.toml"], ["protobuf"], settings) \
        == "changed file 'config/app.toml' matches SCAN_ALWAYS_RESCAN_GLOBS"
    assert diff.module.relevant_changes(["Makefile"], ["protobuf"], settings).startswith("changed file 'Makefile'")
    # go.mod / package.json decide the SCAN_LANGS gate: parser files while the gate is on
    diff.scanner.setenv(SCAN_ALWAYS_RESCAN_GLOBS=None, SCAN_LANGS="go")
    assert diff.module.relevant_changes(["go.mod"], ["protobuf"], diff.scanner.settings()) \
        == "changed file 'go.mod' matches SCAN_ALWAYS_RESCAN_GLOBS"
    diff.scanner.setenv(SCAN_LANGS="all")
    assert diff.module.relevant_changes(["go.mod"], ["protobuf"], diff.scanner.settings()) is None


# ---- main branches: skip vs full --------------------------------------------------------------------------------

def test_main_scan_is_skipped_when_no_parser_file_changed(diff):
    diff.gl.compares[("c1", "c2")] = compare_of("README.md", "docs/a.md", ".gitlab-ci.yml.txt")
    decision = diff.decide(branch(scan_fingerprint=diff.fingerprint))
    assert (decision.skip, decision.reason, decision.changed_files) == (True, "no parser files changed", 3)
    assert decision.progress == {"reason": "no parser files changed", "skipped": "no parser files changed", "changed_files": 3}
    # the ancestry check (merge base) and the exact (straight) compare of the two commits
    assert diff.gl.calls == [("merge_base", "grp/proj", ("c1", "c2")), ("compare", "grp/proj", "c1", "c2", True)]


def test_main_scan_runs_fully_when_a_parser_file_changed(diff):
    diff.gl.compares[("c1", "c2")] = compare_of("README.md", "api/users.proto")
    decision = diff.decide(branch(scan_fingerprint=diff.fingerprint))
    assert not decision.skip
    assert decision.reason == "1 of 2 changed files are read by parsers protobuf" and decision.changed_files == 2
    # renames and deletions count with both paths
    diff.gl.compares[("c1", "c2")] = compare_of(renames=[("docs/old.md", "pkg/model.go")])
    assert diff.decide(branch(scan_fingerprint=diff.fingerprint)).reason.endswith("read by parsers golang")


@pytest.mark.parametrize("case, overrides, env, expected", [
    ("off", {}, {"SCAN_DIFF_SKIP": "false"}, "SCAN_DIFF_SKIP is off"),
    ("no snapshot", {"scanned_commit": None}, {}, "branch has no snapshot yet"),
    ("other fingerprint", {"scan_fingerprint": "other"}, {}, "scan configuration changed (core version, parsers or keyword rules)"),
    ("no full scan time", {"full_scanned_at": None}, {}, "no full scan recorded yet"),
    ("too old", {"full_scanned_at": NOW - timedelta(days=8)}, {}, "last full scan older than SCAN_FULL_RESCAN_DAYS=7"),
    ("too old, custom", {"full_scanned_at": NOW - timedelta(days=2)}, {"SCAN_FULL_RESCAN_DAYS": "1"},
     "last full scan older than SCAN_FULL_RESCAN_DAYS=1"),
])
def test_full_scan_is_forced_before_asking_gitlab(diff, case, overrides, env, expected):
    diff.scanner.setenv(**env)
    diff.gl.compares[("c1", "c2")] = compare_of("README.md")
    decision = diff.decide(branch(**{"scan_fingerprint": diff.fingerprint, **overrides}))
    assert (decision.skip, decision.reason) == (False, expected)
    assert diff.gl.calls == []                     # decided from the row alone


def test_full_rescan_days_zero_never_forces_on_age(diff):
    diff.scanner.setenv(SCAN_FULL_RESCAN_DAYS="0")
    diff.gl.compares[("c1", "c2")] = compare_of("README.md")
    assert diff.decide(branch(scan_fingerprint=diff.fingerprint, full_scanned_at=NOW - timedelta(days=400))).skip
    assert diff.decide(branch(scan_fingerprint=diff.fingerprint, full_scanned_at=None)).skip


def test_full_scan_when_the_scanned_commit_is_not_an_ancestor(diff):
    """A force push / rebase of the main: the merge base is an older commit, not the scanned one."""
    diff.gl.bases[("c1", "c2")] = "c0"
    diff.gl.compares[("c1", "c2")] = compare_of("README.md")
    decision = diff.decide(branch(scan_fingerprint=diff.fingerprint))
    assert (decision.skip, decision.reason) == (False, "branch commit 'c1' is not an ancestor of 'c2' (force push or rebase)")
    assert [c[0] for c in diff.gl.calls] == ["merge_base"]            # no compare asked
    diff.gl.bases[("c1", "c2")] = None                                # unrelated histories (404)
    assert not diff.decide(branch(scan_fingerprint=diff.fingerprint)).skip


def test_full_scan_when_the_compare_is_truncated(diff):
    diff.scanner.setenv(SCAN_DIFF_MAX_FILES="3")
    diff.gl.compares[("c1", "c2")] = compare_of("a.md", "b.md", "c.md")
    decision = diff.decide(branch(scan_fingerprint=diff.fingerprint))
    assert (decision.skip, decision.reason, decision.changed_files) == (
        False, "compare of branch is truncated (3 files, SCAN_DIFF_MAX_FILES=3)", 3)
    diff.scanner.setenv(SCAN_DIFF_MAX_FILES="1000")
    diff.gl.compares[("c1", "c2")] = compare_of("a.md", timeout=True)
    assert diff.decide(branch(scan_fingerprint=diff.fingerprint)).reason.startswith("compare of branch is truncated")
    diff.gl.compares[("c1", "c2")] = compare_of("a.md", overflow=True)
    assert diff.decide(branch(scan_fingerprint=diff.fingerprint)).reason.startswith("compare of branch is truncated")


def test_full_scan_when_a_changed_file_matches_the_always_rescan_globs(diff):
    diff.scanner.setenv(SCAN_ALWAYS_RESCAN_GLOBS="*.md")
    diff.gl.compares[("c1", "c2")] = compare_of("README.md")
    assert diff.decide(branch(scan_fingerprint=diff.fingerprint)).reason == "changed file 'README.md' matches SCAN_ALWAYS_RESCAN_GLOBS"


def test_compare_api_errors_fall_back_to_a_full_scan_without_failing(diff, caplog):
    """The shortcut never fails the job: any GitLab error is logged (credentials stripped) and the scan goes on."""
    diff.gl.compares[("c1", "c2")] = RuntimeError("502 Bad Gateway for https://user:glpat-abcdefghijklmnop@gitlab.example")
    decision = diff.decide(branch(scan_fingerprint=diff.fingerprint))
    assert not decision.skip and decision.reason.startswith("compare failed: RuntimeError: 502 Bad Gateway")
    assert "glpat-abcdefghijklmnop" not in decision.reason and "glpat-abcdefghijklmnop" not in caplog.text
    assert "full scan" in caplog.text
    diff.gl.bases[("c1", "c2")] = ConnectionError("timed out")
    assert diff.decide(branch(scan_fingerprint=diff.fingerprint)).reason.startswith("compare failed: ConnectionError")


def test_same_commit_is_a_skip_without_gitlab(diff):
    decision = diff.decide(branch(scan_fingerprint=diff.fingerprint, scanned_commit="c2"), to="c2")
    assert (decision.skip, decision.changed_files) == (True, 0) and diff.gl.calls == []


def test_fingerprint_follows_the_scan_configuration(diff, monkeypatch):
    import appsec_discovery
    fp = diff.module.scan_fingerprint
    base = fp("2.0.0+kw.abc", ["all"])
    assert base == fp("2.0.0+kw.abc", ["all"]) and len(base) == 16
    assert base != fp("2.0.0+kw.def", ["all"])                # keyword rules edited
    assert base != fp("2.0.0+inventory", ["all"])             # scan mode
    assert base != fp("2.0.0+kw.abc", ["protobuf", "golang"]) # parsers
    assert fp("x", ["golang", "protobuf"]) == fp("x", ["protobuf", "golang"])
    monkeypatch.setattr(appsec_discovery, "__version__", "9.9.9")
    assert base != fp("2.0.0+kw.abc", ["all"])                # core package (parsers, file patterns)


# ---- merge requests -----------------------------------------------------------------------------------------------

def mr(**overrides):
    data = dict(id=7, project_id=1, project_path="grp/proj", mr_id=42, source_branch="feature", source_branch_id=11,
                source_branch_commit="s2", target_branch="main", target_branch_id=10, target_branch_commit="t2")
    data.update(overrides)
    return SimpleNamespace(**data)


def source(**overrides):
    return branch(**{"id": 11, "branch_name": "feature", "is_main": False, "commit": "s2", "scanned_commit": "s1",
                     "delta_target_commit": "t1", **overrides})


def test_mr_rescan_is_skipped_when_neither_side_moved_in_parser_files(diff):
    diff.gl.compares[("s1", "s2")] = compare_of("README.md")
    diff.gl.compares[("t1", "t2")] = compare_of("docs/x.md", "CHANGELOG.md")
    decision = diff.module.decide_mr(mr(), source(scan_fingerprint=diff.fingerprint), diff.fingerprint, ["all"],
                                     diff.scanner.settings())
    assert (decision.skip, decision.reason, decision.changed_files) == (True, "no parser files changed", 3)
    assert diff.gl.calls == [("merge_base", "grp/proj", ("s1", "s2")), ("compare", "grp/proj", "s1", "s2", True),
                             ("compare", "grp/proj", "t1", "t2", True)]
    # the target did not move at all: one compare
    diff.gl.calls.clear()
    assert diff.module.decide_mr(mr(target_branch_commit="t1"), source(scan_fingerprint=diff.fingerprint),
                                 diff.fingerprint, ["all"], diff.scanner.settings()).skip
    assert [c[0] for c in diff.gl.calls] == ["merge_base", "compare"]


@pytest.mark.parametrize("case, env, src, compares, bases, expected", [
    ("mrs off", {"SCAN_DIFF_SKIP_MRS": "false"}, {}, {}, {}, "SCAN_DIFF_SKIP_MRS is off"),
    ("all off", {"SCAN_DIFF_SKIP": "false"}, {}, {}, {}, "SCAN_DIFF_SKIP_MRS is off"),
    ("no delta yet", {}, {"scanned_commit": None}, {}, {}, "source branch has no snapshot yet"),
    ("fingerprint", {}, {"scan_fingerprint": "other"}, {}, {}, "scan configuration changed (core version, parsers or keyword rules)"),
    ("target unknown", {}, {"delta_target_commit": None}, {}, {}, "the target commit of the stored delta is unknown"),
    ("source moved in parser files", {}, {}, {("s1", "s2"): compare_of("api/users.proto")}, {},
     "1 of 1 changed files are read by parsers protobuf"),
    ("source rebased", {}, {}, {}, {("s1", "s2"): "s0"},
     "source branch commit 's1' is not an ancestor of 's2' (force push or rebase)"),
    ("target moved in parser files", {}, {}, {("s1", "s2"): compare_of("README.md"), ("t1", "t2"): compare_of("pkg/a.go")},
     {}, "1 of 1 changed files are read by parsers golang"),
    ("target compare truncated", {}, {}, {("s1", "s2"): compare_of(), ("t1", "t2"): compare_of("a.md", timeout=True)},
     {}, "compare of target branch is truncated (1 files, SCAN_DIFF_MAX_FILES=1000)"),
    ("api error", {}, {}, {("s1", "s2"): RuntimeError("boom")}, {}, "compare failed: RuntimeError: boom"),
])
def test_mr_full_scan_rules(diff, case, env, src, compares, bases, expected):
    diff.scanner.setenv(**env)
    diff.gl.compares.update(compares)
    diff.gl.bases.update(bases)
    decision = diff.module.decide_mr(mr(), source(**{"scan_fingerprint": diff.fingerprint, **src}), diff.fingerprint,
                                     ["all"], diff.scanner.settings())
    assert (decision.skip, decision.reason) == (False, expected)


def test_mr_changed_files_from_the_compare_api(diff):
    """The files an MR changes since the merge base with its target (``straight=false``), both paths of a rename:
    what ``git diff --name-only <merge-base> HEAD`` gives; None when GitLab truncated it or failed."""
    diff.gl.compares[("t2", "s2", False)] = compare_of("api/users.proto", "api/old.proto", renames=[("a/b.go", "a/c.go")])
    assert diff.module.mr_changed_files(mr(), diff.scanner.settings()) == {"api/users.proto", "api/old.proto", "a/b.go", "a/c.go"}
    assert diff.gl.calls == [("compare", "grp/proj", "t2", "s2", False)]
    diff.gl.compares[("t2", "s2", False)] = compare_of("api/users.proto", timeout=True)
    assert diff.module.mr_changed_files(mr(), diff.scanner.settings()) is None
    diff.gl.compares[("t2", "s2", False)] = RuntimeError("502")
    assert diff.module.mr_changed_files(mr(), diff.scanner.settings()) is None
    diff.scanner.setenv(SCAN_DIFF_SKIP="false")
    diff.gl.calls.clear()
    assert diff.module.mr_changed_files(mr(), diff.scanner.settings()) is None and diff.gl.calls == []


# ---- scan_branch / scan_mr with the skip ---------------------------------------------------------------------------

@pytest.fixture
def flow(diff, monkeypatch):
    """``services.scan_service`` over the fake GitLab of ``diff`` with the DB stubbed: records clones, snapshot
    moves and saves; ``progress`` the phases written to the job."""
    from discovery_common.llm_work import CURRENT_PROGRESS, JobProgress
    from test_scanner_stage3 import CORE_RULES

    scanner = diff.scanner
    calls = SimpleNamespace(clone=[], skipped=[], main=[], delta=[], git_changed=[], written=[])
    state = {"branches": {}, "snapshot": {}, "skip_ok": True}
    scanner.gl_service.clone_gitlab_project_code = lambda *a, **kw: calls.clone.append((a, kw)) or True
    scanner.gl_service.get_gitlab_project_lang = lambda path, b: "go"
    scanner.gl_service.get_mr_changed_files = lambda *a: calls.git_changed.append(a) or None
    scanner.db_service.get_project = lambda project_id: SimpleNamespace(id=project_id, scan_mode="rules")
    scanner.db_service.get_rules = lambda kind=None: list(CORE_RULES)
    scanner.db_service.get_scan = lambda scan: None
    scanner.db_service.scan_lock = lambda branch_id: nullcontext()
    scanner.db_service.get_branch_by_id = lambda branch_id: state["branches"].get(branch_id)
    scanner.db_service.load_branch_snapshot = lambda branch_id, parsers=None: dict(state["snapshot"])
    scanner.db_service.load_snapshot_files = lambda branch_id, keys: {}
    scanner.db_service.skip_branch_scan = lambda b, commit, scan, target_commit=None: calls.skipped.append(
        (b.id, commit, scan.branch_commit, target_commit)) or state["skip_ok"]
    scanner.db_service.save_main_scan = lambda b, commit, records, hits, scan, complete=True, parsers=None, **kw: \
        calls.main.append((b.id, commit, kw))
    scanner.db_service.save_mr_delta = lambda b, commit, delta, hits, scan, complete=True, parsers=None, **kw: \
        calls.delta.append((b.id, commit, delta, kw))
    scan_service = scanner.load("services.scan_service")
    monkeypatch.setattr(scan_service, "run_discovery_scan", lambda *a, **kw: ([], scan_service.ScanStatus("scanned")))
    progress = JobProgress(None)
    progress.write = lambda patch, replace=False: calls.written.append(patch)
    token = CURRENT_PROGRESS.set(progress)
    yield SimpleNamespace(scan_service=scan_service, calls=calls, state=state, progress=progress, diff=diff,
                          fingerprint=lambda: scan_service._fingerprint(scan_service._scan_marker(
                              "discovery", 1, 10, "grp/proj", "main", "c2", ["all"], list(CORE_RULES))))
    CURRENT_PROGRESS.reset(token)


def test_scan_branch_skips_without_cloning(flow):
    flow.diff.gl.compares[("c1", "c2")] = compare_of("README.md", "docs/a.md")
    main = branch(scan_fingerprint=flow.fingerprint())
    assert flow.scan_service.scan_branch(main) is True
    assert flow.calls.clone == [] and flow.calls.main == []
    assert flow.calls.skipped == [(10, "c2", "c2", None)]                      # snapshot moved, marker at c2
    last = flow.calls.written[-1]
    assert {k: last[k] for k in ("phase", "reason", "skipped", "changed_files")} == {
        "phase": "skipped", "reason": "no parser files changed", "skipped": "no parser files changed", "changed_files": 2}
    assert last["finished_at"]
    assert flow.progress.last_phase == "skipped" and flow.progress.last_extra["skipped"] == "no parser files changed"


def test_scan_branch_scans_fully_and_records_why(flow):
    flow.diff.gl.compares[("c1", "c2")] = compare_of("README.md", "api/users.proto")
    main = branch(scan_fingerprint=flow.fingerprint())
    assert flow.scan_service.scan_branch(main) is True
    assert [a[1] for a, kw in flow.calls.clone] == ["main"] and flow.calls.skipped == []
    assert flow.calls.main == [(10, "c2", {"fingerprint": flow.fingerprint()})]     # the fingerprint is stored
    clone = next(p for p in flow.calls.written if p.get("phase") == "clone")
    assert clone["full_scan_reason"] == "1 of 2 changed files are read by parsers protobuf"
    assert flow.calls.written[-1]["phase"] == "done"
    # a forced scan / a parser subset never asks GitLab
    flow.diff.gl.calls.clear()
    assert flow.scan_service.scan_branch(main, force=True) is True
    assert flow.scan_service.scan_branch(main, parsers=["protobuf"]) is True
    assert flow.diff.gl.calls == []


def test_scan_branch_with_the_skip_off_behaves_as_before(flow):
    flow.diff.scanner.setenv(SCAN_DIFF_SKIP="false")
    flow.diff.gl.compares[("c1", "c2")] = compare_of("README.md")
    assert flow.scan_service.scan_branch(branch(scan_fingerprint=flow.fingerprint())) is True
    assert flow.diff.gl.calls == [] and flow.calls.skipped == []
    assert [a[1] for a, kw in flow.calls.clone] == ["main"] and len(flow.calls.main) == 1
    assert "full_scan_reason" not in next(p for p in flow.calls.written if p.get("phase") == "clone")


def test_scan_branch_skip_falls_back_when_the_branch_is_not_main_any_more(flow):
    flow.diff.gl.compares[("c1", "c2")] = compare_of("README.md")
    flow.state["skip_ok"] = False
    assert flow.scan_service.scan_branch(branch(scan_fingerprint=flow.fingerprint())) is True
    assert len(flow.calls.skipped) == 1 and len(flow.calls.clone) == 1


def test_scan_mr_skips_without_cloning(flow):
    fp = flow.fingerprint()
    flow.state["branches"] = {10: branch(scanned_commit="t2", scan_fingerprint=fp), 11: source(scan_fingerprint=fp)}
    flow.diff.gl.compares[("s1", "s2")] = compare_of("README.md")
    flow.diff.gl.compares[("t1", "t2")] = compare_of("docs/x.md")
    assert flow.scan_service.scan_mr(mr()) is True
    assert flow.calls.clone == [] and flow.calls.delta == []
    assert flow.calls.skipped == [(11, "s2", "s2", "t2")]              # delta_target_commit follows the target
    assert flow.calls.written[-1]["phase"] == "skipped" and flow.calls.written[-1]["changed_files"] == 2


def test_scan_mr_full_scan_uses_the_compare_for_the_delta_filter_and_a_shallow_clone(flow):
    fp = flow.fingerprint()
    flow.state["branches"] = {10: branch(scanned_commit="t2", scan_fingerprint=fp), 11: source(scan_fingerprint=fp)}
    flow.diff.gl.compares[("s1", "s2")] = compare_of("api/users.proto")                 # the source moved
    flow.diff.gl.compares[("t2", "s2", False)] = compare_of("api/users.proto")           # merge base compare
    assert flow.scan_service.scan_mr(mr()) is True
    (args, kw), = flow.calls.clone
    assert args[1] == "feature" and kw == {"shallow": True}                               # no history needed
    assert flow.calls.git_changed == []                                                   # no git diff
    assert flow.calls.delta == [(11, "s2", [], {"fingerprint": fp, "target_commit": "t2"})]
    # the compare of the merge base is truncated: history clone and git diff, as before
    flow.calls.clone.clear()
    flow.diff.gl.compares[("t2", "s2", False)] = compare_of("api/users.proto", timeout=True)
    assert flow.scan_service.scan_mr(mr()) is True
    assert flow.calls.clone[0][1] == {"shallow": False} and len(flow.calls.git_changed) == 1


def test_scan_mr_with_the_skip_off_behaves_as_before(flow):
    flow.diff.scanner.setenv(SCAN_DIFF_SKIP="false")
    fp = flow.fingerprint()
    flow.state["branches"] = {10: branch(scanned_commit="t2", scan_fingerprint=fp), 11: source(scan_fingerprint=fp)}
    assert flow.scan_service.scan_mr(mr()) is True
    assert flow.diff.gl.calls == [] and flow.calls.skipped == []
    assert flow.calls.clone[0][1] == {"shallow": False} and len(flow.calls.git_changed) == 1


def test_mr_target_moved_without_parser_files_is_not_cloned(flow):
    """The main target of an MR is behind its snapshot: moved by the skip instead of cloned and scanned."""
    fp = flow.fingerprint()
    flow.state["branches"] = {10: branch(commit="t2", scanned_commit="t1", scan_fingerprint=fp),
                              11: source(scanned_commit=None)}
    flow.diff.gl.compares[("t1", "t2")] = compare_of("README.md")
    flow.diff.gl.compares[("t2", "s2", False)] = compare_of("api/users.proto")
    assert flow.scan_service.scan_mr(mr()) is True
    assert flow.calls.skipped == [(10, "t2", "t2", None)] and flow.calls.main == []
    assert [a[1] for a, kw in flow.calls.clone] == ["feature"]                             # the source only


# ---- the job handler: no LLM run after a skip ----------------------------------------------------------------------

def test_scan_branch_job_queues_no_llm_run_after_a_diff_skip(scanner, monkeypatch):
    from discovery_common import jobs
    from discovery_common.jobs import Job

    enqueued = []
    phases = []

    def scan_branch(b, force=False, parsers=None):
        from discovery_common.llm_work import job_phase
        job_phase("skipped", reason="no parser files changed", skipped="no parser files changed", changed_files=3)
        return True

    scanner.stub("services.scan_service", "services.scan_service", scan_branch=scan_branch,
                 scan_mr=lambda m, parsers=None, llm=True: True, llm_score_branch=lambda b, progress=None: True,
                 run_selected_llm_rules=lambda b, ids, progress=None: True,
                 ingest_branch=lambda b, parser, force=False: None)
    scanner.score_service.llm_configured = lambda settings=None: True
    monkeypatch.setattr(jobs, "enqueue", lambda kind, payload=None, dedup_key=None, **kw: enqueued.append(kind) or 1)
    module = scanner.load("services.job_handlers")
    module.get_branch_by_id = lambda branch_id: branch()
    module.set_branch_processed = lambda branch_id, when=None: None
    module.scan_lock = lambda branch_id: nullcontext()
    monkeypatch.setattr(module.JobProgress, "write", lambda self, patch, replace=False: phases.append(patch["phase"]))

    module.scan_branch_job(Job(id=5, kind="scan_branch", payload={"branch_id": 10}, attempts=1, max_attempts=3, locked_by="w"))
    assert enqueued == [] and phases == ["waiting", "skipped"]

    # a plain skip (already scanned with these rules) still queues the LLM rules
    def already(b, force=False, parsers=None):
        from discovery_common.llm_work import job_phase
        job_phase("skipped", reason="already scanned with the same rules and parsers")
        return True
    module.scan_branch = already
    module.scan_branch_job(Job(id=6, kind="scan_branch", payload={"branch_id": 10}, attempts=1, max_attempts=3, locked_by="w"))
    assert enqueued == ["llm_score"]


# ---- Postgres: the snapshot move -------------------------------------------------------------------------------------

def test_skip_branch_scan_moves_the_snapshot_and_keeps_everything_else(pg_scanner):
    """``skip_branch_scan``: scanned_commit, delta_target_commit, the marker and the LLM coverage rows follow the
    commit; objects, hits, fingerprint and full_scanned_at stay. ``save_main_scan`` / ``save_mr_delta`` record the
    fingerprint, the time and the delta's target."""
    from datetime import datetime as dt
    from sqlalchemy import text
    from discovery_common import db
    from discovery_common.models import Scan
    from test_scanner_storage_pg import obj, records, setup_project

    dbs = pg_scanner.db
    project, main, feature, _ = setup_project(dbs)
    marker = lambda b, commit: Scan(scanner="discovery", rules_version="2.0.0+kw.x", parsers=["all"], project_id=b.project_id,  # noqa: E731
                                    branch_id=b.id, branch_commit=commit, project_path=b.project_path,
                                    branch_name=b.branch_name, scanned_at=dt.now())

    dbs.save_main_scan(main, "c1", records(project.id, obj("A", {"id": "int"})), [], marker(main, "c1"), fingerprint="fp-1")
    row = dbs.get_branch_by_id(main.id)
    assert (row.scanned_commit, row.scan_fingerprint) == ("c1", "fp-1") and row.full_scanned_at is not None
    with db.unit_of_work() as s:
        s.execute(text("INSERT INTO rules (kind, name, target, mode, version) VALUES ('llm', 'r1', 'object', 'auto', 1)"))
        rule_id = s.execute(text("SELECT id FROM rules WHERE name = 'r1'")).scalar()
        s.execute(text("INSERT INTO llm_coverage (branch_id, rule_id, rule_version, prompt_version, commit, candidates_total)"
                       " VALUES (:b, :r, 1, 'p', 'c1', 1)"), {"b": main.id, "r": rule_id})

    assert dbs.skip_branch_scan(dbs.get_branch_by_id(main.id), "c2", marker(main, "c2")) is True
    row = dbs.get_branch_by_id(main.id)
    assert (row.scanned_commit, row.scan_fingerprint) == ("c2", "fp-1")
    assert dbs.get_scan(marker(main, "c2")) is not None and dbs.get_scan(marker(main, "c1")) is not None
    with db.unit_of_work() as s:
        assert s.execute(text("SELECT count(*) FROM branch_objects WHERE branch_id = :b"), {"b": main.id}).scalar() == 1
        assert s.execute(text("SELECT commit FROM llm_coverage WHERE branch_id = :b"), {"b": main.id}).scalar() == "c2"

    # an MR source branch: the target of its delta is recorded by the save and moved by the skip
    dbs.save_mr_delta(feature, "s1", [], [], marker(feature, "s1"), fingerprint="fp-1", target_commit="c2")
    row = dbs.get_branch_by_id(feature.id)
    assert (row.scanned_commit, row.delta_target_commit, row.scan_fingerprint) == ("s1", "c2", "fp-1")
    assert dbs.skip_branch_scan(row, "s2", marker(feature, "s2"), target_commit="c3") is True
    row = dbs.get_branch_by_id(feature.id)
    assert (row.scanned_commit, row.delta_target_commit) == ("s2", "c3")

    # a demoted main is left alone
    with db.unit_of_work() as s:
        s.execute(text("UPDATE gitlab_branches SET is_main = false WHERE id = :b"), {"b": main.id})
    assert dbs.skip_branch_scan(main, "c3", marker(main, "c3")) is False
    assert dbs.get_branch_by_id(main.id).scanned_commit == "c2"
