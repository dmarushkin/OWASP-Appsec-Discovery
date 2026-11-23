"""Service wiring of the core ``scan()`` and the storage-v2 scan flow (P1-1, P0-2, stage 4):
per-project config with exclude rules, keyword rules -> hits, MR delta vs the target
snapshot, LLM rule candidates, SCAN_LANGS gate.

The DB layer is faked here; it is tested against Postgres in discovery_common/tests."""

from types import SimpleNamespace

import pytest

from appsec_discovery.models import CodeObject, CodeObjectField, RuleHit


def code_object(name, hash_, field_name="id", field_type="string", severity=None):
    """A parsed object; with ``severity``: scored by a core ``score_tags`` keyword (tag pci)."""
    hits = [RuleHit(rule="score_tags", rule_type="keyword", subject="field", field_name=field_name,
                    severity=severity, tags=["pci"], status="match")] if severity else None
    return CodeObject(
        hash=hash_, object_name=name, object_type="dto", parser="fake", file="/main.go", line=1,
        properties={},
        fields={field_name: CodeObjectField(field_name=field_name, field_type=field_type, file="/main.go", line=2,
                                            severity=severity, tags=["pci"] if severity else None)},
        hits=hits,
    )


def field_hits(record, field_name):
    return [h for h in record.hits if h.subject == "field" and h.field_name == field_name]


class Factory:
    """Parser factory with one parser ``fake`` returning ``objects`` (fresh copies per run)."""

    def __init__(self, objects):
        self.objects = objects

    def get_parser_types(self):
        return ["fake"]

    def get_parser(self, name):
        objects = self.objects

        class _P:
            def __init__(self, parser, source_folder):
                pass

            def run_scan(self):
                return [obj.copy(deep=True) for obj in objects]

        return _P


def rule(id=10, name="r", kind="keyword", target="field", mode="auto", scope=None, severity=None,
         category=None, enabled=True, version=1, prompt=None, deleted_at=None):
    return SimpleNamespace(id=id, name=name, kind=kind, target=target, mode=mode, scope=scope or {},
                           severity=severity, category=category, enabled=enabled, version=version, prompt=prompt,
                           deleted_at=deleted_at)


CORE_RULES = [
    rule(id=1, name="kw-fields", target="field", scope={"source": "core"}, severity=None, category=None),
    rule(id=2, name="kw-props", target="object", scope={"source": "core"}, severity=None, category=None),
]


# ---------------------------------------------------------------------------
# run_discovery_scan goes through the core pipeline (keyword scoring, excludes)
# ---------------------------------------------------------------------------

def test_run_discovery_scan_scores_objects_with_core_rules(scanner):
    scan_service = scanner.load("services.scan_service")
    scanner.patch_parser_factory(Factory([code_object("User", "h1", "email"), code_object("Ping", "h2", "id")]))

    records, status = scan_service.run_discovery_scan("grp/proj", 1, 10, "main", "abc", CORE_RULES)

    by_name = {r.name: r for r in records}
    assert status == "scanned"
    email_hits = field_hits(by_name["User"], "email")
    assert email_hits and all(isinstance(h.severity, str) for h in email_hits)
    assert any("pii" in h.tags for h in email_hits)
    assert by_name["Ping"].hits == []


def test_exclude_rule_is_applied_per_project(scanner):
    scan_service = scanner.load("services.scan_service")
    scanner.patch_parser_factory(Factory([code_object("User", "h1", "email")]))
    rules = CORE_RULES + [rule(scope={"project_re": "grp/other", "field_re": "email", "action": "exclude"}),
                          rule(scope={"project_re": "grp/proj", "object_re": "Order", "action": "exclude"})]

    records, _ = scan_service.run_discovery_scan("grp/proj", 1, 10, "main", "abc", rules)
    assert field_hits(records[0], "email")                     # rules for other projects/objects do not apply

    rules.append(rule(scope={"project_re": "grp/proj", "field_re": "email", "action": "exclude"}))
    records, _ = scan_service.run_discovery_scan("grp/proj", 1, 10, "main", "abc", rules)
    assert field_hits(records[0], "email") == []               # exclude rule of this project removes the hit


def test_build_score_config(scanner):
    scan_service = scanner.load("services.scan_service")
    settings = scanner.settings()

    cfg = scan_service.build_score_config(settings, CORE_RULES + [
        rule(id=11, scope={"field_re": "card", "action": "exclude"}),
        rule(id=12, scope={"action": "exclude"}),                            # no matcher -> skipped
        rule(id=13, name="emails", scope={"field_re": "email"}, category="pii", severity="high", mode="review"),
        rule(id=14, scope={"project_re": "other", "field_re": "x", "action": "exclude"}),
        rule(id=15, scope={"field_re": "y", "action": "exclude"}, enabled=False),
        rule(id=16, name="no-category", scope={"object_re": "Order", "parser": "go"}),
        rule(id=17, scope={"field_re": "z"}, deleted_at="2026-11-20"),
    ], "grp/proj")

    assert cfg.parsers == ["all"]
    # P1-6: DB keyword rules are the core's score_rules (built-in kw-fields / kw-props rules are not)
    assert [r.id for r in cfg.score_rules] == ["11", "13", "16"]
    by_id = {r.id: r for r in cfg.score_rules}
    assert (by_id["13"].field_name, by_id["13"].tag, by_id["13"].severity, by_id["13"].mode) == (
        "email", "pii", "high", "review")
    assert (by_id["16"].object_name, by_id["16"].parser, by_id["16"].tag) == ("Order", "go", "no-category")
    assert [e.field_name for e in cfg.effective_exclude_scoring()] == ["card"]
    assert cfg.ai_local is None and cfg.ai_api is None


# ---------------------------------------------------------------------------
# keyword rules -> hit rows
# ---------------------------------------------------------------------------

def test_keyword_hits_core_and_db_rules(scanner):
    """The core scan records the hits (score_tags + the DB rules mapped to score_rules); the
    scanner maps them to rows of the DB rules, with the status of each DB rule's mode."""
    from discovery_common import keys

    scan_service = scanner.load("services.scan_service")
    scanner.patch_parser_factory(Factory([code_object("UserCard", "h1", "card_number")]))

    rules = CORE_RULES + [
        rule(id=20, name="obj", target="object", mode="review", scope={"object_re": "Card"}, severity="medium", category="fin"),
        rule(id=21, name="fld", scope={"field_re": "number", "field_type_re": "str"}, severity="high", category="pii"),
        rule(id=22, name="other project", scope={"project_re": "other/", "field_re": "card"}, category="x"),
        rule(id=23, name="excl", scope={"field_re": "card", "action": "exclude"}, category="pii"),
        rule(id=24, name="off", scope={"field_re": "card"}, category="x", enabled=False),
    ]

    records, status = scan_service.run_discovery_scan("grp/proj", 1, 10, "main", "abc", rules)
    hits = scan_service.keyword_hits(records, rules, "grp/proj")
    record = records[0]

    got = {(h["rule_id"], h["field_name"], h["status"], h["severity"], h["category"]) for h in hits}
    # score_tags: card_number is finance; rule 21 (pii) is excluded by rule 23 (tag pii) - core exclusions
    assert got == {
        (1, "card_number", "match", "high", "finance"),
        (20, None, "pending_review", "medium", "fin"),
    }
    by_rule = {h["rule_id"]: h for h in hits}
    assert by_rule[20]["subject_key"] == record.object_key
    assert by_rule[1]["subject_key"] == keys.field_key(record.object_key, "card_number")

    # without the exclusion rule 21 hits the field
    rules = [r for r in rules if r.id != 23]
    records, _ = scan_service.run_discovery_scan("grp/proj", 1, 10, "main", "abc", rules)
    got = {(h["rule_id"], h["field_name"], h["status"]) for h in scan_service.keyword_hits(records, rules, "grp/proj")}
    assert (21, "card_number", "match") in got

    # a core rule in review mode makes the score_tags hits pending
    rules = [rule(id=1, name="kw-fields", mode="review", scope={"source": "core"})]
    got = {(h["rule_id"], h["status"]) for h in scan_service.keyword_hits(records, rules, "grp/proj")}
    assert got == {(1, "pending_review")}


def test_disabled_builtin_keyword_rules_do_no_score_tags_scoring(scanner):
    """kw-fields / kw-props are disabled on new installs: the core does no score_tags scoring and no hit is made."""
    scan_service = scanner.load("services.scan_service")
    scanner.patch_parser_factory(Factory([code_object("User", "h1", "email")]))
    off = [rule(id=1, name="kw-fields", target="field", scope={"source": "core"}, enabled=False),
           rule(id=2, name="kw-props", target="object", scope={"source": "core"}, enabled=False)]
    assert scan_service.build_score_config(scanner.settings(), off, "grp/proj").score_tags == {}
    records, _ = scan_service.run_discovery_scan("grp/proj", 1, 10, "main", "abc", off)
    assert field_hits(records[0], "email") == [] and scan_service.keyword_hits(records, off, "grp/proj") == []


def test_rules_fingerprint_changes_with_edits(scanner):
    scan_service = scanner.load("services.scan_service")
    base = [rule(id=1), rule(id=2)]
    fp = scan_service.rules_fingerprint(base)
    assert scan_service.rules_fingerprint(list(reversed(base))) == fp
    assert scan_service.rules_fingerprint([rule(id=1, version=2), rule(id=2)]) != fp
    assert scan_service.rules_fingerprint([rule(id=1, enabled=False), rule(id=2)]) != fp
    assert scan_service.rules_fingerprint([rule(id=1, mode="review"), rule(id=2)]) != fp


# ---------------------------------------------------------------------------
# scan_mr: target snapshot, delta
# ---------------------------------------------------------------------------

def make_mr(**overrides):
    data = dict(
        id=7, project_id=1, project_path="grp/proj", mr_id=42,
        source_branch="feature", source_branch_id=11, source_branch_commit="aaa",
        target_branch="main", target_branch_id=10, target_branch_commit="bbb",
    )
    data.update(overrides)
    return SimpleNamespace(**data)


def branch(id, name, is_main, scanned_commit=None):
    return SimpleNamespace(id=id, branch_name=name, is_main=is_main, scanned_commit=scanned_commit, project_id=1,
                           project_path="grp/proj", commit="head")


@pytest.fixture
def mr_env(scanner, monkeypatch):
    from discovery_common.mapping import from_code_object

    from contextlib import nullcontext

    calls = {"clone": [], "main": [], "delta": [], "lang": [], "locks": [], "changed": []}
    state = {"status": {11: "scanned", 10: "scanned"},
             "branches": {10: branch(10, "main", True, "bbb"), 11: branch(11, "feature", False)},
             "snapshot": {}, "changed_files": None, "files": {}}

    scanner.db_service.scan_lock = lambda branch_id: calls["locks"].append(branch_id) or nullcontext()
    scanner.db_service.get_project = lambda project_id: SimpleNamespace(id=project_id, scan_mode=state["scan_mode"])
    state["scan_mode"] = "rules"
    scanner.db_service.load_snapshot_files = lambda branch_id, keys: {k: state["files"].get(k) for k in keys}
    scanner.gl_service.get_mr_changed_files = lambda *a: calls["changed"].append(a) or state["changed_files"]

    scanner.gl_service.clone_gitlab_project_code = lambda *a, **kw: calls["clone"].append(a) or True
    scanner.gl_service.get_gitlab_project_lang = lambda path, branch: calls["lang"].append(branch) or "go"
    scanner.db_service.get_rules = lambda kind=None: list(CORE_RULES)
    scanner.db_service.get_branch_by_id = lambda branch_id: state["branches"].get(branch_id)
    scanner.db_service.load_branch_snapshot = lambda branch_id, parsers=None: dict(state["snapshot"])
    scanner.db_service.save_main_scan = lambda b, commit, records, hits, scan, complete=True, parsers=None, **kw: calls["main"].append((b.id, commit, records, complete))
    scanner.db_service.save_mr_delta = lambda b, commit, delta, hits, scan, complete=True, parsers=None, **kw: calls["delta"].append((b.id, commit, delta, hits, scan, complete))
    # no GitLab compare in these tests: the diff-based skip finds no snapshot to reuse, the changed files come
    # from the git diff of the checkout (get_mr_changed_files), as without SCAN_DIFF_SKIP
    scanner.gl_service.get_gitlab_compare = lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("no compare here"))

    state["partial"] = set()        # (branch_id, commit) with a partial main scan marker
    scanner.db_service.get_scan = lambda scan: (scan.branch_id, scan.branch_commit) in state["partial"] \
        and scan.rules_version.endswith("+partial")

    def setup(source, target):
        scan_service = scanner.load("services.scan_service")
        objects = {11: source, 10: target}

        def fake_scan(path, pid, branch_id, *a, parsers=None):
            return [from_code_object(o, pid) for o in objects[branch_id]], state["status"][branch_id]

        monkeypatch.setattr(scan_service, "run_discovery_scan", fake_scan)
        return scan_service

    def snapshot_of(objs):
        records = [from_code_object(o, 1) for o in objs]
        state["snapshot"] = {r.object_key: r.content_hash for r in records}

    return SimpleNamespace(calls=calls, state=state, setup=setup, snapshot_of=snapshot_of, scanner=scanner)


def test_scan_mr_stores_delta_vs_current_main_snapshot(mr_env):
    common, changed_t = code_object("Common", "c"), code_object("Changed", "x", "a")
    changed_s, new, gone = code_object("Changed", "x", "b"), code_object("UserCard", "n", "card_number", severity="high"), code_object("Gone", "g")
    mr_env.snapshot_of([common, changed_t, gone])
    scan_service = mr_env.setup([common, changed_s, new], [])

    assert scan_service.scan_mr(make_mr()) is True

    calls = mr_env.calls
    assert calls["clone"] == [("grp/proj", "feature", 1, 11, "aaa")]   # current target snapshot: no target clone
    assert calls["main"] == []                                         # target snapshot is current
    assert calls["locks"] == [10]                                      # read under the target's scan lock
    assert calls["changed"] == [(1, 11, "aaa", "main", "bbb")]
    (branch_id, commit, delta, hits, scan, complete), = calls["delta"]
    assert (branch_id, commit, complete) == (11, "aaa", True)
    assert sorted((c, r.name if r else None) for c, _, r in delta) == [
        ("added", "UserCard"), ("modified", "Changed"), ("removed", None)]
    assert {h["field_name"] for h in hits} == {"card_number"}         # core keyword hit on the new object only
    assert (scan.branch_id, scan.branch_commit) == (11, "aaa")
    assert scan.rules_version == "2.0.0+kw." + scan_service.rules_fingerprint(CORE_RULES)   # rule edits rescan

    assert calls["lang"] == []                                         # SCAN_LANGS=all: no language lookup


def test_scan_mr_scans_stale_main_target_first(mr_env):
    mr_env.state["branches"][10] = branch(10, "main", True, scanned_commit="old")
    scan_service = mr_env.setup([code_object("A", "a")], [code_object("A", "a")])

    assert scan_service.scan_mr(make_mr()) is True

    (branch_id, commit, records, complete), = mr_env.calls["main"]
    assert (branch_id, commit, [r.name for r in records], complete) == (10, "bbb", ["A"], True)
    assert ("grp/proj", "main", 1, 10, "bbb") in mr_env.calls["clone"]


def test_scan_mr_does_not_rescan_a_target_with_a_partial_snapshot(mr_env):
    mr_env.state["branches"][10] = branch(10, "main", True, scanned_commit="old")
    mr_env.state["partial"].add((10, "bbb"))
    scan_service = mr_env.setup([code_object("A", "a")], [code_object("A", "a")])

    assert scan_service.scan_mr(make_mr()) is True
    assert mr_env.calls["main"] == []
    assert [c[1] for c in mr_env.calls["clone"]] == ["feature"]


def test_scan_mr_target_scanned_meanwhile_is_not_scanned_again(mr_env):
    """Another job scanned the main while this MR waited for the target's lock: the re-read
    row is current, so the target is neither cloned nor scanned a second time."""
    rows = iter([branch(11, "feature", False), branch(10, "main", True, scanned_commit="old"),
                 branch(10, "main", True, scanned_commit="bbb")])
    scan_service = mr_env.setup([code_object("A", "a")], [code_object("A", "a")])
    scan_service.get_branch_by_id = lambda branch_id: next(rows)

    assert scan_service.scan_mr(make_mr()) is True
    assert mr_env.calls["main"] == []
    assert [c[1] for c in mr_env.calls["clone"]] == ["feature"]


def test_scan_mr_keeps_only_objects_of_files_changed_since_merge_base(mr_env):
    in_mr, behind = code_object("InMr", "a", "b"), code_object("Behind", "x", "old")
    target_in_mr, target_behind, target_new = code_object("InMr", "a"), code_object("Behind", "x", "new"), code_object("TargetOnly", "t")
    for obj, file in ((in_mr, "/api/mr.proto"), (target_in_mr, "/api/mr.proto"), (behind, "/api/other.proto"),
                      (target_behind, "/api/other.proto"), (target_new, "/api/pay.proto")):
        obj.file = file
    mr_env.snapshot_of([target_in_mr, target_behind, target_new])
    from discovery_common.mapping import from_code_object
    mr_env.state["files"] = {from_code_object(target_new, 1).object_key: "/api/pay.proto"}
    mr_env.state["changed_files"] = {"api/mr.proto"}
    scan_service = mr_env.setup([in_mr, behind], [])

    assert scan_service.scan_mr(make_mr()) is True
    (_, _, delta, _, _, _), = mr_env.calls["delta"]
    assert [(c, r.name if r else None) for c, _, r in delta] == [("modified", "InMr")]


def test_scan_mr_non_main_target_is_scanned_in_memory(mr_env):
    mr_env.state["branches"][10] = branch(10, "release", False)
    scan_service = mr_env.setup([code_object("A", "a"), code_object("B", "b")], [code_object("A", "a")])

    assert scan_service.scan_mr(make_mr(target_branch="release")) is True

    assert mr_env.calls["main"] == []
    (_, _, delta, _, _, _), = mr_env.calls["delta"]
    assert [(c, r.name) for c, _, r in delta] == [("added", "B")]


def test_scan_mr_partial_source_scan(mr_env):
    mr_env.state["status"][11] = "partial"
    mr_env.snapshot_of([code_object("Gone", "g")])
    scan_service = mr_env.setup([code_object("A", "a")], [])

    assert scan_service.scan_mr(make_mr()) is True
    (_, _, delta, _, _, complete), = mr_env.calls["delta"]
    assert complete is False
    assert [c for c, _, _ in delta] == ["added"]                      # no removals from a partial scan


def test_scan_mr_skips_untracked_branches(mr_env):
    del mr_env.state["branches"][11]
    scan_service = mr_env.setup([], [])

    assert scan_service.scan_mr(make_mr()) is False
    assert scan_service.scan_mr(make_mr(source_branch_id=None)) is False
    assert mr_env.calls["delta"] == []


@pytest.mark.parametrize("langs, project_lang, scanned", [
    ("go", "go", True),
    ("go,js", "js", True),
    ("go", "js", False),
])
def test_scan_langs_gate(scanner, mr_env, langs, project_lang, scanned):
    scanner.setenv(SCAN_LANGS=langs)
    scanner.gl_service.get_gitlab_project_lang = lambda path, branch: project_lang
    scan_service = mr_env.setup([code_object("A", "a")], [])

    assert scan_service.scan_mr(make_mr()) is True
    assert bool(mr_env.calls["delta"]) is scanned


def test_scan_langs_default_is_all(scanner):
    settings = scanner.settings()
    assert settings.scan_langs == ["all"]
    assert settings.scans_lang("python") and settings.scans_lang(None)


# ---------------------------------------------------------------------------
# LLM rule: candidates -> verdicts -> hits
# ---------------------------------------------------------------------------

CANDIDATE_ROWS = [
    dict(object_key="k1", content_hash="c1", project_id=1, name="User", type="dto", parser="go", file="/u.go",
         props=None, field_name="email", field_type="string", field_key="f1"),
    dict(object_key="k1", content_hash="c1", project_id=1, name="User", type="dto", parser="go", file="/u.go",
         props=None, field_name="nick", field_type="string", field_key="f2"),
]


def test_run_llm_rule_builds_hits_from_verdicts(scanner, monkeypatch):
    scanner.setenv(LLM_API_URL="https://llm.example")
    scan_service = scanner.load("services.scan_service")
    llm_rule = rule(id=3, name="llm", kind="llm", mode="review", version=4, severity=None, category=None,
                    prompt="custom prompt")
    upserted = []

    monkeypatch.setattr(scan_service, "get_llm_candidates", lambda branch_id, r: CANDIDATE_ROWS)
    monkeypatch.setattr(scan_service, "get_object_fields", lambda hashes: {"c1": [("email", "string"), ("nick", "string"), ("id", "int")]})
    monkeypatch.setattr(scan_service, "get_object_docs", lambda hashes: {})
    asked = []

    def fake_llm(objects, backend=None, prompt=None, severity=None):
        asked.append((objects, prompt))
        return [SimpleNamespace(object_key="k1", field_name="email", positive=True, category="pii", severity="medium", model="m"),
                SimpleNamespace(object_key="k1", field_name="nick", positive=False, category=None, severity=None, model="m")]

    monkeypatch.setattr(scan_service, "llm_score_objects", fake_llm)
    monkeypatch.setattr(scan_service, "upsert_llm_hits", lambda hits, is_main, **kw: upserted.append((hits, is_main)))

    assert scan_service.run_llm_rule(llm_rule, 10, "grp/proj", is_main=True) == 2

    (objects, prompt), = asked
    assert objects[0].candidates == {"email", "nick"} and len(objects[0].fields) == 3 and prompt == "custom prompt"
    (hits, is_main), = upserted
    assert is_main is True
    assert {(h["field_name"], h["status"], h["rule_version"], h["model"]) for h in hits} == {
        ("email", "pending_review", 4, "m"), ("nick", "no_match", 4, "m")}

    # out of the rule's scope: nothing is asked
    scoped = rule(id=3, name="llm", kind="llm", version=4, scope={"project_re": "other/"})
    assert scan_service.run_llm_rule(scoped, 10, "grp/proj", is_main=True) == 0
    disabled = rule(id=3, name="llm", kind="llm", version=4, enabled=False)
    assert scan_service.run_llm_rule(disabled, 10, "grp/proj", is_main=True) == 0


def test_run_llm_rules_runs_every_enabled_rule(scanner, monkeypatch):
    scanner.setenv(LLM_API_URL="https://llm.example")
    scan_service = scanner.load("services.scan_service")
    rules = [rule(id=3, name="llm", kind="llm"), rule(id=4, name="secrets", kind="llm", target="object", category="secret")]
    ran = []
    monkeypatch.setattr(scan_service, "llm_configured", lambda settings=None: True)
    monkeypatch.setattr(scan_service, "get_rules", lambda kind=None: rules if kind == "llm" else [])

    # candidates of every rule are selected first (the progress total), then each rule runs
    monkeypatch.setattr(scan_service, "llm_rule_batch",
                        lambda r, branch_id, project_path, skip_reserved=True: scan_service.LlmRuleBatch(r, branch_id, {}, [], {}))

    def fake_run(r, branch_id, project_path, is_main, backend=None, progress=None, batch=None):
        assert batch is not None and batch.rule is r
        ran.append(r.name)
        if r.name == "llm":
            raise RuntimeError("boom")                  # isolated per rule
        return 5

    monkeypatch.setattr(scan_service, "run_llm_rule", fake_run)
    assert scan_service.run_llm_rules(10, "grp/proj", is_main=False) == 5
    assert ran == ["llm", "secrets"]
    # the coverage of every rule is recounted after the run (also of the one that failed)
    assert scanner.coverage_calls == [(10, [3, 4], True)]


def test_custom_llm_rules_through_the_core_prompts(scanner, monkeypatch):
    """Field and object rules with a category: the core's run_field_rule / run_object_rule with
    the rule's prompt; match -> mode status, need_more_info -> machine need_more_info, no -> rejected."""
    import json

    from appsec_discovery.ai import FakeLlmBackend

    score_service = scanner.use_real("services.score_service")
    scan_service = scanner.load("services.scan_service")

    field_rule = rule(id=5, name="contacts", kind="llm", category="contact", severity="low", mode="auto", version=2,
                      prompt="Find contact data")
    backend = FakeLlmBackend(json.dumps({"fields": [
        {"name": "email", "verdict": "match", "reason": "an address"},
        {"name": "nick", "verdict": "need_more_info"}]}), model="fake")
    monkeypatch.setattr(score_service, "_backend", backend)
    monkeypatch.setattr(scan_service, "get_llm_backend", lambda: backend)
    monkeypatch.setattr(scan_service, "get_llm_candidates", lambda branch_id, r: CANDIDATE_ROWS)
    monkeypatch.setattr(scan_service, "get_object_fields",
                        lambda hashes: {"c1": [("email", "string"), ("nick", "string"), ("age", "int")]})
    monkeypatch.setattr(scan_service, "get_object_docs", lambda hashes: {
        "c1": ("Client contacts", {"email": ("work address", ["a@example.com"]), "age": ("full years", None)})})
    upserted = []
    monkeypatch.setattr(scan_service, "upsert_llm_hits", lambda hits, is_main, **kw: upserted.extend(hits))

    assert scan_service.run_llm_rule(field_rule, 10, "grp/proj", is_main=True) == 2
    assert {(h["field_name"], h["status"], h["category"], h["severity"], h["reason"], h["rule_version"])
            for h in upserted} == {("email", "match", "contact", "low", "an address", 2),
                                   ("nick", "need_more_info", "contact", "low", None, 2)}
    (system, user, schema), = backend.calls
    assert system == "Find contact data" and "- email" in user and "- age" not in user
    # the code comments and samples stored with the fields go into the prompt
    assert "- email: work address (e.g. a@example.com)" in user and "Client contacts" in user

    object_rule = rule(id=6, name="secrets", kind="llm", target="object", category="secret", mode="review")
    backend.calls.clear()
    backend._answer = json.dumps({"verdict": "match", "reason": "holds a token"})
    upserted.clear()
    object_rows = [dict(CANDIDATE_ROWS[0], field_name=None, field_type=None, field_key="k1")]
    monkeypatch.setattr(scan_service, "get_llm_candidates", lambda branch_id, r: object_rows)
    assert scan_service.run_llm_rule(object_rule, 10, "grp/proj", is_main=False) == 1
    (hit,) = upserted
    assert (hit["field_name"], hit["subject_key"], hit["status"], hit["reason"]) == (None, "k1", "pending_review",
                                                                                      "holds a token")
    (_, user, _), = backend.calls
    assert '"age"' in user                                    # object rules see every field
    assert '"comment": "full years"' in user and '"comment": "Client contacts"' in user



def test_llm_object_rule_mark_fields_adds_field_hits(scanner, monkeypatch):
    """mark_fields: one model call per object; the object hit plus one field hit per named field
    of the object (standard field subject keys), and the asked objects go to the stale cleanup."""
    import json

    from appsec_discovery.ai import FakeLlmBackend
    from discovery_common import keys

    scanner.use_real("services.score_service")
    scan_service = scanner.load("services.scan_service")
    backend = FakeLlmBackend(json.dumps({"verdict": "match", "reason": "a person",
                                         "fields": ["email", "nick", "ghost"]}), model="fake")
    monkeypatch.setattr(scan_service, "get_llm_backend", lambda: backend)
    object_rows = [dict(CANDIDATE_ROWS[0], field_name=None, field_type=None, field_key="k1")]
    monkeypatch.setattr(scan_service, "get_llm_candidates", lambda branch_id, r: object_rows)
    monkeypatch.setattr(scan_service, "get_object_fields",
                        lambda hashes: {"c1": [("email", "string"), ("nick", "string"), ("age", "int")]})
    monkeypatch.setattr(scan_service, "get_object_docs", lambda hashes: {})
    calls = []
    monkeypatch.setattr(scan_service, "upsert_llm_hits", lambda hits, is_main, **kw: calls.append((hits, kw)))

    marking = rule(id=7, name="person", kind="llm", target="object", category="pii", severity="high",
                   mode="review", version=3, scope={"mark_fields": True})
    assert scan_service.run_llm_rule(marking, 10, "grp/proj", is_main=True) == 1      # one verdict (the object)
    assert len(backend.calls) == 1
    (hits, kw), = calls
    assert kw == {"rule_id": 7, "asked_objects": ["k1"], "object_fields": {"k1": {"email", "nick", "age"}},
                  "prompt_version": "rule3"}
    # what the model saw: the object version (content hash) and its field names; per field its content
    assert (hits[0]["names_hash"], hits[0]["subject_hash"]) == (
        keys.names_hash(CANDIDATE_ROWS[0]["name"], ["email", "nick", "age"]), "c1")
    assert (hits[1]["names_hash"], hits[1]["subject_hash"]) == (
        keys.names_hash(CANDIDATE_ROWS[0]["name"], ["email"]), keys.field_subject_hash("email", "string", None, None))
    assert [(h["field_name"], h["subject_key"], h["status"], h["severity"], h["category"], h["reason"],
             h["model"], h["rule_version"], h["fields"]) for h in hits] == [
        (None, "k1", "pending_review", "high", "pii", "a person", "fake", 3, ["email", "nick"]),
        ("email", keys.field_key("k1", "email"), "pending_review", "high", "pii", "a person", "fake", 3, None),
        ("nick", keys.field_key("k1", "nick"), "pending_review", "high", "pii", "a person", "fake", 3, None),
    ]

    # no_match: the object verdict only (machine rejected); stale marks are cleaned up by the DB layer
    calls.clear()
    backend._answer = json.dumps({"verdict": "no_match", "fields": ["email"]})
    scan_service.run_llm_rule(marking, 10, "grp/proj", is_main=True)
    (hits, kw), = calls
    assert [(h["field_name"], h["status"]) for h in hits] == [(None, "no_match")] and kw["asked_objects"] == ["k1"]

    # without mark_fields (the default) only the object hit
    calls.clear()
    backend._answer = json.dumps({"verdict": "match", "fields": ["email"]})
    scan_service.run_llm_rule(rule(id=8, name="p", kind="llm", target="object", category="pii"), 10, "grp/proj",
                              is_main=True)
    (hits, kw), = calls
    assert [h["field_name"] for h in hits] == [None] and hits[0]["fields"] == ["email"]


def test_llm_score_objects_returns_verdicts_for_candidates_only(scanner):
    import json

    from appsec_discovery.ai import FakeLlmBackend

    score_service = scanner.use_real("services.score_service")

    backend = FakeLlmBackend(json.dumps({"fields": [{"name": "card_number", "category": "finance"}]}), model="fake-model")
    objects = [score_service.LlmObject(object_key="k", name="Card",
                                       fields=[("card_number", "string"), ("holder", "string"), ("card_id", "int")],
                                       candidates={"card_number", "holder", "card_id"})]
    verdicts = score_service.llm_score_objects(objects, backend=backend)

    assert [(v.field_name, v.positive, v.category, v.model) for v in verdicts] == [
        ("card_number", True, "finance", "fake-model"), ("holder", False, None, "fake-model")]  # card_id: id field
    [(system, user, schema)] = backend.calls                                 # one structured request
    assert "card_id" not in user and schema is not None
    assert score_service.llm_score_objects(objects) is None                  # no LLM configured


def test_llm_score_objects_skips_failed_objects(scanner):
    from appsec_discovery.ai import FakeLlmBackend

    score_service = scanner.use_real("services.score_service")
    objects = [score_service.LlmObject(object_key="k", name="Card", fields=[("pan", "string")], candidates={"pan"})]
    assert score_service.llm_score_objects(objects, backend=FakeLlmBackend("not json")) == []


def test_llm_score_objects_counts_failed_objects(scanner):
    from appsec_discovery.ai import FakeLlmBackend

    score_service = scanner.use_real("services.score_service")
    objects = [score_service.LlmObject(object_key="k", name="Card", fields=[("pan", "string")], candidates={"pan"})]
    assert score_service.llm_score_objects(objects, backend=FakeLlmBackend("not json")).failed == 1


class _DownBackend:
    model = "down"

    def complete(self, system, user, json_schema=None):
        raise ConnectionError("LLM is down")


def test_llm_score_branch_does_not_mark_the_commit_scored_when_the_llm_fails(scanner, monkeypatch):
    """LLM unavailable: no llm-scorer marker, so the job is retried and later llm_score of the
    same commit asks again (only the subjects without a verdict)."""
    scanner.setenv(LLM_API_URL="https://llm.example")
    score_service = scanner.use_real("services.score_service")
    scan_service = scanner.load("services.scan_service")
    backend = _DownBackend()
    monkeypatch.setattr(score_service, "_backend", backend)
    llm_rule = rule(id=3, name="llm", kind="llm", mode="review", version=4)
    markers, upserted = [], []
    monkeypatch.setattr(scan_service, "llm_configured", lambda settings=None: True)
    monkeypatch.setattr(scan_service, "is_inventory", lambda project_id: False)
    monkeypatch.setattr(scan_service, "get_rules", lambda kind=None: [llm_rule] if kind == "llm" else [])
    monkeypatch.setattr(scan_service, "get_scan", lambda scan: None)
    monkeypatch.setattr(scan_service, "insert_scan", lambda scan: markers.append(scan))
    monkeypatch.setattr(scan_service, "get_llm_candidates", lambda branch_id, r: CANDIDATE_ROWS)
    monkeypatch.setattr(scan_service, "get_object_fields", lambda hashes: {"c1": [("email", "string"), ("nick", "string")]})
    monkeypatch.setattr(scan_service, "get_object_docs", lambda hashes: {})
    monkeypatch.setattr(scan_service, "upsert_llm_hits", lambda hits, is_main, **kw: upserted.extend(hits))
    branch = SimpleNamespace(id=10, project_id=1, project_path="grp/proj", branch_name="main", is_main=True,
                             commit="c", scanned_commit="c")

    # the reason (rule, how many objects, the error class) travels to the job's last_error
    with pytest.raises(scan_service.ScanError, match=r"LLM rule 'llm': 1 of 1 objects failed: ConnectionError: LLM is down"):
        scan_service.llm_score_branch(branch)
    assert markers == [] and upserted == []

    # the LLM is back: verdicts are stored and the commit is marked scored
    import json
    from appsec_discovery.ai import FakeLlmBackend
    monkeypatch.setattr(score_service, "_backend", FakeLlmBackend(json.dumps({"fields": []}), model="m"))
    assert scan_service.llm_score_branch(branch) is True
    assert len(markers) == 1 and {h["field_name"] for h in upserted} == {"email", "nick"}


def test_llm_rule_partly_failed_stores_its_verdicts_and_reports_incomplete(scanner, monkeypatch):
    scanner.setenv(LLM_API_URL="https://llm.example")
    scan_service = scanner.load("services.scan_service")
    llm_rule = rule(id=3, name="llm", kind="llm", mode="review", version=4)
    upserted = []

    class Partial(list):
        failed = 1

    monkeypatch.setattr(scan_service, "get_llm_candidates", lambda branch_id, r: CANDIDATE_ROWS)
    monkeypatch.setattr(scan_service, "get_object_fields", lambda hashes: {"c1": [("email", "string")]})
    monkeypatch.setattr(scan_service, "get_object_docs", lambda hashes: {})
    monkeypatch.setattr(scan_service, "llm_score_objects", lambda *a, **kw: Partial([SimpleNamespace(
        object_key="k1", field_name="email", positive=False, category=None, severity=None, model="m")]))
    monkeypatch.setattr(scan_service, "upsert_llm_hits", lambda hits, is_main, **kw: upserted.extend(hits))

    with pytest.raises(scan_service.LlmRuleIncomplete) as err:
        scan_service.run_llm_rule(llm_rule, 10, "grp/proj", is_main=True)
    assert (err.value.verdicts, err.value.failed) == (1, 1) and len(upserted) == 1


# ---------------------------------------------------------------------------
# failure reasons reach the job (services.failures)
# ---------------------------------------------------------------------------

def test_llm_object_failures_are_recorded_with_their_reason(scanner, monkeypatch):
    """Per object: the error class and message in the job progress (bounded) and summarised in
    the LlmRuleIncomplete message; the job's last_error says which rule, how many objects, why."""
    from discovery_common.llm_work import JobProgress

    scanner.setenv(LLM_API_URL="https://llm.example")
    scan_service = scanner.load("services.scan_service")
    llm_rule = rule(id=3, name="db-tables", kind="llm", mode="review", version=4)
    rows = [{"object_key": f"k{i}", "name": f"Table{i}", "type": "table", "content_hash": "c1", "project_id": 1,
             "field_name": "email", "field_type": "string"} for i in range(4)]

    class Failed(list):
        def __init__(self, key, error):
            super().__init__()
            self.failed, self.errors = 1, {key: error}

    def verdicts(objects, *a, on_object=None, **kw):
        obj = objects[0]
        if on_object is not None:
            on_object(obj, obj.object_key == "k3")
        if obj.object_key == "k0":
            return Failed("k0", "LlmError: LLM answer truncated at max_tokens=8192 (raise LLM_MAX_TOKENS)")
        if obj.object_key == "k1":
            return Failed("k1", "LlmError: LLM answer truncated at max_tokens=8192 (raise LLM_MAX_TOKENS)")
        if obj.object_key == "k2":
            return Failed("k2", "APITimeoutError: Request timed out.")
        return [SimpleNamespace(object_key="k3", field_name="email", positive=False, category=None, severity=None,
                                model="m")]

    written = []
    monkeypatch.setattr(scan_service, "get_llm_candidates", lambda branch_id, r: rows)
    monkeypatch.setattr(scan_service, "get_object_fields", lambda hashes: {"c1": [("email", "string")]})
    monkeypatch.setattr(scan_service, "get_object_docs", lambda hashes: {})
    monkeypatch.setattr(scan_service, "llm_score_objects", verdicts)
    monkeypatch.setattr(scan_service, "upsert_llm_hits", lambda hits, is_main, **kw: None)
    progress = JobProgress(None)
    progress.write = lambda patch, replace=False: written.append(patch)

    with pytest.raises(scan_service.LlmRuleIncomplete) as err:
        scan_service.run_llm_rule(llm_rule, 10, "grp/proj", is_main=True, progress=progress)
    assert str(err.value) == ("LLM rule 'db-tables': 3 of 4 objects failed: LlmError: LLM answer truncated at "
                              "max_tokens=8192 (2), APITimeoutError: Request timed out (1) (1 verdicts stored)")
    errors = progress.snapshot()["errors"]
    assert errors["total"] == 3
    assert [(e["rule"], e["object"], e["object_key"]) for e in errors["items"]] == [
        ("db-tables", "Table0", "k0"), ("db-tables", "Table1", "k1"), ("db-tables", "Table2", "k2")]
    assert errors["items"][0]["error"].startswith("LlmError: LLM answer truncated at max_tokens=8192")
    assert [(c["error_class"], c["count"]) for c in errors["by_class"]] == [
        ("LlmError: LLM answer truncated at max_tokens=8192", 2), ("APITimeoutError: Request timed out", 1)]
    assert progress.failed == 3 and progress.done == 1


def test_llm_errors_in_progress_are_bounded(scanner):
    from discovery_common.redact import ErrorLog, MAX_CLASSES, MAX_ITEMS

    log = ErrorLog()
    for i in range(100):
        log.add(f"LlmError: broken answer number {i}", rule_id=1, rule_name="r", object_name=f"o{i}", object_key=f"k{i}")
    for i in range(MAX_CLASSES + 5):
        log.add(f"Kind{i}Error: something", rule_id=1, rule_name="r")
    data = log.as_dict()
    assert data["total"] == 100 + MAX_CLASSES + 5 and len(data["items"]) == MAX_ITEMS
    assert data["by_class"][0] == {"rule_id": 1, "rule": "r", "error_class": "LlmError: broken answer number 0", "count": 1} \
        or data["by_class"][0]["count"] == 100
    assert len(data["by_class"]) == MAX_CLASSES + 1 and data["by_class"][-1]["error_class"] == "other"
    assert ErrorLog.from_dict(data).as_dict() == data


def test_scan_mr_clone_failure_names_the_source_branch_and_is_permanent_for_a_deleted_branch(mr_env):
    """The deleted MR source branch of the incident: the reason (git's line) reaches the caller with the
    branch in front; permanent, so the job is not retried five times."""
    from services.failures import ScanError

    scan_service = mr_env.setup([], [])

    def clone(project_path, branch_name, *a, **kw):
        raise ScanError("remote branch not found in upstream origin (deleted?)", permanent=True)

    scan_service.clone_gitlab_project_code = clone          # bound at import: patched on the module
    with pytest.raises(ScanError) as err:
        scan_service.scan_mr(make_mr(source_branch="release/2024-11"))
    assert str(err.value) == "cannot clone source branch 'release/2024-11': remote branch not found in upstream origin (deleted?)"
    assert err.value.permanent is True
    assert mr_env.calls["delta"] == []

    # a transient git failure keeps retrying; a False (no details) is a failure too
    scan_service.clone_gitlab_project_code = lambda *a, **kw: (_ for _ in ()).throw(
        ScanError("git clone failed: fatal: unable to access '<repo>': Could not resolve host: gitlab.example"))
    with pytest.raises(ScanError, match=r"cannot clone source branch 'feature': git clone failed: fatal: unable to access") as err:
        scan_service.scan_mr(make_mr())
    assert err.value.permanent is False
    scan_service.clone_gitlab_project_code = lambda *a, **kw: False
    with pytest.raises(ScanError, match=r"cannot clone source branch 'feature': git clone failed \(no details\)"):
        scan_service.scan_mr(make_mr())


def test_scan_mr_target_clone_failure_and_unexpected_errors_carry_their_reason(mr_env):
    from services.failures import ScanError

    scan_service = mr_env.setup([], [])
    mr_env.state["branches"][10] = branch(10, "main", True, None)       # target never scanned: cloned first
    seen = []

    def clone(project_path, branch_name, *a, **kw):
        seen.append(branch_name)
        if branch_name == "main":
            raise ScanError("git clone timed out after 600s")
        return True

    scan_service.clone_gitlab_project_code = clone
    with pytest.raises(ScanError, match=r"^cannot clone target branch 'main': git clone timed out after 600s$"):
        scan_service.scan_mr(make_mr())
    assert seen == ["feature", "main"]

    scan_service.clone_gitlab_project_code = lambda *a, **kw: True
    scan_service.get_branch_by_id = lambda branch_id: (_ for _ in ()).throw(
        ConnectionError("database connection lost"))
    with pytest.raises(ScanError, match=r"^ConnectionError: database connection lost$") as err:
        scan_service.scan_mr(make_mr())
    assert err.value.permanent is False


def test_scan_branch_partial_scan_reports_the_parser_error(scanner, monkeypatch):
    """A parser that fails makes the scan partial: the job's error names the parser and its error."""
    from discovery_common.llm_work import CURRENT_PROGRESS, JobProgress
    from services.failures import ScanError

    scanner.gl_service.clone_gitlab_project_code = lambda *a, **kw: True
    scanner.gl_service.get_gitlab_project_lang = lambda path, b: "go"
    scanner.db_service.get_project = lambda project_id: SimpleNamespace(id=project_id, scan_mode="rules")
    scanner.db_service.get_rules = lambda kind=None: list(CORE_RULES)
    scanner.db_service.get_scan = lambda scan: None
    saved = []
    scanner.db_service.save_main_scan = lambda b, commit, records, hits, scan, complete=True, parsers=None, **kw: saved.append(complete)
    scan_service = scanner.load("services.scan_service")
    monkeypatch.setattr(scan_service, "run_discovery_scan", lambda *a, **kw: (
        [], scan_service.ScanStatus("partial", {"golang": RuntimeError("semgrep exited with code 2: rules file not found")})))
    written = []
    progress = JobProgress(None)
    progress.write = lambda patch, replace=False: written.append(patch)
    token = CURRENT_PROGRESS.set(progress)
    try:
        main = SimpleNamespace(id=10, project_id=1, project_path="grp/proj", branch_name="main", is_main=True, commit="abc")
        with pytest.raises(ScanError) as err:
            scan_service.scan_branch(main)
    finally:
        CURRENT_PROGRESS.reset(token)
    assert str(err.value) == "partial scan at abc: parser 'golang' failed: semgrep exited with code 2: rules file not found"
    assert err.value.permanent is False
    assert saved == [False]                                   # the partial result is kept
    assert written[-1]["phase"] == "partial" and written[-1]["error"].startswith("partial scan at abc: parser 'golang'")

    # a clone that fails: the branch is named, the phase is failed with the reason
    monkeypatch.setattr(scan_service, "clone_gitlab_project_code", lambda *a, **kw: (_ for _ in ()).throw(
        ScanError("repository not found (deleted, or not visible to the scanner's token)", permanent=True)))
    written.clear()
    token = CURRENT_PROGRESS.set(JobProgress(None))
    CURRENT_PROGRESS.get().write = lambda patch, replace=False: written.append(patch)
    try:
        with pytest.raises(ScanError, match=r"^cannot clone branch 'main': repository not found") as err:
            scan_service.scan_branch(main)
    finally:
        CURRENT_PROGRESS.reset(token)
    assert err.value.permanent is True
    assert written[-1]["phase"] == "failed" and written[-1]["error"].startswith("cannot clone branch 'main'")


def test_no_known_parser_is_a_permanent_failure(scanner, monkeypatch):
    from services.failures import ScanError

    scanner.setenv(PARSERS="nosuchparser")
    scan_service = scanner.load("services.scan_service")
    with pytest.raises(ScanError, match="no known parser is configured") as err:
        scan_service.run_discovery_scan("grp/proj", 1, 10, "main", "abc", list(CORE_RULES))
    assert err.value.permanent is True


def test_llm_backend_is_built_once_from_settings(scanner, monkeypatch):
    scanner.setenv(LLM_API_URL="http://discovery_llm:8080/v1", LLM_TIMEOUT_S="5")
    score_service = scanner.use_real("services.score_service")
    monkeypatch.setattr(score_service, "_backend", None)

    backend = score_service.get_llm_backend()
    assert score_service.get_llm_backend() is backend
    assert (backend.base_url, backend.model, backend.timeout) == ("http://discovery_llm:8080/v1", "local-model", 5.0)
    assert score_service.llm_configured() is True


def test_scan_mr_inventory_project_has_no_hits_and_no_llm(mr_env, monkeypatch):
    mr_env.state["scan_mode"] = "inventory"
    scan_service = mr_env.setup([code_object("UserCard", "n", "card_number", severity="high")], [])
    llm = []
    monkeypatch.setattr(scan_service, "run_llm_rules", lambda *a, **kw: llm.append(a) or 0)

    assert scan_service.scan_mr(make_mr()) is True
    (_, _, delta, hits, scan, _), = mr_env.calls["delta"]
    assert [c for c, _, _ in delta] == ["added"] and hits == [] and llm == []
    assert scan.rules_version.endswith("+inventory")
    assert mr_env.scanner.coverage_calls == []                  # no LLM rules in inventory mode


def test_inventory_score_config_has_no_categorisation(scanner):
    scan_service = scanner.load("services.scan_service")
    config = scan_service.build_score_config(scanner.settings(), scan_service.InventoryRules(), "grp/proj")
    assert config.score_tags == {} and config.score_rules == []


def test_parser_types_match_the_core():
    from appsec_discovery.parsers import ParserFactory
    from discovery_common.models import PARSER_TYPES
    assert list(PARSER_TYPES) == ParserFactory.get_parser_types()


def test_llm_prompts_version_matches_the_core(scanner):
    from discovery_common.models import LLM_PROMPTS_VERSION
    score_service = scanner.load("services.score_service")
    assert LLM_PROMPTS_VERSION == score_service.core_prompts_version()
    # the per-family versions of the lifecycle (migration 0024): the API knows them without importing the core
    from appsec_discovery.ai import PROMPT_VERSION
    from appsec_discovery.ai.rules import RULE_PROMPT_VERSION
    from discovery_common.models import CORE_PROMPT_FAMILIES
    assert CORE_PROMPT_FAMILIES == {"classifier": f"classifier{PROMPT_VERSION}", "rule": f"rule{RULE_PROMPT_VERSION}"}


def test_parse_with_parser_subset_scopes_the_mr_scan(mr_env):
    scan_service = mr_env.setup([code_object("A", "a")], [])
    seen = []
    real = scan_service.run_discovery_scan
    scan_service.run_discovery_scan = lambda *a, parsers=None: seen.append(parsers) or real(*a, parsers=parsers)
    loads = []
    scan_service.load_branch_snapshot = lambda branch_id, parsers=None: loads.append(parsers) or {}

    assert scan_service.scan_mr(make_mr(), parsers=["protobuf", "graphql", "protobuf"], llm=False) is True
    assert seen == [["graphql", "protobuf"]] and loads == [["graphql", "protobuf"]]
    (_, _, _, _, scan, _), = mr_env.calls["delta"]
    assert scan.parsers == ["graphql", "protobuf"]
    # no LLM run on the delta: its coverage is recounted after the save
    assert [(c[1], c[2]) for c in mr_env.scanner.coverage_calls] == [(None, False)]
