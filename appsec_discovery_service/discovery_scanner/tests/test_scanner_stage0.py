"""Unit tests for the stage-0 scanner fixes (P0-2 / P0-3 interim parts, parser isolation).

Run without Postgres or GitLab: see conftest.py for the stubs.
"""

from appsec_discovery.models import CodeObject


def make_code_object(name, hash_):
    return CodeObject(
        hash=hash_,
        object_name=name,
        object_type="route",
        parser="fake",
        file="/main.go",
        line=1,
        properties={},
        fields={},
    )


class FakeParserFactory:

    def __init__(self, behaviours):
        self.behaviours = behaviours

    def get_parser_types(self):
        return list(self.behaviours)

    def get_parser(self, name):
        behaviour = self.behaviours[name]

        class _Parser:
            def __init__(self, parser, source_folder):
                pass

            def run_scan(self):
                if isinstance(behaviour, Exception):
                    raise behaviour
                return behaviour

        return _Parser


# ---------------------------------------------------------------------------
# run_discovery_scan: parser isolation (P0-5, service side)
# ---------------------------------------------------------------------------

def test_run_discovery_scan_isolates_failing_parsers(scanner, monkeypatch):
    scan_service = scanner.load("services.scan_service")
    scanner.patch_parser_factory(FakeParserFactory({
        "broken": RuntimeError("semgrep not found"),
        "none": None,
        "ok": [make_code_object("Users", "h1")],
    }))

    objs, result = scan_service.run_discovery_scan("grp/proj", 1, 10, "main", "bbb", [])

    assert [o.name for o in objs] == ["Users"]
    assert objs[0].project_id == 1
    assert result == "partial"


def test_run_discovery_scan_all_ok_is_scanned(scanner, monkeypatch):
    scan_service = scanner.load("services.scan_service")
    scanner.patch_parser_factory(FakeParserFactory({
        "a": [make_code_object("A", "h1")],
        "b": [],
    }))

    objs, result = scan_service.run_discovery_scan("grp/proj", 1, 10, "main", "bbb", [])

    assert len(objs) == 1
    assert result == "scanned"


def test_run_discovery_scan_reports_phases_of_the_running_job(scanner):
    """scan_branch jobs: jobs.progress phases parse -> save with object counts per parser and
    the failed parsers (discovery_common.llm_work.CURRENT_PROGRESS); nothing outside a job."""
    from discovery_common import llm_work

    scan_service = scanner.load("services.scan_service")
    scanner.patch_parser_factory(FakeParserFactory({
        "broken": RuntimeError("semgrep not found"),
        "ok": [make_code_object("Users", "h1"), make_code_object("Cards", "h2")],
    }))
    phases = []
    recorder = type("Recorder", (), {"phase": lambda self, name, **extra: phases.append((name, extra))})()
    token = llm_work.CURRENT_PROGRESS.set(recorder)
    try:
        scan_service.run_discovery_scan("grp/proj", 1, 10, "main", "bbb", [])
    finally:
        llm_work.CURRENT_PROGRESS.reset(token)
    assert [name for name, _ in phases] == ["parse", "save"]
    save = phases[1][1]
    assert save["objects"] == 2 and save["failed_parsers"] == ["broken"] and sum(save["by_parser"].values()) == 2

    phases.clear()
    scan_service.run_discovery_scan("grp/proj", 1, 10, "main", "bbb", [])
    assert phases == []


# scan_mr(mr) itself: see test_scanner_stage3.py (storage v2 flow).


# main.scan_all was replaced by the job queue (P2-4): see test_scanner_jobs.py
