"""``Parser.file_patterns`` and ``appsec_discovery.changes``: which parsers a changed file can affect."""

import pytest

import appsec_discovery
from appsec_discovery.changes import affected_parsers, parser_file_patterns, path_matches
from appsec_discovery.parsers import FileParser, ParserFactory, SemgrepParser


def test_every_builtin_parser_declares_the_files_it_reads():
    """The patterns come from each parser's own file selection (``globs`` of the file parsers, the semgrep
    languages / ``paths`` of the rule based ones); a parser without them would force a full scan on any change."""
    patterns = parser_file_patterns(["all"])
    assert set(patterns) == {"golang", "graphql", "java", "javascript", "migrations", "protobuf", "python", "swagger",
                             "terraform"}
    assert patterns["protobuf"] == ("*.proto",)
    assert patterns["graphql"] == ("*.graphql", "*.gql")
    assert patterns["javascript"] == ("*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs")
    assert patterns["migrations"] == ("*.sql",)
    assert patterns["swagger"] == ("*.yaml", "*.yml", "*.json")
    assert patterns["terraform"] == ("*.tf", "*.tf.json")
    assert patterns["golang"] == ("*.go",)
    assert patterns["java"] == ("*.java",)
    assert patterns["python"] == ("*.py", "*.pyi")
    for name, declared in patterns.items():
        cls = ParserFactory.get_parser(name)
        if issubclass(cls, FileParser):
            assert declared == tuple(cls.globs), name
    # the deprecated parsers read nothing: no change affects them
    assert parser_file_patterns(["db", "client"]) == {"db": (), "client": ()}


def test_file_patterns_default_from_globs_and_stay_overridable():
    class Walker(FileParser):
        globs = ("*.abc",)

        def parse_file(self, path, text):
            return text

        def build_objects(self, parsed):
            return []

    class Picky(Walker):
        file_patterns = ("*.abc", "config/*.toml")

    class Rules(SemgrepParser):
        pass

    assert Walker.file_patterns == ("*.abc",)
    assert Picky.file_patterns == ("*.abc", "config/*.toml")
    assert Rules.file_patterns is None            # not declared: anything may affect it


@pytest.mark.parametrize("path, patterns, expected", [
    ("api/users.proto", ("*.proto",), True),
    ("/api/users.proto", ("*.proto",), True),                 # the parsers' leading slash
    ("./README.md", ("*.proto", "*.go"), False),
    ("src/main/App.java", ("*.java",), True),
    ("db/migrations/0001_init.up.sql", ("*.sql",), True),
    ("infra/main.tf.json", ("*.tf", "*.tf.json"), True),
    ("infra/vars.json", ("*.tf", "*.tf.json"), False),
    ("pkg/model.GO", ("*.go",), False),                       # case sensitive, as the walkers are
    ("docs/openapi/spec.yaml", ("docs/openapi/*",), True),    # a pattern with / is matched on the path
    ("other/spec.yaml", ("docs/openapi/*",), False),
    ("schema.graphql", ("**/schema.graphql",), True),
    ("svc/a/schema.graphql", ("**/schema.graphql",), True),
    ("", ("*",), False),
])
def test_path_matches(path, patterns, expected):
    assert path_matches(path, patterns) is expected


def test_affected_parsers_by_changed_files():
    assert affected_parsers(["README.md", "docs/arch.md", ".gitlab-ci.yml"], ["protobuf", "golang"]) == []
    assert affected_parsers(["api/users.proto"], ["protobuf", "golang"]) == ["protobuf"]
    assert affected_parsers(["cmd/main.go", "api/users.proto"], ["all"]) == ["golang", "protobuf"]
    # .gitlab-ci.yml is a yaml file: the swagger parser reads every yaml / json file (it decides on the content)
    assert affected_parsers([".gitlab-ci.yml"], ["all"]) == ["swagger"]
    # an unknown parser may read anything (its run fails the scan anyway)
    assert affected_parsers(["README.md"], ["protobuf", "nosuchparser"]) == ["nosuchparser"]
    assert affected_parsers([], ["all"]) == []


def test_changes_are_part_of_the_public_api():
    assert appsec_discovery.affected_parsers is affected_parsers
    assert appsec_discovery.parser_file_patterns is parser_file_patterns
