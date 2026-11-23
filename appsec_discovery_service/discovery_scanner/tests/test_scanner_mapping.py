"""CodeObject -> storage records (keys) and MR delta (test item 5)."""


from appsec_discovery.models import CodeObject, CodeObjectField, CodeObjectProp


def make_code_object(line=3, field_line=9, field_type="String", hash_="h1", path="/user"):
    return CodeObject(
        hash=hash_,
        object_name="Query getUser",
        object_type="query",
        parser="graphql",
        severity="high",
        tags=["pii"],
        file="/schema.graphql",
        line=line,
        properties={
            "path": CodeObjectProp(prop_name="path", prop_value=path, file="/schema.graphql", line=line,
                                   severity="low", tags=["route"]),
        },
        fields={
            "output.User.email": CodeObjectField(
                field_name="output.User.email", field_type=field_type, file="/schema.graphql", line=field_line,
                severity="medium", tags=["pii"]),
            "input.id": CodeObjectField(field_name="input.id", field_type="Int", file="/schema.graphql", line=4),
        },
    )


def test_from_code_object_maps_identity_props_and_fields(scanner):
    from discovery_common import keys
    from discovery_common.mapping import from_code_object

    record = from_code_object(make_code_object(), project_id=1)

    assert record.object_key == keys.object_key(1, "graphql", "h1")
    assert (record.name, record.type, record.parser, record.file, record.line) == ("Query getUser", "query", "graphql", "/schema.graphql", 3)
    assert record.props == {"path": "/user"}
    assert set(record.fields) == {"output.User.email", "input.id"}
    email = record.fields["output.User.email"]
    assert (email.type, email.line) == ("String", 9)
    assert email.key == keys.field_key(record.object_key, "output.User.email")
    assert record.hits == []          # scores are not hits: only the hits the core recorded are stored
    assert record.field_lines == {"output.User.email": 9, "input.id": 4}

    row = record.object_row()
    assert row["content_hash"] == record.content_hash and row["project_id"] == 1
    assert {f["field_name"] for f in record.field_rows()} == {"output.User.email", "input.id"}


def test_keys_ignore_lines_but_follow_shape(scanner):
    from discovery_common.mapping import from_code_object

    base = from_code_object(make_code_object(), 1)
    moved = from_code_object(make_code_object(line=30, field_line=90), 1)
    retyped = from_code_object(make_code_object(field_type="Text"), 1)
    new_prop = from_code_object(make_code_object(path="/v2/user"), 1)
    other_project = from_code_object(make_code_object(), 2)

    assert (moved.object_key, moved.content_hash) == (base.object_key, base.content_hash)
    assert retyped.object_key == base.object_key and retyped.content_hash != base.content_hash
    assert new_prop.object_key == base.object_key and new_prop.content_hash != base.content_hash
    # field subject keys survive a retype (a reviewer judged "field email of User")
    assert retyped.fields["output.User.email"].key == base.fields["output.User.email"].key
    assert other_project.object_key != base.object_key


def test_compute_delta(scanner):
    from discovery_common.mapping import compute_delta, from_code_object

    same = from_code_object(make_code_object(hash_="same"), 1)
    changed = from_code_object(make_code_object(hash_="changed", field_type="Text"), 1)
    new = from_code_object(make_code_object(hash_="new"), 1)
    target = {
        same.object_key: same.content_hash,
        changed.object_key: from_code_object(make_code_object(hash_="changed"), 1).content_hash,
        "gone-key": "gone-hash",
    }

    delta = compute_delta([same, changed, new], target)
    assert [(change, key) for change, key, _ in delta] == [
        ("modified", changed.object_key), ("added", new.object_key), ("removed", "gone-key")]
    assert delta[2][2] is None

    # a partial source scan reports no removals
    assert [c for c, _, _ in compute_delta([same], target, complete=False)] == []


def test_dedupe_keeps_first_record_per_identity(scanner):
    from discovery_common.mapping import dedupe, from_code_object

    first = from_code_object(make_code_object(), 1)
    dup = from_code_object(make_code_object(field_type="Text"), 1)
    assert dedupe([first, dup]) == [first]


def test_run_discovery_scan_respects_parsers_setting(scanner, monkeypatch):
    scanner.setenv(PARSERS="b, missing")
    scan_service = scanner.load("services.scan_service")
    ran = []

    class Factory:
        @staticmethod
        def get_parser_types():
            return ["a", "b"]

        @staticmethod
        def get_parser(name):
            class _P:
                def __init__(self, parser, source_folder):
                    ran.append((parser, source_folder))

                def run_scan(self):
                    return [make_code_object()]
            return _P

    scanner.patch_parser_factory(Factory)

    records, result = scan_service.run_discovery_scan("grp/proj", 1, 10, "main", "abc", [])

    assert ran == [("b", "code/1/10/abc")]
    assert [r.name for r in records] == ["Query getUser"] and result == "scanned"
