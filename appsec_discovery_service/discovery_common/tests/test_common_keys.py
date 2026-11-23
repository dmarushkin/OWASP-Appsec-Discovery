"""Storage keys: properties, and parity between the Python keys and the SQL of migration 0002."""

import importlib.util
import uuid
from pathlib import Path

from sqlalchemy import create_engine, text

from discovery_common import keys

MIGRATION = Path(__file__).resolve().parents[1] / "migrations" / "versions" / "0002_storage_v2.py"


def _migration():
    spec = importlib.util.spec_from_file_location("m0002", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_keys_are_uuids_and_stable():
    ok = keys.object_key(1, "go", "abc")
    assert isinstance(ok, uuid.UUID)
    assert ok == keys.object_key(1, "go", "abc")
    assert ok != keys.object_key(2, "go", "abc") != keys.object_key(1, "java", "abc")
    assert keys.subject_key(ok) == ok
    assert keys.subject_key(ok, "email") == keys.field_key(ok, "email") != ok


def test_content_hash_is_order_independent_and_unambiguous():
    ok = keys.object_key(1, "go", "abc")
    a = keys.content_hash(ok, {"a": "int", "b": "string"}, {"p": "1"})
    assert a == keys.content_hash(ok, {"b": "string", "a": "int"}, {"p": "1"})
    assert a != keys.content_hash(ok, {"a": "int", "b": "text"}, {"p": "1"})
    assert a != keys.content_hash(ok, {"a": "int"}, {"p": "1"})
    assert a != keys.content_hash(ok, {"a": "int", "b": "string"}, {})
    # separators cannot be confused with names
    assert keys.content_hash(ok, {"a:b": "c"}, {}) != keys.content_hash(ok, {"a": "b:c"}, {})


SAMPLES = [
    (7, "golang", "0f0e", {"Email": "string", "id": "int64", "Zeta": "", "émail": "string", "_x": "T"},
     {"path": "/user", "method": "GET", "Ä": "1"}),
    (1, "graphql", "h", {}, {}),
    (2, "swagger", "h2", {"b": "int"}, {}),
]


def test_sql_keys_match_python(pg_url):
    m = _migration()
    engine = create_engine(pg_url)
    try:
        with engine.connect() as conn:
            for project_id, parser, ident, fields, props in SAMPLES:
                obj_key = conn.execute(text("SELECT " + m.SQL_OBJECT_KEY.format(
                    project_id="CAST(:p AS integer)", parser=":parser", hash=":h")), {"p": project_id, "parser": parser, "h": ident}).scalar()
                assert obj_key == keys.object_key(project_id, parser, ident)

                for name in fields:
                    field_key = conn.execute(text("SELECT " + m.SQL_FIELD_KEY.format(
                        object_key="CAST(:k AS uuid)", field_name=":f")), {"k": str(obj_key), "f": name}).scalar()
                    assert field_key == keys.field_key(obj_key, name)

                # same expression as the UPDATE mig_objects ... SET content_hash in 0002
                content = conn.execute(text("""
                    SELECT md5(CAST(:k AS uuid)::text || '#' ||
                        COALESCE((SELECT string_agg(f.key || chr(30) || COALESCE(f.value, ''), chr(31) ORDER BY f.key COLLATE "C")
                                  FROM json_each_text(CAST(:fields AS json)) f), '') || '#' ||
                        COALESCE((SELECT string_agg(p.key || chr(30) || COALESCE(p.value, ''), chr(31) ORDER BY p.key COLLATE "C")
                                  FROM json_each_text(CAST(:props AS json)) p), ''))::uuid"""),
                    {"k": str(obj_key), "fields": __import__("json").dumps(fields), "props": __import__("json").dumps(props)}).scalar()
                assert content == keys.content_hash(obj_key, fields, props)
    finally:
        engine.dispose()



def test_documentation_is_in_the_content_hash_only_when_present():
    from types import SimpleNamespace as N
    from discovery_common.mapping import from_code_object

    def obj(comment=None, field_comment=None, samples=None):
        return N(hash="h", object_name="Table t", object_type="table", parser="migrations", file="/m", line=1,
                 properties={}, comment=comment, hits=[],
                 fields={"pan": N(field_name="pan", field_type="text", line=2, comment=field_comment, samples=samples)})

    plain = from_code_object(obj(), 1)
    legacy = from_code_object(N(**{k: v for k, v in vars(obj()).items() if k != "comment"},), 1)
    assert plain.content_hash == legacy.content_hash == keys.content_hash(plain.object_key, {"pan": "text"}, {})
    hashes = {from_code_object(o, 1).content_hash for o in
              (obj(), obj(comment="cards"), obj(field_comment="masked"), obj(samples=["4276****"]))}
    assert len(hashes) == 4
    record = from_code_object(obj(comment="cards", field_comment="masked", samples=["4276****"]), 1)
    assert record.object_row()["comment"] == "cards"
    (row,) = record.field_rows()
    assert (row["comment"], row["samples"]) == ("masked", ["4276****"])



def test_fields_without_samples_are_sql_null():
    from discovery_common.models import ObjectField
    assert ObjectField.__table__.c.samples.type.none_as_null


LLM_SAMPLES = [
    ("User", ["email", "id", "Zeta", "émail", "_x", "Ä"]),
    ("", []),
    (None, ["a#b", "c"]),
    ("Café", ["naïve", "Straße"]),         # non-ASCII Latin
]

FIELD_SAMPLES = [
    ("email", "string", None, None),
    ("email", "string", "", []),
    ("email", None, "work address\nsecond line", ["a@example.com", "b@example.com"]),
    ("pan", "text", "card # number", ["4276****", None, "5555"]),
    ("prénom", "varchar(255)", "nom complet (é, ß)", ["Zoë", "Ångström"]),
]


def test_llm_hashes_properties():
    assert keys.names_hash("User", ["b", "a"]) == keys.names_hash("User", ["a", "b"])        # order of fields
    assert keys.names_hash("User", ["a"]) != keys.names_hash("Users", ["a"]) != keys.names_hash("User", ["a", "b"])
    assert keys.names_hash("a#b", []) != keys.names_hash("a", ["b"])
    base = keys.field_subject_hash("f", "int", None, None)
    assert base == keys.field_subject_hash("f", "int", "", [])                                # empty = none
    assert len({base, keys.field_subject_hash("f", "text", None, None), keys.field_subject_hash("f", "int", "c", None),
                keys.field_subject_hash("f", "int", None, ["1"]), keys.field_subject_hash("g", "int", None, None)}) == 5
    assert keys.field_subject_hash("f", "int", None, ["1", "2"]) != keys.field_subject_hash("f", "int", None, ["2", "1"])
    assert keys.object_subject_hash(uuid.UUID(int=5)) == "00000000-0000-0000-0000-000000000005"


def test_sql_llm_hashes_match_python(pg_url):
    """The SQL functions of migration 0018 (candidate queries, coverage, backfill) == discovery_common.keys."""
    import json
    from discovery_common import testing

    testing.migrate(pg_url)
    engine = create_engine(pg_url)
    try:
        with engine.connect() as conn:
            for name, fields in LLM_SAMPLES:
                sql = conn.execute(text("SELECT llm_names_hash(:n, CAST(:f AS text[]))"), {"n": name, "f": fields}).scalar()
                assert sql == keys.names_hash(name, fields), (name, fields)
            for name, type_, comment, samples in FIELD_SAMPLES:
                sql = conn.execute(text("SELECT llm_field_hash(:n, :t, :c, CAST(:s AS jsonb))"), {
                    "n": name, "t": type_, "c": comment, "s": None if samples is None else json.dumps(samples)}).scalar()
                assert sql == keys.field_subject_hash(name, type_, comment, samples), (name, samples)
            # the object subject: the content hash as text
            ch = uuid.uuid4()
            assert conn.execute(text("SELECT CAST(:u AS uuid)::text"), {"u": str(ch)}).scalar() == keys.object_subject_hash(ch)
    finally:
        engine.dispose()
