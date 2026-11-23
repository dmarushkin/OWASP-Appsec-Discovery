"""External parsers: POST /ingest, upload sessions, service tokens, limits, idempotency."""

import json

import pytest

pytest.importorskip("fastapi")

PROJECT = "external/payments/db01-billing"


def table(name, *columns, **props):
    return {"name": name, "type": "table", "file": "db01/billing", "props": props,
            "fields": [{"name": c, "type": "varchar(100)", "line": i + 1} for i, c in enumerate(columns)]}


def body(*objects, **extra):
    return {"project": PROJECT, "parser": "postgres", "objects": list(objects), **extra}


def as_token(api, token):
    return {"Authorization": f"Bearer {token}"}


def test_ingest_creates_an_external_project_and_is_idempotent(api, sql):
    clients = table("public.clients", "id", "last_name", "phone", server="db01", is_view=False, rows=5.0, owner=None)
    r = api.post("/ingest", json=body(clients, table("public.orders", "id", "amount")))
    assert r.status_code == 202, r.text
    first = r.json()
    assert (first["status"], first["objects"], first["fields"]) == ("committed", 2, 5) and first["job_id"]
    assert sql("SELECT source, created_by FROM gitlab_projects WHERE full_path = :p", p=PROJECT)[0][0] == "external"
    assert sql("SELECT branch_name, is_main FROM gitlab_branches WHERE project_id = :p",
               p=first["project_id"]) == [("snapshot", True)]
    (job,) = sql("SELECT kind, dedup_key FROM jobs")
    assert job == ("ingest", f"ingest:{first['project_id']}:postgres:{first['batch_id']}")
    (props,) = sql("SELECT payload->'objects'->0->'props' FROM ingest_chunks")[0]
    assert props == {"server": "db01", "is_view": "false", "rows": "5", "owner": ""}   # one text per value

    # the same state again (objects in another order): nothing new
    again = api.post("/ingest", json=body(table("public.orders", "id", "amount"), clients)).json()
    assert again["unchanged"] is True and again["batch_id"] == first["batch_id"]
    assert sql("SELECT count(*) FROM ingest_batches")[0][0] == 1

    # an Idempotency-Key replays the batch it created
    changed = body(clients)
    one = api.post("/ingest", json=changed, headers={"Idempotency-Key": "run-42"}).json()
    two = api.post("/ingest", json=changed, headers={"Idempotency-Key": "run-42"}).json()
    assert two["replayed"] is True and two["batch_id"] == one["batch_id"]

    listed = api.get("/ingest").json()
    assert [b["status"] for b in listed] == ["committed", "committed"]


@pytest.mark.parametrize("patch, status", [
    ({"project": "grp/proj"}, 422),                                     # not under external/
    ({"project": "external/../x"}, 422),
    ({"parser": "protobuf"}, 422),                                      # a built-in parser name
    ({"objects": [table("a", "x"), table("a", "y")]}, 422),             # duplicate objects
    ({"objects": [table("a", "x", "x")]}, 422),                         # duplicate fields
    ({"objects": [{**table("a", "x"), "line": 2**31}]}, 422),
    ({"objects": [table("a", "x", **{f"p{i}": 1 for i in range(51)})]}, 422),
    ({"objects": [{**table("a", "x"), "props": {"deep": {"a": 1}}}]}, 422),
    ({"objects": [{**table("a"), "fields": [{"name": "x", "samples": ["v"] * 21}]}]}, 422),   # too many samples
    ({"objects": [{**table("a"), "fields": [{"name": "x", "samples": ["v" * 1001]}]}]}, 422),
    ({"objects": [{**table("a"), "comment": "c" * 4001}]}, 422),
])
def test_ingest_validation(api, patch, status):
    assert api.post("/ingest", json={**body(table("a", "x")), **patch}).status_code == status


def test_ingest_into_a_gitlab_path_and_body_limit(api, sql, monkeypatch):
    sql("INSERT INTO gitlab_projects (gitlab_id, project_name, full_path, visibility, created_at, updated_at) "
        "VALUES (7, 'x', 'external/grp/x', 'private', now(), now())")
    assert api.post("/ingest", json={**body(table("a", "x")), "project": "external/grp/x"}).status_code == 409

    import main
    monkeypatch.setattr(main, "INGEST_MAX_BODY", 100)
    assert api.post("/ingest", json=body(table("a", "x" * 50))).status_code == 413


def test_service_tokens(api, sql):
    r = api.post("/tokens", json={"name": "payments-collector", "project_prefixes": ["external/payments/"]})
    assert r.status_code == 201, r.text
    token = r.json()["token"]
    assert token.startswith("adt_") and sql("SELECT count(*) FROM api_tokens WHERE token_hash = :t", t=token)[0][0] == 0
    for bad in ({"name": "x", "project_prefixes": ["grp/"]}, {"name": "x", "project_prefixes": ["external/a"],
                                                               "scopes": ["admin"]}):
        assert api.post("/tokens", json=bad).status_code == 422

    headers = as_token(api, token)
    assert api.post("/ingest", json=body(table("a", "x")), headers=headers).status_code == 202
    other = {**body(table("a", "x")), "project": "external/risk/db02"}
    assert api.post("/ingest", json=other, headers=headers).status_code == 403
    assert sql("SELECT created_by FROM gitlab_projects WHERE full_path = :p", p=PROJECT) == [("token:payments-collector",)]
    assert [b["project"] for b in api.get("/ingest", headers=headers).json()] == [PROJECT]
    assert api.get("/hits", headers=headers).status_code == 403          # ingest only
    assert api.post("/tokens", json={"name": "y", "project_prefixes": ["external/y"]}, headers=headers).status_code == 403

    (row,) = api.get("/tokens").json()
    assert row["last_used_at"] is not None and "token" not in row
    assert api.delete(f"/tokens/{row['id']}").status_code == 200
    assert api.post("/ingest", json=body(table("b", "x")), headers=headers).status_code == 401


def test_upload_session(api, sql):
    r = api.post("/ingest/sessions", json={"project": PROJECT, "parser": "postgres", "llm": True})
    assert r.status_code == 201, r.text
    sid = r.json()["session_id"]
    assert api.put(f"/ingest/sessions/{sid}/chunks/0", json={"objects": [table("a", "x")]}).status_code == 200
    r = api.put(f"/ingest/sessions/{sid}/chunks/1", json={"objects": [table("b", "x", "y")]})
    assert r.json()["session_objects"] == 2 and r.json()["session_fields"] == 3
    assert api.put(f"/ingest/sessions/{sid}/chunks/1", json={"objects": [table("b", "x")]}).json()["session_fields"] == 2
    assert sql("SELECT count(*) FROM jobs")[0][0] == 0                    # nothing applied before the commit

    r = api.post(f"/ingest/sessions/{sid}/commit")
    assert r.status_code == 202 and (r.json()["objects"], r.json()["fields"]) == (2, 2)
    assert sql("SELECT status, llm FROM ingest_batches WHERE id = :b", b=sid) == [("committed", True)]
    assert api.put(f"/ingest/sessions/{sid}/chunks/2", json={"objects": []}).status_code == 409
    assert api.post(f"/ingest/sessions/{sid}/commit").status_code == 409

    # the same chunks in a new session: unchanged, the session is dropped
    s2 = api.post("/ingest/sessions", json={"project": PROJECT, "parser": "postgres"}).json()["session_id"]
    api.put(f"/ingest/sessions/{s2}/chunks/0", json={"objects": [table("a", "x")]})
    api.put(f"/ingest/sessions/{s2}/chunks/1", json={"objects": [table("b", "x")]})
    assert api.post(f"/ingest/sessions/{s2}/commit").json()["unchanged"] is True
    s3 = api.post("/ingest/sessions", json={"project": PROJECT, "parser": "postgres"}).json()["session_id"]
    assert api.post(f"/ingest/sessions/{s3}/commit").status_code == 422     # no chunk
    assert api.delete(f"/ingest/sessions/{s3}").json()["aborted"] is True
    assert api.put(f"/ingest/sessions/999/chunks/0", json={"objects": []}).status_code == 404


def test_parse_reapplies_the_latest_external_state(api, sql):
    first = api.post("/ingest", json=body(table("a", "x"))).json()
    sql("UPDATE ingest_batches SET status = 'processed'")
    r = api.post("/projects/parse", json={"project_ids": [first["project_id"]], "force": True})
    assert r.status_code == 202, r.text
    assert [(j["kind"], j["dedup_key"]) for j in r.json()["queued"]] == [
        ("ingest", f"ingest:{first['project_id']}:postgres:parse:force")]
    only_external = api.post("/projects/parse", json={"parsers": ["postgres"]}).json()
    assert {j["kind"] for j in only_external["queued"]} <= {"ingest"}
    assert api.post("/projects/parse", json={"parsers": ["cobol"]}).status_code == 422



def test_ingest_keeps_comments_and_samples(api, sql):
    clients = {**table("public.clients", "id"), "comment": "Bank clients",
               "fields": [{"name": "phone", "type": "varchar(20)", "comment": "mobile, E.164", "samples": ["+7900*****00"]}]}
    r = api.post("/ingest", json=body(clients))
    assert r.status_code == 202, r.text
    (obj,) = sql("SELECT payload->'objects'->0 FROM ingest_chunks")[0]
    assert obj["comment"] == "Bank clients"
    assert obj["fields"][0]["comment"] == "mobile, E.164" and obj["fields"][0]["samples"] == ["+7900*****00"]
    # an object without documentation is stored without the keys (its chunk hash is as before)
    api.post("/ingest", json=body(table("public.orders", "id")))
    (latest,) = sql("SELECT payload->'objects'->0 FROM ingest_chunks ORDER BY batch_id DESC LIMIT 1")[0]
    assert "comment" not in latest and "samples" not in latest["fields"][0]


def test_ingest_body_cap_behind_root_path_and_chunked(api_settings, monkeypatch):
    """uvicorn --root-path /api puts /api/ingest in scope["path"]: the cap still applies, also
    to a body without Content-Length (chunked)."""
    from fastapi.testclient import TestClient

    import auth
    import main

    headers = {"Authorization": f"Bearer {auth.create_access_token('reviewer@example.com')}",
               "Content-Type": "application/json"}
    monkeypatch.setattr(main, "INGEST_MAX_BODY", 100)
    big = json.dumps(body(table("a", "x" * 200))).encode()
    with TestClient(main.create_app(), root_path="/api") as client:
        assert client.post("/api/ingest", content=big, headers=headers).status_code == 413
        chunked = client.post("/api/ingest", content=iter([big[:60], big[60:]]), headers=headers)
        assert chunked.status_code == 413, chunked.text
        small = json.dumps(body(table("a", "x"))).encode()
        monkeypatch.setattr(main, "INGEST_MAX_BODY", len(small))
        assert client.post("/api/ingest", content=iter([small]), headers=headers).status_code == 202
        assert client.post("/api/tokens", content=big, headers=headers).status_code != 413   # other routes: no cap


def test_list_ingests_of_a_service_token_filters_before_the_limit(api, sql):
    token = api.post("/tokens", json={"name": "c", "project_prefixes": ["external/payments/"]}).json()["token"]
    assert api.post("/ingest", json=body(table("a", "x")), headers=as_token(api, token)).status_code == 202
    for i in range(5):
        assert api.post("/ingest", json={**body(table(f"t{i}", "x")), "project": f"external/risk_{i}/db"}).status_code == 202
    # a look-alike prefix ('_' / '%' are literal) does not leak
    assert api.post("/ingest", json={**body(table("z", "x")), "project": "external/paymentsX/db"}).status_code == 202
    listed = api.get("/ingest", params={"limit": 2}, headers=as_token(api, token)).json()
    assert [b["project"] for b in listed] == [PROJECT]
    assert len(api.get("/ingest", params={"limit": 2}).json()) == 2                       # admin: everything


def test_concurrent_push_with_the_same_idempotency_key_replays(api, sql, monkeypatch):
    """Two requests with one new key: the other's SELECT ran before this one's INSERT, so the
    unique index decides; the loser replays the winner's batch instead of a 500."""
    from services import ingest_service

    first = api.post("/ingest", json=body(table("a", "x")), headers={"Idempotency-Key": "k-1"}).json()
    lookup, state = ingest_service._by_key, {"raced": False}

    def racing_by_key(*args, **kwargs):            # the first lookup misses (the row was not there yet)
        return lookup(*args, **kwargs) if state["raced"] else None

    def racing_new_batch(*args, **kwargs):
        state["raced"] = True
        return original_new_batch(*args, **kwargs)

    original_new_batch = ingest_service._new_batch
    monkeypatch.setattr(ingest_service, "_by_key", racing_by_key)
    monkeypatch.setattr(ingest_service, "_new_batch", racing_new_batch)
    r = api.post("/ingest", json=body(table("b", "y")), headers={"Idempotency-Key": "k-1"})
    state["raced"] = False
    s = api.post("/ingest/sessions", json={"project": PROJECT, "parser": "postgres"},
                 headers={"Idempotency-Key": "k-1"})
    assert r.status_code == 202, r.text
    assert r.json()["replayed"] is True and r.json()["batch_id"] == first["batch_id"]
    assert s.status_code == 201 and s.json()["replayed"] is True and s.json()["session_id"] == first["batch_id"]
    assert sql("SELECT count(*) FROM ingest_batches")[0][0] == 1


def test_stuck_committed_batch_is_not_unchanged_and_superseded_batches(api, sql):
    first = api.post("/ingest", json=body(table("a", "x")), headers={"Idempotency-Key": "k-a"}).json()
    assert api.post("/ingest", json=body(table("a", "x"))).json()["unchanged"] is True    # its job is pending
    sql("UPDATE jobs SET status = 'failed', finished_at = now() WHERE kind = 'ingest'")    # lost: never applied
    again = api.post("/ingest", json=body(table("a", "x"))).json()
    assert again.get("unchanged") is not True and again["batch_id"] != first["batch_id"]

    sql("UPDATE ingest_batches SET status = 'superseded' WHERE id = :b", b=first["batch_id"])
    assert [b["id"] for b in api.get("/ingest").json()] == [again["batch_id"]]
    assert {b["id"] for b in api.get("/ingest", params={"include_superseded": True}).json()} == {
        first["batch_id"], again["batch_id"]}
    replay = api.post("/ingest", json=body(table("old", "x")), headers={"Idempotency-Key": "k-a"}).json()
    assert (replay["replayed"], replay["status"], replay["batch_id"]) == (True, "superseded", first["batch_id"])
