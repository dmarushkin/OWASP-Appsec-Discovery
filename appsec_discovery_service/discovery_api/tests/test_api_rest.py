"""REST API against a real Postgres: auth, keyword / LLM rule CRUD (versioning, soft
delete, built-ins), review queue filters, hit detail and review transitions."""

import json

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("mcp")
pydantic = pytest.importorskip("pydantic")
if not pydantic.VERSION.startswith("2"):
    pytest.skip("the API runs on pydantic v2", allow_module_level=True)

from conftest import ADMIN, fast_hash  # noqa: E402


def lst(client, path, **params):
    query = {k: json.dumps(v) for k, v in params.items()}
    response = client.get(path, params=query)
    assert response.status_code == 200, response.text
    return response.json(), response.headers["Content-Range"]


# ---- auth ------------------------------------------------------------------------------------

def test_auth(api):
    anonymous = {"Authorization": ""}
    assert api.get("/keyword_rules", headers=anonymous).status_code == 401
    assert api.get("/hits", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert api.get("/mcp", headers=anonymous).status_code == 401
    assert api.post("/token", data={"username": ADMIN, "password": "wrong"}).status_code == 401
    assert api.post("/token", data={"username": "x@example.com", "password": "wrong"}).status_code == 401
    assert api.get("/health").json() == {"status": "ok"}
    assert api.get("/health/db").json()["revision"] == "0032_scale_api"


def test_weak_or_plain_admin_password_is_refused():
    import auth
    import config

    with pytest.raises(config.ConfigError, match="no longer accepted"):
        config.ApiSettings.from_env({"DATABASE_URL": "postgresql://x", "UI_ADMIN_EMAIL": "a@b.c",
                                     "UI_JWT_KEY": "k" * 40, "UI_ADMIN_PASSWORD": "admin"})
    weak = config.ApiSettings(database_url="x", ui_admin_email="a@b.c", ui_jwt_key="k" * 40,
                              ui_admin_password_hash=fast_hash("admin"))
    with pytest.raises(config.ConfigError, match="well-known"):
        auth.check_settings(weak)


# ---- keyword rules ---------------------------------------------------------------------------

KEYWORD = {"name": "passwords", "category": "auth", "severity": "high", "mode": "review",
           "field_re": "pass(word)?", "project_re": "grp/"}


def test_keyword_rule_crud_and_versioning(api, sql):
    created = api.post("/keyword_rules", json=KEYWORD)
    assert created.status_code == 201, created.text
    rule = created.json()
    assert (rule["target"], rule["action"], rule["version"], rule["updated_by"]) == ("field", "score", 1, ADMIN)
    rid = rule["id"]

    # validation
    assert api.post("/keyword_rules", json={"name": "x", "category": "c"}).status_code == 422       # no matcher
    assert api.post("/keyword_rules", json={"name": "x", "object_re": "A"}).status_code == 422      # no category
    assert api.post("/keyword_rules", json={"name": "x", "object_re": "A", "action": "exclude"}).status_code == 201
    assert api.post("/keyword_rules", json=KEYWORD).status_code == 409                              # same name

    # metadata edit: same version; react-admin sends the whole record back
    edited = api.put(f"/keyword_rules/{rid}", json={**rule, "severity": "critical", "mode": "auto"}).json()
    assert (edited["severity"], edited["mode"], edited["version"]) == ("critical", "auto", 1)
    # matcher edit: version bump
    edited = api.put(f"/keyword_rules/{rid}", json={**edited, "field_re": "passwd"}).json()
    assert (edited["field_re"], edited["version"]) == ("passwd", 2)
    assert api.put(f"/keyword_rules/{rid}", json={**edited, "action": "alert"}).status_code == 422   # removed
    edited = api.put(f"/keyword_rules/{rid}", json={**edited, "action": "exclude"}).json()
    assert edited["version"] == 3
    edited = api.put(f"/keyword_rules/{rid}", json={**edited, "action": "score"}).json()

    # list: filter / sort / Content-Range
    items, crange = lst(api, "/keyword_rules", filter={"q": "pass"}, range=[0, 9], sort=["id", "ASC"])
    assert [i["id"] for i in items] == [rid] and crange == "keyword_rules 0-0/1"
    items, crange = lst(api, "/keyword_rules", range=[0, 1], sort=["name", "DESC"])
    assert len(items) == 2 and crange == "keyword_rules 0-1/4"     # 2 core + 2 new (0013 seeds an LLM rule only)
    assert api.get("/keyword_rules", params={"sort": json.dumps(["prompt; drop", "ASC"])}).status_code == 422
    assert api.get("/keyword_rules", params={"filter": json.dumps({"bogus": 1})}).status_code == 422

    # kinds are separate resources
    assert api.get(f"/llm_rules/{rid}").status_code == 404

    # soft delete
    deleted = api.delete(f"/keyword_rules/{rid}").json()
    assert deleted["deleted_at"] is not None and deleted["enabled"] is False
    assert rid not in [i["id"] for i in lst(api, "/keyword_rules", range=[0, 99])[0]]
    assert rid in [i["id"] for i in lst(api, "/keyword_rules", filter={"include_deleted": True}, range=[0, 99])[0]]
    assert api.get(f"/keyword_rules/{rid}").json()["deleted_at"] is not None
    assert api.put(f"/keyword_rules/{rid}", json=KEYWORD).status_code == 404
    assert sql("SELECT count(*) FROM rules WHERE id = :i", i=rid) == [(1,)]
    # the name is free again
    assert api.post("/keyword_rules", json=KEYWORD).status_code == 201


def test_core_keyword_rules_are_builtin(api):
    items, _ = lst(api, "/keyword_rules", filter={"q": "kw-"}, range=[0, 9])
    core = {i["name"]: i for i in items}
    assert set(core) == {"kw-fields", "kw-props"}                     # migration 0028: short names
    assert not any(r["enabled"] for r in core.values())              # opt-in on a new install
    field_rule = core["kw-fields"]
    assert field_rule["builtin"] == "core"
    edited = api.put(f"/keyword_rules/{field_rule['id']}", json={**field_rule, "mode": "review", "field_re": "x"})
    assert edited.status_code == 200
    edited = edited.json()
    assert (edited["mode"], edited["field_re"], edited["version"]) == ("review", None, 1)
    assert api.delete(f"/keyword_rules/{field_rule['id']}").status_code == 409


# ---- LLM rules -------------------------------------------------------------------------------

def test_llm_rule_crud(api):
    rules, _ = lst(api, "/llm_rules", range=[0, 9])
    assert not any(r["name"] == "llm" for r in rules)                # no env-managed rule any more (0028)
    assert {r["name"]: r["enabled"] for r in rules} == {"db-tables-with-client-data": True, "api-with-auth": False}

    created = api.post("/llm_rules", json={"name": "secrets", "category": "secret", "target": "object",
                                           "prompt": "Does the object hold secrets?", "object_type_re": "dto"})
    assert created.status_code == 201, created.text
    rule = created.json()
    assert (rule["mode"], rule["target"], rule["version"]) == ("auto", "object", 1)              # default: auto
    assert api.post("/llm_rules", json={"name": "o", "target": "object"}).status_code == 422          # no category
    assert api.post("/llm_rules", json={"name": "o", "target": "object", "category": "c",
                                        "field_re": "x"}).status_code == 422

    same = api.put(f"/llm_rules/{rule['id']}", json={**rule, "severity": "high"}).json()
    assert same["version"] == 1
    bumped = api.put(f"/llm_rules/{rule['id']}", json={**same, "prompt": "Does it hold keys or secrets?"}).json()
    assert bumped["version"] == 2
    # an update without mode keeps the rule's mode (the create default does not apply)
    review = api.put(f"/llm_rules/{rule['id']}", json={**bumped, "mode": "review"}).json()
    kept = api.put(f"/llm_rules/{rule['id']}", json={k: v for k, v in review.items() if k != "mode"}).json()
    assert (review["mode"], kept["mode"], kept["version"]) == ("review", "review", 2)

    # the edit is a new version (active at once; its rollout of the stale verdicts is planned: a human starts it)
    versions = api.get(f"/llm_rules/{rule['id']}/versions").json()["items"]
    assert [(v["version"], v["status"]) for v in versions] == [(2, "active"), (1, "retired")]
    assert versions[1]["diff"]["prompt"] and versions[0]["rollout"]["status"] == "planned"
    # ?candidate=true: a candidate only, the rule is unchanged
    cand = api.put(f"/llm_rules/{rule['id']}?candidate=true", json={**kept, "prompt": "Only keys?"}).json()
    assert cand["version"] == 2 and cand["prompt"] == "Does it hold keys or secrets?"
    assert api.get(f"/llm_rules/{rule['id']}/versions").json()["items"][0]["status"] == "candidate"

    assert api.get(f"/keyword_rules/{rule['id']}").status_code == 404


# ---- review queue ----------------------------------------------------------------------------

def ids(items):
    return {i["id"] for i in items}


def test_queue_filters(api, seed):
    items, crange = lst(api, "/hits", range=[0, 24])
    assert ids(items) == {seed["email_llm"], seed["card_llm"], seed["email_core"], seed["user_obj"]}   # live only
    assert crange == "hits 0-3/4"

    pending, _ = lst(api, "/hits", filter={"status": "pending_review"})
    assert ids(pending) == {seed["email_llm"], seed["card_llm"], seed["user_obj"]}
    assert [i["id"] for i in pending] == [seed["email_llm"], seed["card_llm"], seed["user_obj"]]   # oldest first

    main_only, _ = lst(api, "/hits", filter={"presence": "main"})
    assert ids(main_only) == {seed["email_llm"], seed["email_core"], seed["user_obj"]}
    mr_only, _ = lst(api, "/hits", filter={"presence": "mr"})
    assert ids(mr_only) == {seed["card_llm"]}
    assert mr_only[0]["in_open_mr"] is True and mr_only[0]["in_main"] is False
    everything, _ = lst(api, "/hits", filter={"presence": "all"})
    assert seed["ssn_llm"] in ids(everything)

    assert ids(lst(api, "/hits", filter={"category": "finance"})[0]) == {seed["card_llm"]}
    llm_rule = seed["rules"]["llm"]
    assert ids(lst(api, "/hits", filter={"rule_id": llm_rule})[0]) == {seed["email_llm"], seed["card_llm"]}
    assert ids(lst(api, "/hits", filter={"kind": "keyword"})[0]) == {seed["email_core"], seed["user_obj"]}
    assert lst(api, "/hits", filter={"project_id": 2})[0] == []
    assert ids(lst(api, "/hits", filter={"q": "card"})[0]) == {seed["card_llm"]}
    assert ids(lst(api, "/hits", filter={"id": [seed["card_llm"], seed["ssn_llm"]], "presence": "all"})[0]) == {
        seed["card_llm"], seed["ssn_llm"]}

    by_severity, _ = lst(api, "/hits", sort=["severity", "DESC"])
    assert by_severity[0]["id"] == seed["email_core"]
    page, crange = lst(api, "/hits", range=[1, 2], sort=["first_seen_at", "ASC"])
    assert len(page) == 2 and crange == "hits 1-2/4"

    row = next(i for i in items if i["id"] == seed["email_llm"])
    assert (row["rule_name"], row["object_name"], row["field_name"], row["project_path"], row["reason"]) == (
        "llm", "User", "email", "grp/proj", "an e-mail address")

    assert api.get("/hits", params={"filter": json.dumps({"presence": "nowhere"})}).status_code == 422
    assert api.get("/hits", params={"filter": json.dumps({"status": "maybe"})}).status_code == 422

    # pending_hits counts the open LIVE hits (the Review queue's definition): the gone ssn hit is not in it
    projects, _ = lst(api, "/projects")
    assert [(p["full_path"], p["pending_hits"]) for p in projects] == [("grp/other", 0), ("grp/proj", 3)]


def test_hit_detail(api, seed):
    detail = api.get(f"/hits/{seed['email_llm']}").json()
    obj = detail["object"]
    assert (obj["name"], obj["source"], obj["file"], obj["line"], obj["props"]) == (
        "User", "main", "/user.go", 3, {"package": "users"})
    assert [(f["name"], f["type"], f["line"], f["is_subject"]) for f in obj["fields"]] == [
        ("email", "string", 5, True), ("id", "int", 4, False)]
    assert [(p["branch_name"], p["is_main"]) for p in detail["presence"]] == [("main", True)]
    assert {h["id"] for h in detail["other_hits"]} == {seed["email_core"], seed["user_obj"]}
    assert detail["rule"]["kind"] == "llm" and set(detail["allowed_actions"]) == {"confirm", "reject", "request_info"}

    card = api.get(f"/hits/{seed['card_llm']}").json()
    assert card["object"]["source"] == "mr"
    assert [(p["branch_name"], p["change"], p["mr_iid"]) for p in card["presence"]] == [("feature", "added", 7)]

    gone = api.get(f"/hits/{seed['ssn_llm']}").json()
    assert gone["object"]["source"] == "orphan" and gone["presence"] == []

    assert api.get("/hits/garbage").status_code == 404
    assert api.get(f"/hits/{seed['rules']['llm']}:00000000-0000-0000-0000-000000000000").status_code == 404


def test_review_transitions(api, seed, sql):
    hit = seed["email_llm"]

    def review(action, **extra):
        return api.post(f"/hits/{hit}/review", json={"action": action, **extra})

    assert api.get(f"/hits/{hit}").json()["decided_by"] is None       # open: nobody decided yet
    assert review("reopen").status_code == 409                       # already pending
    assert review("request_info").status_code == 422                 # needs a note
    r = review("request_info", note="where is it shown?")
    assert r.status_code == 200 and r.json()["status"] == "need_more_info"
    assert review("request_info", note="again").status_code == 409   # need_more_info -> match|no_match only

    r = review("confirm", category="pii-contact", severity="high", note="shown in the profile")
    body = r.json()
    assert r.status_code == 200, r.text
    assert (body["status"], body["category"], body["severity"], body["reviewer"], body["note"]) == (
        "match", "pii-contact", "high", ADMIN, "shown in the profile")
    assert body["reviewed_at"] is not None and body["decided_by"] == "human"
    assert review("reject").status_code == 409                       # decided: reopen first
    assert review("bogus").status_code == 422

    r = review("reopen")
    assert r.json()["status"] == "pending_review" and r.json()["category"] == "pii-contact"
    assert review("reject", note="test data").json()["status"] == "no_match"

    # category / severity / note without a status change
    r = api.patch(f"/hits/{seed['card_llm']}", json={"category": "pci", "severity": "critical"})
    assert r.status_code == 200
    assert (r.json()["status"], r.json()["category"], r.json()["reviewer"]) == ("pending_review", "pci", ADMIN)
    assert api.patch(f"/hits/{seed['card_llm']}", json={}).status_code == 422
    assert api.patch(f"/hits/{seed['card_llm']}", json={"severity": "huge"}).status_code == 422

    assert sql("SELECT status, reviewer IS NOT NULL FROM rule_hits WHERE subject_key = :s AND rule_id = :r",
               s=seed["user_email"], r=seed["rules"]["llm"]) == [("no_match", True)]


def test_list_rows_carry_allowed_actions_and_the_service_reason(api, seed, sql):
    """Every list row says what a reviewer may do with it (the same as the detail): the UI renders the buttons from
    the row, not from a client-side copy of the transitions. The detail keeps the service model's reason."""
    items, _ = lst(api, "/hits", range=[0, 24])
    for row in items:
        assert row["allowed_actions"] == api.get(f"/hits/{row['id']}").json()["allowed_actions"], row["id"]
    by_id = {i["id"]: i for i in items}
    assert by_id[seed["email_llm"]]["allowed_actions"] == ["confirm", "reject", "request_info"]
    assert by_id[seed["email_core"]]["allowed_actions"] == ["reopen"]
    detail = api.get(f"/hits/{seed['email_llm']}").json()
    assert detail["service_reason"] == "an e-mail address"                  # the service verdict is the current one
    assert api.get(f"/hits/{seed['email_core']}").json()["service_reason"] is None     # keyword hits have none

    r = api.post(f"/hits/{seed['email_llm']}/review", json={"action": "request_info", "note": "where?"})
    assert r.json()["allowed_actions"] == ["confirm", "reject", "reopen"]
    (row,), _ = lst(api, "/hits", filter={"id": seed["email_llm"]})
    assert row["allowed_actions"] == ["confirm", "reject", "reopen"] and row["cascaded"] is None

    # the service model's reason stays visible once a human decided (hit_verdicts keeps the service verdict)
    sql("UPDATE rule_hits SET prompt_version = 'classifier3', decided_tier = 'service', reviewer = NULL, "
        "status = 'pending_review' WHERE rule_id = :r AND subject_key = :s",
        r=seed["rules"]["llm"], s=seed["user_email"])
    api.post(f"/hits/{seed['email_llm']}/review", json={"action": "confirm", "note": "yes"})
    detail = api.get(f"/hits/{seed['email_llm']}").json()
    assert (detail["decided_tier"], detail["service_reason"]) == ("human", "an e-mail address")


def test_field_marks_filter_and_review_cascade(api, seed, sql):
    """An LLM object rule with mark_fields marks the fields the model named: the field marks can be hidden from the
    queue (field_marks=false) while keyword field hits stay, and a review of the object cascades to the field marks
    the service model set - never to a field a human decided."""
    from discovery_common import keys
    rule = api.post("/llm_rules", json={"name": "person", "category": "pii", "target": "object", "mode": "review",
                                        "mark_fields": True}).json()["id"]
    phone = keys.field_key(seed["user_key"], "phone")
    sql("""INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, field_name, rule_version, model, category,
                                  severity, status, reason, reviewer, decided_tier, first_seen_at, last_seen_at) VALUES
           (:r, :obj, 1, :obj, NULL, 1, 'm', 'pii', 'medium', 'pending_review', 'a person', NULL, 'service', now(), now()),
           (:r, :email, 1, :obj, 'email', 1, 'm', 'pii', 'medium', 'pending_review', 'a person', NULL, 'service', now(), now()),
           (:r, :id, 1, :obj, 'id', 1, 'm', 'pii', 'medium', 'pending_review', 'a person', NULL, 'service', now(), now()),
           (:r, :phone, 1, :obj, 'phone', 1, 'm', 'pii', 'medium', 'no_match', 'a person', 'alice', 'human', now(), now())""",
        r=rule, obj=seed["user_key"], email=seed["user_email"], id=seed["user_id"], phone=phone)
    marks = {f"{rule}:{seed['user_email']}", f"{rule}:{seed['user_id']}", f"{rule}:{phone}"}
    object_hit = f"{rule}:{seed['user_key']}"

    everything = ids(lst(api, "/hits", filter={"presence": "all"}, range=[0, 49])[0])
    without = ids(lst(api, "/hits", filter={"presence": "all", "field_marks": "false"}, range=[0, 49])[0])
    assert everything - without == marks
    assert {seed["email_core"], seed["email_llm"], object_hit} <= without          # keyword / LLM field rules stay
    assert ids(lst(api, "/hits", filter={"presence": "all", "field_marks": "true"}, range=[0, 49])[0]) == marks
    assert api.get("/hits", params={"filter": json.dumps({"field_marks": "maybe"})}).status_code == 422

    r = api.post(f"/hits/{object_hit}/review", json={"action": "confirm", "category": "personal", "note": "a client"})
    assert r.status_code == 200, r.text
    assert r.json()["cascaded"] == 2 and r.json()["status"] == "match"
    assert sql("""SELECT field_name, status, category, reviewer, decided_tier, note FROM rule_hits
                  WHERE rule_id = :r AND field_name IS NOT NULL ORDER BY field_name""", r=rule) == [
        ("email", "match", "personal", ADMIN, "human", "a client"),
        ("id", "match", "personal", ADMIN, "human", "a client"),
        ("phone", "no_match", "pii", "alice", "human", None)]                     # the human's decision stays
    # a field hit of its own, and hits of rules without mark_fields, cascade to nothing
    assert api.post(f"/hits/{seed['card_llm']}/review", json={"action": "reject"}).json()["cascaded"] is None
    bulk = api.post("/hits/review_bulk", json={"hit_ids": [object_hit], "action": "reopen", "note": "again",
                                               "dry_run": False}).json()
    assert bulk["items"][0]["cascaded"] == 0                                      # the fields are human-decided now


def test_hits_decided_by_filter(api, seed, sql):
    # a scan's negative LLM verdict is cached as a machine 'no_match' hit (no reviewer)
    sql("UPDATE rule_hits SET status = 'no_match' WHERE rule_id = :r AND subject_key = :s",
        r=seed["rules"]["llm"], s=seed["user_email"])
    assert api.post(f"/hits/{seed['card_llm']}/review", json={"action": "reject"}).status_code == 200

    machine, _ = lst(api, "/hits", filter={"decided_by": "machine", "presence": "all"}, range=[0, 99])
    human, _ = lst(api, "/hits", filter={"decided_by": "human", "presence": "all"}, range=[0, 99])
    assert seed["email_llm"] in [i["id"] for i in machine]
    assert all(i["decided_by"] == "machine" and i["reviewer"] is None and i["status"] in ("match", "no_match")
               for i in machine)
    assert [i["id"] for i in human] == [seed["card_llm"]] and human[0]["decided_by"] == "human"
    assert api.get("/hits", params={"filter": json.dumps({"decided_by": "robot"})}).status_code == 422


def test_parse_projects_queues_jobs_once(api, seed, sql):
    r = api.post("/projects/1/parse")
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["project_ids"] == [1] and body["parsers"] is None and body["already_queued"] == []
    assert [(j["kind"], j["dedup_key"]) for j in body["queued"]] == [
        ("scan_branch", "scan_branch:1:c1"), ("scan_mr", "scan_mr:1:f1:c1")]
    (payload,), = sql("SELECT payload FROM jobs WHERE kind = 'scan_branch'")
    assert payload == {"branch_id": 1, "commit": "c1", "force": False, "llm": False, "requested_by": ADMIN}

    # pending jobs of the same subject are not queued twice
    again = api.post("/projects/1/parse").json()
    assert again["queued"] == [] and again["already_queued"] == ["scan_branch:1:c1", "scan_mr:1:f1:c1"]

    # several projects, a parser subset (own dedup key), force
    r = api.post("/projects/parse", json={"project_ids": [1, 2], "parsers": ["protobuf", "graphql"], "mrs": False,
                                          "force": True})
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["project_ids"] == [1, 2] and body["parsers"] == ["graphql", "protobuf"]
    assert [j["dedup_key"] for j in body["queued"]] == ["scan_branch:1:c1:p=graphql,protobuf:force"]
    (payload,), = sql("SELECT payload FROM jobs WHERE dedup_key LIKE '%p=graphql%'")
    assert payload["parsers"] == ["graphql", "protobuf"]

    # every project
    assert api.post("/projects/parse", json={"mrs": False, "llm": True}).json()["project_ids"] == [1, 2]

    assert api.post("/projects/parse", json={"parsers": ["cobol"]}).status_code == 422
    assert api.post("/projects/parse", json={"parsers": []}).status_code == 422
    assert api.post("/projects/parse", json={"project_ids": []}).status_code == 422
    assert api.post("/projects/parse", json={"project_ids": [1, 999]}).status_code == 404
    assert api.post("/projects/1/parse", json={"mains": False, "mrs": False}).status_code == 422
    assert api.post("/projects/1/parse", json={"project_ids": [2]}).status_code == 422     # not on the one-project form
    assert api.post("/projects/999/parse").status_code == 404

def test_inventory_mode_and_manual_labels(api, seed, sql):
    projects, _ = lst(api, "/projects", filter={"q": "grp/proj"})
    assert projects[0]["scan_mode"] == "rules"

    # a human decision survives the switch; open machine hits of keyword / LLM rules go away
    assert api.post(f"/hits/{seed['card_llm']}/review", json={"action": "reject"}).status_code == 200
    r = api.patch("/projects/1", json={"scan_mode": "inventory"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["scan_mode"], body["previous_scan_mode"]) == ("inventory", "rules")
    assert body["removed_machine_hits"] == 4                     # email llm + core, ssn llm, user-objects
    assert [j["kind"] for j in body["parse"]["queued"]] == ["scan_branch", "scan_mr"]
    (payload,), = sql("SELECT payload FROM jobs WHERE kind = 'scan_branch'")
    assert payload["llm"] is False
    assert sql("SELECT count(*) FROM rule_hits")[0][0] == 1      # the rejected card hit
    assert api.patch("/projects/1", json={"scan_mode": "bogus"}).status_code == 422
    assert api.patch("/projects/999", json={"scan_mode": "rules"}).status_code == 404

    # browse the inventory
    objs, _ = lst(api, "/objects", filter={"project_id": 1})
    assert [o["name"] for o in objs] == ["User"]                 # main only by default
    objs, _ = lst(api, "/objects", filter={"project_id": 1, "presence": "live"})
    assert [o["name"] for o in objs] == ["Card", "User"]
    objs, _ = lst(api, "/objects", filter={"field": "card", "presence": "mr"})
    assert [(o["name"], o["source"], o["fields"]) for o in objs] == [("Card", "mr", 1)]
    user_key = str(seed["user_key"])
    detail = api.get(f"/objects/{user_key}").json()
    assert detail["source"] == "main" and [f["name"] for f in detail["fields"]] == ["email", "id"]
    assert api.get("/objects/00000000-0000-0000-0000-000000000000").status_code == 404

    # label a field and the object, relabel, list labelled, unlabel
    r = api.post(f"/objects/{user_key}/labels", json={"field_name": "email", "category": "pii", "severity": "high"})
    assert r.status_code == 200, r.text
    hit = r.json()
    assert (hit["status"], hit["category"], hit["rule_kind"], hit["decided_by"]) == ("match", "pii", "manual", "human")
    r = api.post(f"/objects/{user_key}/labels", json={"field_name": "email", "category": "contact", "note": "work mail"})
    assert (r.json()["id"], r.json()["category"], r.json()["severity"]) == (hit["id"], "contact", "medium")
    assert api.post(f"/objects/{user_key}/labels", json={"category": "identity"}).status_code == 200
    assert api.post(f"/objects/{user_key}/labels", json={"field_name": "nope", "category": "x"}).status_code == 422
    assert api.post(f"/objects/{user_key}/labels", json={"category": ""}).status_code == 422

    detail = api.get(f"/objects/{user_key}").json()
    assert [h["category"] for h in detail["object_hits"]] == ["identity"]
    assert [(f["name"], [h["category"] for h in f["hits"]]) for f in detail["fields"]] == [("email", ["contact"]), ("id", [])]
    labelled, _ = lst(api, "/objects", filter={"project_id": 1, "labelled": True})
    assert [(o["name"], o["labels"]) for o in labelled] == [("User", 2)]
    assert lst(api, "/objects", filter={"project_id": 1, "labelled": False})[0] == []
    manual, _ = lst(api, "/hits", filter={"kind": "manual", "status": "match"})
    assert len(manual) == 2

    assert api.delete(f"/objects/{user_key}/labels", params={"field_name": "email"}).status_code == 200
    assert api.delete(f"/objects/{user_key}/labels", params={"field_name": "email"}).status_code == 404
    assert [f["hits"] for f in api.get(f"/objects/{user_key}").json()["fields"]] == [[], []]

    # back to rules: nothing deleted, no parse asked
    body = api.patch("/projects/1", json={"scan_mode": "rules", "parse": False}).json()
    assert body["scan_mode"] == "rules" and body["removed_machine_hits"] == 0 and body["parse"] is None


def test_run_llm_rule_over_scanned_projects(api, seed, sql):
    sql("UPDATE gitlab_branches SET scanned_commit = commit")
    sql("INSERT INTO gitlab_projects (id, gitlab_id, project_name, full_path, visibility, scan_mode, created_at, "
        "updated_at) VALUES (3, 103, 'inv', 'grp/inv', 'private', 'inventory', now(), now())")
    llm = seed["rules"]["llm"]

    r = api.post(f"/llm_rules/{llm}/run")
    assert r.status_code == 202, r.text
    body = r.json()
    assert [(j["project_path"], j["branch_id"], j["mr_id"]) for j in body["queued"]] == [("grp/proj", 1, None)]
    assert body["skipped_inventory"] == ["grp/inv"] and body["already_queued"] == []
    (payload,), = sql("SELECT payload FROM jobs WHERE kind = 'llm_score'")
    assert payload == {"branch_id": 1, "commit": "c1", "rule_ids": [llm], "requested_by": ADMIN}

    again = api.post(f"/llm_rules/{llm}/run", json={"project_ids": [1], "mrs": True}).json()
    assert again["already_queued"] == [f"llm_rule:{llm}:v1:1:c1"]
    assert [(j["branch_id"], j["mr_id"]) for j in again["queued"]] == [(2, 1)]         # the MR delta

    assert api.post(f"/llm_rules/{llm}/run", json={"project_ids": [1, 999]}).status_code == 404
    assert api.post(f"/llm_rules/{llm}/run", json={"project_ids": []}).status_code == 422
    keyword = seed["rules"]["user-objects"]
    assert api.post(f"/llm_rules/{keyword}/run").status_code == 404
    sql("UPDATE rules SET enabled = false WHERE id = :r", r=llm)
    assert api.post(f"/llm_rules/{llm}/run").status_code == 422


def test_run_several_llm_rules_in_one_go(api, seed, sql):
    sql("UPDATE gitlab_branches SET scanned_commit = commit")
    sql("INSERT INTO rules (kind, name, category, severity, target, mode, scope, prompt, version, enabled) VALUES "
        "('llm', 'secrets', 'secret', 'high', 'object', 'review', '{}', 'Secrets?', 2, true)")
    llm, secrets = seed["rules"]["llm"], sql("SELECT id FROM rules WHERE name = 'secrets'")[0][0]

    r = api.post("/llm_rules/run", json={"rule_ids": [secrets, llm], "project_ids": [1], "mrs": True})
    assert r.status_code == 202, r.text
    body = r.json()
    assert [rule["name"] for rule in body["rules"]] == ["llm", "secrets"]
    assert [(j["branch_id"], j["mr_id"]) for j in body["queued"]] == [(1, None), (2, 1)]     # one job per branch
    assert body["queued"][0]["dedup_key"] == f"llm_rule:{llm}:v1+{secrets}:v2:1:c1"
    (payload,), = sql("SELECT payload FROM jobs WHERE dedup_key = :k", k=body["queued"][0]["dedup_key"])
    assert payload["rule_ids"] == [llm, secrets]

    assert api.post("/llm_rules/run", json={"rule_ids": []}).status_code == 422
    assert api.post("/llm_rules/run", json={"rule_ids": [llm, 9999]}).status_code == 404
    assert api.post("/llm_rules/run", json={"rule_ids": [seed["rules"]["user-objects"]]}).status_code == 404


def test_combination_keyword_rule_and_hit_fields(api, seed, sql):
    rule = {"name": "person-contact", "category": "pii", "severity": "high", "mode": "auto", "action": "score",
            "fields_all": ["last_?name|fio", " phone ", ""], "fields_none": ["masked"], "min_groups": 2}
    r = api.post("/keyword_rules", json=rule)
    assert r.status_code == 201, r.text
    body = r.json()
    assert (body["target"], body["fields_all"], body["fields_none"], body["min_groups"]) == (
        "object", ["last_?name|fio", "phone"], ["masked"], 2)

    for bad in ({"field_re": "x"}, {"min_groups": 3}, {"fields_all": ["("]}, {"action": "exclude"}):
        assert api.post("/keyword_rules", json={**rule, "name": "bad", **bad}).status_code == 422, bad
    assert api.post("/keyword_rules", json={"name": "only-none", "category": "x", "object_re": "X",
                                            "fields_none": ["a"]}).status_code == 422

    # an object hit with its fields: listed on the hit, marked as subjects in the detail
    sql("UPDATE rule_hits SET fields = ARRAY['email', 'id'] WHERE rule_id = :r AND subject_key = :s",
        r=seed["rules"]["user-objects"], s=seed["user_key"])
    detail = api.get(f"/hits/{seed['user_obj']}").json()
    assert detail["fields"] == ["email", "id"]
    assert [f["name"] for f in detail["object"]["fields"] if f["is_subject"]] == ["email", "id"]
    listed, _ = lst(api, "/hits", filter={"rule_id": seed["rules"]["user-objects"]})
    assert listed[0]["fields"] == ["email", "id"]


def test_rule_tags_tag_objects_of_confirmed_hits(api, seed, sql):
    # user-objects (review) hits User; tags are read at query time and need a confirmed hit
    rule_id = seed["rules"]["user-objects"]
    rule = api.get(f"/keyword_rules/{rule_id}").json()
    r = api.put(f"/keyword_rules/{rule_id}", json={**{k: v for k, v in rule.items() if v is not None},
                                                  "tags": ["personal-data", " gdpr ", ""]})
    assert r.status_code == 200, r.text
    assert r.json()["tags"] == ["personal-data", "gdpr"] and r.json()["version"] == rule["version"]   # no bump
    assert api.get(f"/hits/{seed['user_obj']}").json()["tags"] == ["personal-data", "gdpr"]

    user_key = str(seed["user_key"])
    assert api.get(f"/objects/{user_key}").json()["tags"] is None         # pending: not tagged yet
    assert lst(api, "/objects", filter={"tag": "gdpr"})[0] == []
    assert api.post(f"/hits/{seed['user_obj']}/review", json={"action": "confirm"}).status_code == 200
    assert api.get(f"/objects/{user_key}").json()["tags"] == ["gdpr", "personal-data"]
    objs, _ = lst(api, "/objects", filter={"tag": ["gdpr", "personal-data"]})
    assert [(o["name"], o["tags"]) for o in objs] == [("User", ["gdpr", "personal-data"])]

    # a core rule: only mode / enabled / tags are editable
    core = seed["rules"]["core:score_tags:field"]
    r = api.put(f"/keyword_rules/{core}", json={"tags": ["keyword-hit"]})
    assert r.status_code == 200 and r.json()["tags"] == ["keyword-hit"]
    assert "keyword-hit" in api.get(f"/objects/{user_key}").json()["tags"]   # core hit on email is confirmed

    # manual label with tags
    r = api.post(f"/objects/{user_key}/labels", json={"field_name": "id", "category": "ids", "tags": ["internal-id"]})
    assert r.status_code == 200 and r.json()["tags"] == ["internal-id"]
    assert "internal-id" in api.get(f"/objects/{user_key}").json()["tags"]
    assert api.post(f"/objects/{user_key}/labels", json={"category": "x", "tags": ["t" * 300]}).status_code == 422


# ---- agent / analyst helpers ------------------------------------------------------------------

def test_bulk_review_dry_run_then_apply(api, seed, sql):
    ids = [seed["email_llm"], seed["card_llm"], seed["email_core"], "1:00000000-0000-0000-0000-000000000000"]
    r = api.post("/hits/review_bulk", json={"hit_ids": ids, "action": "reject", "note": "test data"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dry_run"] is True and body["changed"] == 0
    assert [i["result"] for i in body["items"]] == ["ok", "ok", "conflict", "not_found"]   # core hit: confirmed
    assert sql("SELECT count(*) FROM rule_hits WHERE status = 'no_match'")[0][0] == 0

    body = api.post("/hits/review_bulk", json={"hit_ids": ids[:2], "action": "reject", "note": "test data",
                                               "dry_run": False}).json()
    assert body["changed"] == 2
    assert sql("SELECT DISTINCT status, decided_via, note FROM rule_hits WHERE status = 'no_match'") == [
        ("no_match", "rest", "test data")]
    rejected, _ = lst(api, "/hits", filter={"status": "no_match", "decided_via": "rest", "reviewed_after": "2000-01-01"})
    assert len(rejected) == 2
    # the statuses before migration 0023 are accepted as filter aliases for one release; output: the new ones
    legacy, _ = lst(api, "/hits", filter={"status": ["rejected", "no_match"], "decided_via": "rest"})
    assert sorted(h["id"] for h in legacy) == sorted(h["id"] for h in rejected)
    assert {h["status"] for h in legacy} == {"no_match"}
    assert lst(api, "/hits", filter={"status": "confirmed", "presence": "all"})[0] == \
        lst(api, "/hits", filter={"status": "match", "presence": "all"})[0]
    assert api.get("/hits", params={"filter": '{"status": "approved"}'}).status_code == 422

    assert api.post("/hits/review_bulk", json={"hit_ids": ids, "action": "reject", "note": ""}).status_code == 422
    assert api.post("/hits/review_bulk", json={"hit_ids": [str(i) for i in range(51)], "action": "reject",
                                               "note": "x"}).status_code == 422


def test_dry_run_keyword_and_llm_rules(api, seed, sql):
    r = api.post("/rules/dry_run", json={"kind": "keyword", "rule": {"name": "mails", "category": "pii",
                                                                     "field_re": ".*mail"}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["hits"], body["by_project"], body["human_confirmed"]) == (1, {"grp/proj": 1}, 0)
    assert body["sample"][0]["object"] == "User" and body["sample"][0]["fields"] == ["email"]
    assert sql("SELECT count(*) FROM rules WHERE name = 'mails'")[0][0] == 0      # nothing written

    api.post(f"/hits/{seed['email_llm']}/review", json={"action": "confirm"})
    combo = api.post("/rules/dry_run", json={"kind": "keyword", "rule": {
        "name": "c", "category": "pii", "fields_all": ["MAIL", "^id$"]}}).json()
    assert combo["hits"] == 1 and combo["sample"][0]["fields"] == ["email", "id"]
    field = api.post("/rules/dry_run", json={"kind": "keyword", "rule": {"name": "m", "category": "pii",
                                                                         "field_re": "email"}}).json()
    assert field["human_confirmed"] == 1                                    # people already confirmed this subject

    existing = api.post("/rules/dry_run", json={"rule_id": seed["rules"]["user-objects"],
                                                "rule": {"object_re": "Nobody"}}).json()
    assert (existing["hits"], existing["current_hits"], existing["gone"]) == (0, 1, 1)

    llm = api.post("/rules/dry_run", json={"rule_id": seed["rules"]["llm"]}).json()
    assert llm["kind"] == "llm" and llm["subjects_to_send"] == 0             # email already has a verdict
    new_llm = api.post("/rules/dry_run", json={"kind": "llm", "rule": {"name": "x", "category": "pii",
                                                                       "target": "object"}}).json()
    assert new_llm["model_calls"] == 1                                      # User (the only main object)
    assert api.post("/rules/dry_run", json={"kind": "keyword", "rule": {"name": "x"}}).status_code == 422
    assert api.post("/rules/dry_run", json={"rule_id": 9999}).status_code == 404



def test_llm_rule_mark_fields(api, seed, sql):
    """mark_fields (object rules only): stored in rules.scope, part of the rule's version; the dry
    run counts calls per object as without it."""
    created = api.post("/llm_rules", json={"name": "person", "category": "pii", "target": "object",
                                           "mark_fields": True})
    assert created.status_code == 201, created.text
    rule = created.json()
    assert (rule["mark_fields"], rule["version"]) == (True, 1)
    assert sql("SELECT scope FROM rules WHERE id = :r", r=rule["id"]) == [({"mark_fields": True},)]
    assert api.get(f"/llm_rules/{rule['id']}").json()["mark_fields"] is True
    assert any(r["id"] == rule["id"] and r["mark_fields"] for r in lst(api, "/llm_rules", range=[0, 49])[0])

    bad = api.post("/llm_rules", json={"name": "f", "category": "pii", "target": "field", "mark_fields": True})
    assert bad.status_code == 422 and "mark_fields" in bad.text
    plain = api.post("/llm_rules", json={"name": "plain", "category": "pii", "target": "object"}).json()
    assert plain["mark_fields"] is False
    assert sql("SELECT scope FROM rules WHERE id = :r", r=plain["id"]) == [({},)]       # nothing stored

    same = api.put(f"/llm_rules/{rule['id']}", json={**rule, "severity": "high"}).json()
    assert (same["mark_fields"], same["version"]) == (True, 1)
    off = api.put(f"/llm_rules/{rule['id']}", json={**same, "mark_fields": False}).json()
    assert (off["mark_fields"], off["version"]) == (False, 2)                        # changes what it hits
    assert sql("SELECT scope FROM rules WHERE id = :r", r=rule["id"]) == [({},)]
    assert api.put(f"/llm_rules/{plain['id']}", json={**plain, "severity": "low"}).json()["version"] == 1

    dry = api.post("/rules/dry_run", json={"kind": "llm", "rule": {"name": "x", "category": "pii",
                                                                   "target": "object", "mark_fields": True}}).json()
    assert dry["model_calls"] == 1 and dry["subjects_to_send"] == 1                  # per object, as without it
    patched = api.post("/rules/dry_run", json={"rule_id": rule["id"], "rule": {"mark_fields": True}}).json()
    assert patched["model_calls"] == 1


def test_rule_stats_overview_and_merge_requests(api, seed, sql):
    api.post(f"/hits/{seed['email_llm']}/review", json={"action": "confirm"})
    api.post(f"/hits/{seed['card_llm']}/review", json={"action": "reject", "note": "masked"})
    (llm,) = api.get("/rules/stats", params={"rule_id": seed["rules"]["llm"]}).json()
    (v1,) = llm["versions"]
    assert (v1["precision_human"], v1["human_decisions"], llm["top_reject_notes"]) == (0.5, 2, [{"note": "masked", "n": 1}])
    assert api.get("/rules/stats", params={"rule_id": 9999}).status_code == 404

    ov = api.get("/overview").json()
    assert {"objects_by_type", "hits_by_status", "confirmed_by_category", "pending_by_rule", "open_mrs"} <= set(ov)
    assert ov["open_mrs"] == 1 and api.get("/overview", params={"project_id": 999}).status_code == 404
    # the landscape: matches per project (email llm + email core confirmed; user-objects and ssn still open)
    (row,) = ov["matches_by_project"]
    assert (row["project_path"], row["matches"], row["open"]) == ("grp/proj", 2, 2)
    assert row["by_type"] == {"table": 0, "rpc": 0, "query": 0, "mutation": 0} and ov["filters"] is None
    high = api.get("/overview", params={"severity": "high"}).json()
    assert high["matches_by_project"][0]["matches"] == 1 and high["filters"] == {"severity": ["high"]}
    assert high["confirmed_by_category"] == [{"category": "pii", "severity": "high", "n": 1}]
    assert api.get("/overview", params={"category": "pii"}).json()["matches_by_project"][0]["matches"] == 2
    assert api.get("/overview", params={"category": "finance"}).json()["matches_by_project"] == []    # rejected
    by_rule = api.get("/overview", params={"rule_id": seed["rules"]["llm"]}).json()["matches_by_project"]
    assert (by_rule[0]["matches"], by_rule[0]["open"]) == (1, 1)                   # email match, ssn open
    api.put(f"/keyword_rules/{seed['rules']['core:score_tags:field']}", json={"tags": ["keyword-hit"]})
    assert api.get("/overview", params={"tag": "keyword-hit"}).json()["matches_by_project"][0]["matches"] == 1
    assert api.get("/overview", params={"tag": "nothing"}).json()["matches_by_project"] == []

    mrs = api.get("/mrs", params={"project_id": 1}).json()
    (mr,) = mrs["items"]
    assert (mr["iid"], mr["delta_objects"]) == (7, 1)
    api.post(f"/hits/{seed['card_llm']}/review", json={"action": "reopen"})
    api.post(f"/hits/{seed['card_llm']}/review", json={"action": "confirm"})
    detail = api.get(f"/mrs/{mr['id']}").json()
    assert detail["delta_counts"] == {"added": 1} and detail["delta"][0]["name"] == "Card"
    assert [h["field_name"] for h in detail["hits"]] == ["card_number"]
    assert not {"alert_candidates", "alerted_at"} & set(detail)                 # alerting removed (0022)
    assert all("alerted" not in h for h in detail["hits"]) and "alerted_at" not in mr

    r = api.post(f"/mrs/{mr['id']}/scan", json={"llm": False})
    assert r.status_code == 202 and r.json()["queued"] is True
    assert api.post(f"/mrs/{mr['id']}/scan").json()["queued"] is False         # already pending
    assert api.get("/mrs/999").status_code == 404


def test_object_search_filters_and_bulk_labels(api, seed, sql):
    objs, _ = lst(api, "/objects", filter={"project_glob": "grp/*", "fields_all": ["MAIL", "^id$"],
                                           "include_fields": True})
    assert [(o["name"], o["field_names"]) for o in objs] == [("User", ["email", "id"])]
    assert lst(api, "/objects", filter={"fields_all": ["mail"], "fields_none": ["^id$"]})[0] == []
    assert lst(api, "/objects", filter={"project_glob": "other/*"})[0] == []
    assert [o["name"] for o in lst(api, "/objects", filter={"field_type": "int"})[0]] == ["User"]
    assert [o["name"] for o in lst(api, "/objects", filter={"has_open_hits": True, "presence": "live"})[0]] == ["Card", "User"]
    assert lst(api, "/objects", filter={"decided": True})[0] == []
    assert api.get("/objects", params={"filter": json.dumps({"fields_all": ["("]})}).status_code == 422

    user_key = str(seed["user_key"])
    items = [{"object_id": user_key, "field_name": "email"}, {"object_id": user_key, "field_name": "nope"}]
    dry = api.post("/objects/labels", json={"items": items, "category": "pii", "tags": ["personal-data"]}).json()
    assert dry["dry_run"] and [i["result"] for i in dry["items"]] == ["ok", "error"]
    done = api.post("/objects/labels", json={"items": items, "category": "pii", "dry_run": False}).json()
    assert done["changed"] == 1
    assert sql("SELECT decided_via FROM rule_hits h JOIN rules r ON r.id = h.rule_id WHERE r.kind = 'manual'") == [("rest",)]
    assert [o["name"] for o in lst(api, "/objects", filter={"decided": True})[0]] == ["User"]


# ---- review fixes: dry run semantics, regex safety, filter values ----------------------------

def test_dry_run_matches_project_re_like_the_scanner(api, seed):
    def projects(project_re):
        r = api.post("/rules/dry_run", json={"kind": "keyword", "rule": {"name": "m", "category": "pii",
                                                                         "field_re": "email",
                                                                         "project_re": project_re}})
        assert r.status_code == 200, r.text
        return r.json()["projects"]

    # Pattern semantics: match from the start OR case-insensitive substring (not re.search)
    assert projects("PROJ") == 1 and projects("grp/") == 2
    assert projects("proj$") == 0 and projects("o.*proj") == 0


def test_dry_run_llm_counts_what_the_scanner_would_send_again(api, seed, sql):
    from discovery_common.models import CORE_PROMPT_FAMILIES
    LLM_PROMPTS_VERSION = CORE_PROMPT_FAMILIES["classifier"]      # the classifier's family (migration 0024)
    llm = seed["rules"]["llm"]
    # a machine verdict made with other core prompts (here: none recorded) is asked again
    assert api.post("/rules/dry_run", json={"rule_id": llm}).json()["subjects_to_send"] == 1
    sql("UPDATE rule_hits SET prompt_version = :v WHERE rule_id = :r", v=LLM_PROMPTS_VERSION, r=llm)
    same = api.post("/rules/dry_run", json={"rule_id": llm}).json()
    assert same["subjects_to_send"] == 0                     # email: a hit of the current version and prompts
    edited = api.post("/rules/dry_run", json={"rule_id": llm, "rule": {"prompt": "Is it personal data?"}}).json()
    assert edited["subjects_to_send"] == 1 and edited["model_calls"] == 1   # new version: pending email asked again
    assert edited["migration"] == {"subjects": 1, "model_calls": 1} and edited["fresh"]["subjects"] == 0
    sql("UPDATE rules SET version = 2 WHERE id = :r", r=llm)                # already bumped, hits still v1
    assert api.post("/rules/dry_run", json={"rule_id": llm}).json()["subjects_to_send"] == 1
    api.post(f"/hits/{seed['email_llm']}/review", json={"action": "confirm"})
    assert api.post("/rules/dry_run", json={"rule_id": llm}).json()["subjects_to_send"] == 0   # human decision is final
    sql("UPDATE rule_hits SET status = 'no_match', reviewer = NULL WHERE rule_id = :r AND subject_key = :s",
        r=llm, s=seed["user_email"])
    assert api.post("/rules/dry_run", json={"rule_id": llm}).json()["subjects_to_send"] == 1   # machine reject: again

    # what the model saw (subject_hash, 0018): the current content -> answered; other content -> asked again
    from discovery_common import keys
    sql("UPDATE rules SET version = 1 WHERE id = :r", r=llm)
    sql("UPDATE rule_hits SET subject_hash = :h WHERE rule_id = :r AND subject_key = :s",
        h=keys.field_subject_hash("email", "string", None, None), r=llm, s=seed["user_email"])
    assert api.post("/rules/dry_run", json={"rule_id": llm}).json()["subjects_to_send"] == 0
    sql("UPDATE rule_hits SET subject_hash = 'other' WHERE rule_id = :r AND subject_key = :s", r=llm, s=seed["user_email"])
    assert api.post("/rules/dry_run", json={"rule_id": llm}).json()["subjects_to_send"] == 1
    sql("UPDATE rule_hits SET reviewer = 'alice' WHERE rule_id = :r AND subject_key = :s", r=llm, s=seed["user_email"])
    assert api.post("/rules/dry_run", json={"rule_id": llm}).json()["subjects_to_send"] == 0   # a human decided


def test_dry_run_llm_object_rule_asks_again_about_other_field_names(api, seed, sql):
    from discovery_common import keys
    LLM_PROMPTS_VERSION = "rule3"
    sql("UPDATE gitlab_branches SET scanned_commit = commit")
    rule = api.post("/llm_rules", json={"name": "obj", "category": "pii", "target": "object"}).json()["id"]
    sql("""INSERT INTO rule_hits (rule_id, subject_key, project_id, object_key, rule_version, prompt_version, status,
                                  reviewer, names_hash)
           VALUES (:r, :k, 1, :k, 1, :pv, 'match', 'alice', :n)""",
        r=rule, k=seed["user_key"], pv=LLM_PROMPTS_VERSION, n=keys.names_hash("User", ["email", "id"]))
    assert api.post("/rules/dry_run", json={"rule_id": rule}).json()["subjects_to_send"] == 0
    sql("UPDATE rule_hits SET names_hash = :n WHERE rule_id = :r", r=rule, n=keys.names_hash("User", ["email"]))
    assert api.post("/rules/dry_run", json={"rule_id": rule}).json()["subjects_to_send"] == 1  # a field was added


def test_dry_run_does_not_hang_on_catastrophic_backtracking(api, seed, sql):
    import time
    sql("UPDATE objects SET name = :n WHERE name = 'User'", n="a" * 60 + "!")
    started = time.monotonic()
    r = api.post("/rules/dry_run", json={"kind": "keyword", "rule": {"name": "slow", "category": "x",
                                                                     "object_re": "(a|aa)+$"}})
    assert r.status_code == 422 and "too long" in r.json()["detail"], r.text
    assert time.monotonic() - started < 10
    for pattern in ("(a+)+$", "(?:x+|y)*z", "(\\w*)*"):         # nested quantifiers are refused up front
        r = api.post("/keyword_rules", json={"name": "n", "category": "x", "object_re": pattern})
        assert r.status_code == 422 and "nested quantifier" in r.text, (pattern, r.text)
        r = api.post("/keyword_rules", json={"name": "n", "category": "x", "fields_all": [pattern]})
        assert r.status_code == 422, pattern
    assert api.post("/keyword_rules", json={"name": "ok", "category": "x",
                                            "field_re": "(\\w+\\.)*\\w+"}).status_code == 201


def test_object_field_patterns_mean_the_same_in_postgres(api, seed):
    def status(*patterns, key="fields_all"):
        return api.get("/objects", params={"filter": json.dumps({key: list(patterns)})}).status_code

    assert status("mail") == 200 and status("^e.*l$", key="fields_none") == 200
    assert status("\\bmail") == 422                      # \b: word boundary in Python, backspace in Postgres
    assert status("(?P<g>mail)") == 422 and status("(?<g>mail)", key="fields_none") == 422
    assert status("a{1,300}") == 422                     # valid in Python, refused by Postgres: 422, not 500
    assert status(*["x"] * 21) == 422 and status("x" * 501) == 422


def test_bad_filter_values_are_422(api, seed):
    def get(path, **params):
        return api.get(path, params={k: json.dumps(v) if k == "filter" else v for k, v in params.items()})

    assert get("/hits", filter={"reviewed_after": "last week"}).status_code == 422
    assert get("/hits", filter={"first_seen_after": "abc"}).status_code == 422
    assert get("/hits", filter={"reviewed_after": "2026-01-01T00:00:00Z"}).status_code == 200
    assert get("/rules/stats", since="abc").status_code == 422
    assert get("/rules/stats", since="2026-01-01").status_code == 200
    assert get("/projects", filter={"id": ["x"]}).status_code == 422
    assert get("/keyword_rules", filter={"id": "x"}).status_code == 422
    assert get("/keyword_rules", filter={"enabled": "maybe"}).status_code == 422
    assert get("/keyword_rules", filter={"enabled": "true"}).status_code == 200


def test_list_mrs_query_is_a_literal(api, seed):
    def total(q):
        return api.get("/mrs", params={"q": q}).json()["total"]

    assert total("Add cards") == 1 and total("add") == 1
    assert total("%") == 0 and total("Add_cards") == 0 and total("_") == 0


def test_mr_sharing_a_source_branch_shows_no_foreign_delta(api, seed, sql):
    sql("""INSERT INTO gitlab_mrs (project_id, project_path, source_branch_id, source_branch, source_branch_commit,
                                   target_branch_id, target_branch, target_branch_commit, mr_id, title, state,
                                   created_at, updated_at)
           VALUES (1, 'grp/proj', 2, 'feature', 'f1', 1, 'main', 'c1', 8, 'Backport cards', 'opened', now(), now())""")
    owner_id, other_id = [r[0] for r in sql("SELECT id FROM gitlab_mrs ORDER BY id")]
    owner, other = api.get(f"/mrs/{owner_id}").json(), api.get(f"/mrs/{other_id}").json()
    assert owner["delta_counts"] == {"added": 1} and owner["delta_owner_mr_id"] == owner_id
    assert (other["delta"], other["hits"]) == ([], [])
    assert other["delta_owner_mr_id"] == owner_id and "older open MR" in other["note"]
    listed = {m["iid"]: m for m in api.get("/mrs").json()["items"]}
    assert (listed[7]["delta_objects"], listed[8]["delta_objects"]) == (1, 0)
    assert listed[8]["delta_owner_mr_id"] == owner_id
    scan = api.post(f"/mrs/{other_id}/scan", json={"llm": False}).json()
    assert scan["queued"] is False and scan["delta_owner_mr_id"] == owner_id
    parse = api.post("/projects/parse", json={"project_ids": [1], "mrs": True, "mains": False}).json()
    assert [j["dedup_key"].split(":")[1] for j in parse["queued"] if j["kind"] == "scan_mr"] == [str(owner_id)]
