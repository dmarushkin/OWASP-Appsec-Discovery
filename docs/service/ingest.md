---
hide:
  - footer
---

# External parsers (ingest)

Objects collected outside GitLab - tables and columns of SQL servers, a CMDB, an API gateway export - are pushed
to an **external project** (`external/<team>/<source>`, created on the first push, never cloned or synced) and
then behave like parsed code: keyword rules, LLM rules over the stored snapshot, hits, decisions, tags, the review
queue, the inventory.

## Pushing a state

`POST /ingest` (MCP `ingest_objects` for up to 1000 objects / 50k fields, 16 MB per call) takes the **full state
of one parser** for one project:

```json
{"project": "external/payments/db01-billing", "parser": "postgres",
 "objects": [{"name": "public.clients", "type": "table", "file": "db01/billing", "props": {"schema": "public"},
              "comment": "customer master data",
              "fields": [{"name": "last_name", "type": "varchar(100)", "line": 2, "comment": "...", "samples": ["..."]}]}]}
```

An `ingest` job applies the keyword rules (combinations, tags; nothing in inventory mode) and replaces that
parser's objects in the project snapshot: objects missing from the new state are removed (decisions on them are
kept and come back with the object); `llm: true` also runs the LLM rules. Object identity is (parser, file, type,
name): keep them stable between pushes. Send masked or synthetic samples. An unchanged state is a no-op
(`unchanged: true`); an `Idempotency-Key` header replays the first result (`replayed: true`).

Large states go in chunks: `POST /ingest/sessions` -> `PUT /ingest/sessions/{id}/chunks/{seq}` ->
`POST /ingest/sessions/{id}/commit` (`DELETE /ingest/sessions/{id}` abandons one; open sessions expire after 24
hours). Limits: 50k objects / 500k fields per request, 5k fields per object, 50 props per object, 64 MB per body
(nginx `client_max_body_size` for `/api/ingest`), 1M objects per session.

`GET /ingest` (MCP `list_ingests`; UI Ingest batches) lists the batches with their status: `open`, `committed`,
`processed`, `failed`, `superseded` (replaced by a newer processed state; kept without chunks for the key's
retention). `POST /projects/parse` re-applies the latest state of each external parser (after rule edits).
`GET /scan_progress` counts external projects apart (`external`).

## Service tokens

Collectors authenticate with **service tokens**: `POST /tokens` by the admin (UI Service tokens page):
`{"name", "project_prefixes": ["external/payments"]}` - scope `ingest` only, limited to those project path
prefixes under `external/`, accepted by the `/ingest` endpoints only (review, rules and MCP refuse them). The
token (`adt_...`) is shown once; only its sha256 is stored. `GET /tokens` lists them, `DELETE /tokens/{id}` revokes
(the row stays with `revoked_at`).

## Example collector

`appsec_discovery_service/collectors/sql_schema.py` reads `information_schema` of PostgreSQL, MS SQL Server,
MySQL, ... through SQLAlchemy and pushes one state (`POST /ingest`, or an upload session for large schemas, chosen
by object and field counts):

```bash
export DISCOVERY_TOKEN=adt_...
export DISCOVERY_DB_URL='postgresql://reader:...@db01:5432/billing'      # or --url-file; never --url with a password
python sql_schema.py --api http://discovery.local/api --project external/payments/db01-billing --parser postgres
```

`file` = `<host>/<database>`, `name` = `<schema>.<table>`; keep the URL host / database spelling stable between
runs. Run it on a schedule: an unchanged schema is a no-op on the server.
