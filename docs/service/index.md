---
hide:
  - footer
---

# Service: overview and quick start

The service (`appsec_discovery_service/`) keeps the inventory of a GitLab instance up to date: it polls the GitLab
API for projects under configured prefixes, clones main branches and open merge requests, parses them with the core
package, applies the rules edited in the UI and stores objects, hits and decisions in Postgres. People and agents
review the hits in the UI, over the REST API and over MCP.

## Components (`docker-compose.yml`)

| container | what it does |
|---|---|
| `discovery_scanner` | the scanner: a supervisor with a scheduler (GitLab polling, periodic jobs) and worker processes that run the jobs of the Postgres queue - `MAX_WORKERS` scan workers, `SYNC_WORKERS` GitLab sync workers, `CONTROL_WORKERS` control workers, `LLM_WORKERS` LLM workers (service model runs, `LLM_CONCURRENCY` calls in flight each). Built from the repository root so it uses the core package sources (pinned `appsec-discovery>=1.1.0,<2.0.0`) |
| `discovery_llm` | the bundled llama.cpp server (OpenAI-compatible API at `http://discovery_llm:8080/v1`), the default **service model**; downloads `LLM_HF_REPO` into the `llm_cache` volume on first start; scaled to 0 when an external API is used |
| `discovery_migrate` | one-shot Alembic migration (`python -m discovery_common.migrate`); the API and the scanner start after it succeeded |
| `discovery_api` | FastAPI: REST under `/api` (OpenAPI UI at `/api/docs`) and the MCP server at `/api/mcp`; the same bearer token for both |
| `discovery_ui` | the React (react-admin) UI |
| `discovery_db` | Postgres 13, data in `$HOME/db_data` |
| `discovery_nginx` | the only published port (`HTTP_PORT`, default 80): the UI at `/`, the API at `/api/`, login rate limit on `/api/token` (5 per minute per client) |

Networks: `edge` (nginx, UI, API), `backend` (internal, no route outside: Postgres, migrate, API, scanner, LLM),
`egress` (the scanner for GitLab, the LLM for the model download). Postgres, the API and the LLM server are not
reachable from the host; `docker compose -f docker-compose.yml -f docker-compose.dev.yml up` publishes Postgres on
`127.0.0.1:54321` (`POSTGRES_DEV_PORT`) for local debugging or a BI tool.

```
GitLab API ──poll──> scanner ──clone / parse / rules──> Postgres <── API (REST + MCP) <── nginx <── UI, agents, scripts
                        │                                  ▲
                        └── service model (discovery_llm or any OpenAI-compatible API)
                                       harness model (an agent harness over MCP) ─┘
```

The service only **reads** GitLab (project / branch / MR lists, MR state, clones over HTTP) and never writes to it:
no MR comments, notes, labels, statuses, no webhooks. Objects added or changed in an MR are stored as the MR's
delta and reviewed like the rest (presence "Only in open MRs"); MR data is available through the API / MCP
(`list_mrs`, `get_mr`, `scan_mr`), there is no MR page in the UI.

## Quick start

Requirements: Docker Compose v2.20+ with BuildKit (the default since Docker 23; the compose file uses
`depends_on.required` and per-Dockerfile `.dockerignore`), a GitLab token with the scopes `read_api` and
`read_repository` (a project / group access token or a personal token of a user with the Reporter role).

```bash
git clone https://github.com/dmarushkin/appsec-discovery
cd appsec-discovery/appsec_discovery_service
cp .env.example .env
```

Edit `.env` - the required part:

```ini
POSTGRES_PASSWORD=<random>
GITLAB_URL=https://gitlab.example.com
GITLAB_PRIVATE_TOKEN=<read-only token>
# comma separated, matched on path segments: "grp/" = every project of the group, "grp/proj" = that project
# only (not grp/proj-tools); a trailing * keeps a plain string prefix ("grp/proj*")
GITLAB_PROJECTS_PREFIX=grp/
GITLAB_SCAN_TYPES=mains,mrs
UI_ADMIN_EMAIL=admin@example.com
# bcrypt hash in single quotes (a plain UI_ADMIN_PASSWORD and well-known passwords are refused at startup):
#   python -c "from passlib.context import CryptContext; print(CryptContext(schemes=['bcrypt']).hash('<password>'))"
UI_ADMIN_PASSWORD_HASH='$2b$12$...'
# at least 32 random characters: openssl rand -hex 32
UI_JWT_KEY=<random>
```

```bash
docker compose up --build                       # with the bundled local model
docker compose up --build --scale discovery_llm=0   # with LLM_API_URL / LLM_API_KEY / LLM_API_MODEL set to an external API
```

Open `http://127.0.0.1/` and log in with `UI_ADMIN_EMAIL` and the password. The scanner syncs the projects of the
prefixes, scans their main branches and open MRs and runs the enabled LLM rules; see [Scanning](scanning.md) for
what happens when and [Configuration](config.md) for every setting (`LLM_API_URL=` empty disables LLM rules).

First things to do in the UI: check **Pipeline health** (Admin role) while the first scans run, then switch to
**Datasec** and look at the **Review** queue and the default rules (`db-tables-with-client-data` is enabled,
`api-with-auth` is disabled) under **LLM rules** - see [Rules](rules.md) and [UI](ui.md).

To connect an agent (a harness model) use the MCP server at `http://127.0.0.1/api/mcp` with a bearer token from
`POST /api/token` - see [MCP](mcp.md) and [Tiered review](tiers.md).

## Production notes

* Put a TLS terminator in front of nginx and declare it in `discovery_nginx/conf.d/real_ip.conf` (copy
  `real_ip.conf.example`, set its address / CIDR): otherwise every request comes from the terminator's address and
  the login rate limit of `/api/token` is shared by all clients.
* Bake the images in your own registry / Kubernetes and use an external Postgres (`DATABASE_URL` is what the
  services read; the compose file builds it from `POSTGRES_*`).
* Upgrade the migrate, API, scanner and UI images together: the migrations change constraints that older versions
  cannot write (`discovery_migrate` runs before the API and the scanner start).
* For analytics connect Superset, Grafana, Tableau, ... to Postgres (see the dev compose override for publishing
  it).
* Postgres settings: the compose file starts the bundled Postgres with `shared_buffers` 1 GB, `work_mem` 32 MB,
  `effective_cache_size` 3 GB, `random_page_cost` 1.1, `max_wal_size` 2 GB (`PG_*` variables, see
  [Configuration](config.md#postgres-compose)) - sized for an 8 GB host shared with the scanner and the LLM server.
  An external Postgres needs the equivalent; with the image defaults the planner falls back to sequential scans at
  millions of rows.
