# OWASP AppSec Discovery

**Code in, inventory of sensitive data out.** AppSec Discovery parses source code and extracts the objects that
carry data - database tables, API routes, gRPC methods, GraphQL operations, DTOs, Terraform resources - with
their fields. Rules then mark what is sensitive:

* **keyword rules** match names (`last_name`, `card_number`, a last name *together with* a phone);
* **LLM rules** ask a model with a prompt you write (any OpenAI-compatible API, a local llama.cpp server is enough).

Every match is a **hit** with a status: `pending_review`, `match`, `no_match` or `need_more_info`. In the
service, LLM verdicts go through a **tiered review**: the **service model** (a cheap model the service calls)
categorises everything, a **harness model** (a capable model in an agent harness, connected over MCP) checks what
the service model was unsure about plus a sample of what it was sure about, and a **human** decides the rest in
the UI. Human decisions always win and are never overwritten by scans.

Use it to know where personal, payment and authentication data lives: prioritise reviews and audits, scope data
governance, focus monitoring on the routes and tables that matter, inventory IaC assets.

## Two ways to use it

| | **CLI / Python package** | **Service** |
|---|---|---|
| Input | one source folder | a GitLab instance: projects under prefixes, main branches and open MRs, polled over the API (read-only, no webhooks) |
| Rules | `conf.yaml` | edited in the UI / REST / MCP, stored in Postgres |
| Output | YAML / JSON / SARIF report (DefectDojo, CI gate) | inventory, hits and decisions in Postgres; UI with **Admin** and **Datasec** roles, REST API, MCP server for agents |
| LLM | optional, one endpoint | service model + optional harness model + human review; rule versions and budgeted rollouts |

Under the hood: the core package `appsec_discovery` (Semgrep OSS with bundled rules plus own scanners for specs,
schemas, migrations and HCL); the service adds a scanner, a FastAPI API with MCP, a React UI and Postgres.

## Quick start: CLI

```bash
pip install appsec-discovery
appsec-discovery --source path/to/project                       # default keyword rules, YAML report
appsec-discovery --source path/to/project --config conf.yaml --output report.sarif --output-type sarif
```

```yaml
# conf.yaml - keyword rules by category and severity; add ai_api / llm_rules for LLM scoring
score_tags:
  pii:     {high: [first_name, last_name, phone, passport], medium: [address, email]}
  finance: {high: [pan, card_number], medium: [amount, balance]}
  auth:    {high: [password, token], medium: [login]}
ai_api:                                   # optional: a local llama.cpp server or an external API
  base_url: http://localhost:8080/v1
  model: local-model
```

```yaml
- object_name: GET /user/login            # a route from a swagger file
  object_type: route
  severity: high
  tags: [auth]
  fields:
    query.param.password: {field_type: string, severity: high, tags: [auth]}
```

More: [CLI quick start](docs/cli/index.md) · [conf.yaml reference](docs/cli/config.md) ·
[LLM scoring in the CLI](docs/cli/llm.md) · [Parsers](docs/parsers/index.md).

## Quick start: service

Requirements: Docker Compose v2.20+ (BuildKit), a GitLab token with `read_api` + `read_repository`.

```bash
git clone https://github.com/dmarushkin/appsec-discovery
cd appsec-discovery/appsec_discovery_service
cp .env.example .env     # set GITLAB_URL, GITLAB_PRIVATE_TOKEN, GITLAB_PROJECTS_PREFIX (grp/), POSTGRES_PASSWORD,
                         # UI_ADMIN_EMAIL, UI_ADMIN_PASSWORD_HASH (bcrypt), UI_JWT_KEY (32+ random chars)
docker compose up --build                            # with the bundled local model (discovery_llm)
docker compose up --build --scale discovery_llm=0    # with an external API: LLM_API_URL / LLM_API_KEY / LLM_API_MODEL
```

Open `http://127.0.0.1/`. The scanner syncs the projects, scans main branches and open MRs, applies the rules
and runs the enabled LLM rules; hits wait in **Review**. Two default LLM rules come with a new install:
`db-tables-with-client-data` (enabled, mode auto) and `api-with-auth` (disabled); the keyword rules `kw-fields`
/ `kw-props` are disabled until you enable them. An agent connects to the MCP server at
`http://127.0.0.1/api/mcp` with a token from `POST /api/token`.

More: [Service overview](docs/service/index.md) · [Configuration (.env)](docs/service/config.md) ·
[UI](docs/service/ui.md) · [MCP](docs/service/mcp.md) · [REST API](docs/service/api.md).

### Ask the marked-up landscape over MCP

The rules turn the code base into a map of where sensitive data lives. Connect your agent (Claude Code or any
MCP client) to `/api/mcp` and ask about it in plain words - the agent answers from the marked objects and can
open the code to check:

* *Where is authorization implemented?* - API operations that carry passwords, codes or tokens (rule `api-with-auth`);
* *Which services process card numbers (PCI scope)?* - projects with tables or APIs holding PAN (add a card-data rule first);
* *Where do we store personal data?* - tables with client data and the columns that hold it (rule `db-tables-with-client-data`).

More: [Asking questions about the landscape](docs/service/mcp.md#asking-questions-about-the-landscape).

## Architecture

```
                 CLI: appsec-discovery --source . --config conf.yaml  ->  YAML / JSON / SARIF
                                       │ same core package
GitLab API ──poll──> discovery_scanner ─┤ clone, parse, keyword rules, LLM rules ──> Postgres
                      (job queue:       │                                             ▲
                       scan / llm /     └── service model: discovery_llm (llama.cpp)   │
                       control workers)     or any OpenAI-compatible API               │
                                                                                       │
            browser ──> nginx ──> discovery_ui (Admin | Datasec)  ──>  discovery_api ──┘
            agents  ──> nginx ──> /api/mcp  (harness model: verifies, takes over runs, proposes prompts)
```

Flow of a verdict: service model -> `llm_verify` items -> harness model (`llm_work_claim(purpose="verify")`)
-> final, or a question for a human -> Review. The service only reads GitLab: no MR comments, no alerts, no
webhooks; MR objects are stored as deltas and reviewed like everything else.

## Documentation

| | |
|---|---|
| [Overview and navigation](docs/index.md) | the docs index (mkdocs site: `mkdocs.yml`) |
| [Objects, hits and scoring](docs/scoring.md) | the data model shared by the CLI and the service |
| [Scanning and change detection](docs/service/scanning.md) | polling, mains and MRs, the diff-based scan skip |
| [Jobs and workers](docs/service/jobs.md) | job kinds, progress, failure causes, graceful shutdown |
| [Rules and hits in the service](docs/service/rules.md) | keyword / LLM rules, default rules, modes, tags, inventory mode |
| [Tiered review](docs/service/tiers.md) | service model, harness model, human; QA, quality, prompt trials |
| [LLM rule lifecycle](docs/service/llm-lifecycle.md) | re-asks, rule versions, prompt versions, rollouts, history |
| [External executor](docs/service/external-executor.md) | a harness model answers instead of the service model |
| [External parsers (ingest)](docs/service/ingest.md) | push objects collected outside GitLab |
| [Data model and migrations](docs/service/data-model.md) · [Retention](docs/service/retention.md) · [Troubleshooting](docs/service/troubleshooting.md) | |
| [Changelog](docs/changelog.md) · [Contributing](docs/contrib/index.md) | |

![service_ui](https://github.com/dmarushkin/appsec-discovery/blob/main/service_ui.png?raw=true)

## License

[MIT](LICENSE).
