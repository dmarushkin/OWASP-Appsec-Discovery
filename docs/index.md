---
hide:
  - footer
---

# AppSec Discovery

AppSec Discovery turns code into an **inventory of the objects that carry data**: database tables, API routes,
gRPC methods, GraphQL operations, DTOs, Terraform resources. Every object has fields; **rules** mark the objects
and fields that hold sensitive data (PII, payment, authentication secrets, ...):

* **keyword rules** match names (`last_name`, `card_number`, a combination of fields),
* **LLM rules** ask a model (any OpenAI-compatible API) with a prompt you write.

Every rule match is a **hit** with a status: `pending_review`, `match`, `no_match` or `need_more_info`. In the
service, LLM verdicts go through a **tiered review**: the **service model** categorises everything, a **harness
model** (a capable model in an agent harness connected over MCP) checks what the service model was unsure about and
a sample of what it was sure about, and a **human** decides the rest in the UI.

There are two ways to use it:

| | CLI / Python package `appsec-discovery` | Service (`appsec_discovery_service/`) |
|---|---|---|
| Input | one source folder | GitLab projects, polled over the API (main branches and open MRs) |
| Rules | `conf.yaml` | edited in the UI / REST / MCP, stored in Postgres |
| Output | YAML / JSON / SARIF report | inventory, hits and decisions in Postgres; UI, REST API, MCP server |
| LLM | optional, one endpoint | the service model + optional harness model + human review |

## Where to go

**CLI / package**

* [CLI quick start](cli/index.md) - install, run, reports, CI gate, the Python API
* [Configuration (`conf.yaml`)](cli/config.md) - keyword rules, `score_rules`, exclusions
* [LLM scoring in the CLI](cli/llm.md) - a local llama.cpp server or an external API, `llm_rules`
* [Parsers](parsers/index.md) - what each parser reads and the objects it produces
* [Objects, hits and scoring](scoring.md) - the data model shared by the CLI and the service

**Service**

* [Service overview and quick start](service/index.md) - components, docker compose, network perimeter
* [Configuration reference (`.env`)](service/config.md) - every setting with its default
* [Scanning and change detection](service/scanning.md) - GitLab polling, main branches and MRs, what triggers a scan
* [Jobs and workers](service/jobs.md) - job kinds, the queue, progress, failure causes, graceful shutdown
* [Rules and hits in the service](service/rules.md) - keyword / LLM rules, default rules, modes, tags, inventory mode
* [Tiered review: service model, harness model, human](service/tiers.md) - verify items, QA sample, quality, prompt trials
* [LLM rule lifecycle](service/llm-lifecycle.md) - re-asks, rule versions, prompt versions, rollouts, verdict history
* [External executor](service/external-executor.md) - a harness model answers instead of the service model
* [UI](service/ui.md) - pages and the Admin / Datasec roles
* [MCP server](service/mcp.md) - connection and the tool list
* [REST API](service/api.md) - endpoint reference
* [External parsers (ingest)](service/ingest.md) - push objects collected outside GitLab, service tokens, collectors
* [Data model and migrations](service/data-model.md) - tables, keys, migrations `0001` .. `0029`
* [Retention](service/retention.md) - what is deleted when
* [Troubleshooting](service/troubleshooting.md) - failures and their causes

**Project**

* [Changelog](changelog.md)
* [Contributing](contrib/index.md)
