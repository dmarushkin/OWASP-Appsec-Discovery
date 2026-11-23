---
hide:
  - footer
---

# Objects, hits and scoring

The data model is the same in the CLI report and in the service database.

## Objects and fields

A **`CodeObject`** is one thing a parser found: an API route, a gRPC method, a GraphQL operation, a DTO / entity
class, a database table, a Terraform block.

| key | meaning |
|---|---|
| `hash` | identity of the object: parser, type, name and position-independent content (the service's `object_key` is built from it); lines are never part of it |
| `object_name` | the name without a type word: `GET /user/login`, `/pkg.Svc/Method`, `Queries.promoterInfo`, `public.users`, `User` |
| `object_type` | `route`, `rpc`, `query`, `mutation`, `subscription`, `dto`, `entity`, `table`, `resource`, `data`, `module`, `variable`, `output`, `provider`, ... |
| `parser` | the parser that produced it |
| `file`, `line` | where it is |
| `properties` | name / value pairs such as `path` and `method` of a route |
| `fields` | the fields (`field_name`, `field_type`, `file`, `line`, `comment`, `samples`), named by their path: `query.param.username`, `input.SumInput.n1`, `output.Payload.firstName` |
| `comment` | documentation taken from the code (cut at 1000 characters) |
| `severity`, `tags` | the score: computed from the `match` hits |
| `hits` | every rule match on the object or its fields |

Field `samples` (at most 5 of 200 characters) are values seen in the code: defaults, enum values, examples.
Secrets never become samples: samples of secret-named fields (`password`, `token`, `api_key`, `client_secret`,
`dsn`, ...) and secret-looking values (PEM keys, `user:pass@` URLs, `Bearer` / `Basic` credentials, JWTs, cloud /
VCS tokens, long random strings) are dropped by every parser.

## Hits

A **hit** is one match of one rule on one subject: a field, a property or the object itself (`subject`:
`field` | `prop` | `object`). It carries the rule (`rule`, `rule_type` keyword / llm, `rule_id`,
`rule_version`), the matched `keyword` (keyword rules) or the model's `reason` and `model` (LLM rules), the
`fields` that made an object match (combination rules, object LLM rules), `severity`, `tags` and a **status**:

| status | meaning |
|---|---|
| `pending_review` | the rule runs in mode `review` (or the hit was reopened): waits for a decision, does not score |
| `match` | the rule applies: scores the subject (mode `auto` hits are a `match` at once) |
| `no_match` | the rule does not apply: listed, never scores (LLM rules store negative verdicts so a subject is not asked again) |
| `need_more_info` | the model was unsure, or a reviewer asked for more information: waits, does not score |

Reviewer actions keep their verbs: **confirm** -> `match`, **reject** -> `no_match`, **request info** ->
`need_more_info`, **reopen** -> `pending_review`. Transitions: `pending_review` -> `need_more_info` | `match` |
`no_match`; `need_more_info` -> `match` | `no_match` | `pending_review`; `match` / `no_match` -> `pending_review`.
The old statuses `confirmed` / `rejected` are accepted as aliases by the library (`apply_hit_statuses`,
`RuleHit(status=...)`, with a deprecation warning) and by the service's status filters for one release; every output
has the new names only.

In the service a hit also records **who decided** (`decided_tier`: `service` | `harness` | `human`, see
[Tiered review](service/tiers.md)) and, for human decisions, the reviewer and `decided_via` (`rest` | `mcp`).

## Scoring

Only `match` hits score. A field's severity is the highest severity of its `match` hits and its tags are their
tags (`pii`, `auth`, `llm-pci`, ...). An object's severity is the highest of its own and its fields' hits; its tags
are the union, plus the `tags` of the rules whose hits matched (`personal-data`, `gdpr`). Objects without a match
have no severity. `appsec_discovery.apply_hit_statuses(objects, {hit.key(obj.hash): status})` applies stored
decisions and recomputes everything.

Severities: `critical` > `high` > `medium` > `low` > `info`.

## Reports

* **YAML / JSON**: the objects as above, hits under `hits`.
* **SARIF 2.1.0**: a result per scored object (`[<parser>.<object_type>] <name>`) and per scored field
  (`...: field <name>`), the hits in `properties.hits`; a result whose hits all wait for a decision has
  `kind: review` and `level: none`.
