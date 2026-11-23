---
hide:
  - footer
---

# Configuration: `conf.yaml`

`appsec-discovery --config conf.yaml`. Every section is optional; without a config file the default `score_tags`
keywords apply and no LLM runs. The schema is `appsec_discovery.models.ScoreConfig`.

```yaml
parsers: [all]            # or a list: swagger, protobuf, graphql, javascript, migrations, terraform, java, golang, python
object_types: [all]       # or: route, rpc, query, mutation, subscription, dto, entity, table, resource, ...
score_tags: {...}         # keyword rules on field / property names (below)
score_tags_mode: auto     # auto (default) | review
score_rules: [...]        # keyword rules limited to particular objects (below)
llm_rules: [...]          # LLM rules, see "LLM scoring in the CLI"
ai_api: {...}             # the LLM endpoint every LLM rule runs on
exclude_scan: [...]       # drop objects before scoring
exclude_scoring: [...]    # suppress particular keyword hits
```

## `score_tags`: keywords by category and severity

A keyword matches a field name or a property value (a route path) as a case-insensitive substring (or as a regex
from the start). A hit gives the field / property its severity and the category as a tag; the object gets the
highest severity and the tags of its hits.

```yaml
score_tags:
  pii:
    high: [first_name, last_name, phone, passport]
    medium: [address, email]
    low: [city]
  finance:
    high: [pan, card_number]
    medium: [amount, balance]
  auth:
    high: [password, pincode, codeword, token]
    medium: [login]
score_tags_mode: auto     # auto: hits are a match at once; review: hits are pending_review and do not score yet
```

The built-in default (`appsec_discovery/models/config.py`):

| category | high | medium | low |
|---|---|---|---|
| `pii` | full_name, fullname, first_name, firstname, last_name, lastname, phone, passport, ssn | address, email | city |
| `finance` | pan, card_number, cardnumber | account_number, accountnumber, balance, amount | - |
| `auth` | password, pincode, codeword, token | login, email, phone, username | - |

Severities: `critical`, `high`, `medium`, `low`, `info`. An unknown severity key is a config error.

## `score_rules`: keyword rules on particular objects

Matchers are `Pattern`s: a regex matched from the start of the value, or a case-insensitive substring; `parser` is
an exact name. A rule with `field_name` / `field_type` hits fields, otherwise the object. `object` and `field` are
accepted as short aliases of `object_name` and `field_name`.

```yaml
score_rules:
  - name: cards-in-dtos
    object_type: dto
    field_name: card
    severity: critical
    tag: pci
    mode: auto                   # auto | review (hits wait for triage and do not score until a match)
  - name: admin-routes
    object_name: /admin          # the name has no type word: "POST /admin", not "Route /admin"
    object_type: route
    tag: admin
    action: score                # score (default) | exclude
    project: payments/*          # optional project glob (library API: scan(..., project=...))
  - object_name: Legacy
    action: exclude              # suppresses every hit on Legacy* objects, like exclude_scoring
  - name: person-contact         # a combination of fields: one hit on the object
    fields_all:                  # groups: regex searched in the field name, case-insensitive
      - last_?name|surname|full_?name
      - phone|msisdn
    min_groups: 2                # optional: how many groups must match (default: all)
    fields_none: [masked]        # optional: no field may match
    tag: pii
    severity: high
    tags: [personal-data]        # object tags added once the hit is a match
```

A `fields_all` rule hits the object, not single fields, and the hit lists the fields that matched (`fields`): a last
name with a phone is a hit, a first name with a phone is not. One decision covers the whole combination.

`tags` (any `score_rules` / `llm_rules` entry): once a hit of the rule is a `match`, these tags are added to the
object; its fields keep the hit's own `tag`.

`action: alert` is deprecated: still accepted for one release, treated as `score` with a warning.

## Exclusions

```yaml
exclude_scan:                    # objects dropped before scoring; all set criteria must match
  - parser: swagger
    file: generated/
  - object_type: dto
    object_name: ^Internal
exclude_scoring:                 # keyword hits suppressed (LLM hits are not affected)
  - field_name: password_hash    # criteria: file, parser, object_name, object_type, prop_name, field_name, field_type, tag, keyword
    tag: auth
  - keyword: token               # the score_tags keyword that hit, exact
    object_name: TokenType
```

`prop_name` criteria only apply to hits on properties, `field_name` / `field_type` only to hits on fields; a rule
with no criteria never matches.

## Patterns and the object name

Object names carry no type word (it is `object_type`): `GET /user/login`, `/pkg.Svc/Method`, `public.users`,
`User`, `GetUser.me`, `aws_s3_bucket.logs`. Patterns on the name match the rest (`/admin`, `^GET `); use
`object_type` (and `parser`) for the kind. See [Parsers](../parsers/index.md) for the names each parser produces.
