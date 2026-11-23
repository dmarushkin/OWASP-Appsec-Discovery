---
hide:
  - footer
---

# CLI and Python package

The `appsec-discovery` package scans one source folder and prints the objects it found, scored by the rules of a
`conf.yaml`. It runs the parsers (most of them on the Semgrep OSS engine with bundled rules, some on their own
scanners) and, optionally, LLM rules against any OpenAI-compatible API. Models never run inside the process, so
`pip install` needs no native build.

## Install and run

```bash
pip install appsec-discovery
appsec-discovery --source path/to/project                 # default keyword rules, YAML to stdout
appsec-discovery --source path/to/project --config conf.yaml --output report.json --output-type json
```

Options (`appsec-discovery --help`):

| option | meaning |
|---|---|
| `--source DIR` | the folder to scan (required) |
| `--config FILE` | `conf.yaml`, see [Configuration](config.md); without it the default `score_tags` keywords apply |
| `--output FILE` | write the report to a file instead of stdout |
| `--output-type yaml|json|sarif` | report format (default `yaml`) |
| `--only-scored-objects` | report only objects with a severity / tags |
| `--fail-on-error` | exit 1 when any parser failed (by default only when every parser failed) |
| `--fail-on-severity low|medium|high|critical` | exit 1 when an object of this severity or higher was reported (CI gate) |
| `-v` / `-vv` | log level INFO / DEBUG (default WARNING) |

Exit codes: `0` success; `1` every parser failed, any parser failed with `--fail-on-error`, or the severity gate
fired; `2` invalid arguments or config.

Example output (swagger sample, keyword rules):

```yaml
- hash: 40140abef3b5f45d447d16e7180cc231
  object_name: GET /user/login
  object_type: route
  parser: swagger
  severity: high
  tags: [auth]
  file: swagger.yaml
  line: 1
  properties:
    path: {prop_name: path, prop_value: /user/login, severity: medium, tags: [auth]}
    method: {prop_name: method, prop_value: GET}
  fields:
    query.param.username:
      field_name: query.param.username
      field_type: string
      severity: medium
      tags: [auth]
    query.param.password:
      field_name: query.param.password
      field_type: string
      severity: high
      tags: [auth]
  hits:
    - rule: kw-fields
      subject: field
      field_name: query.param.password
      keyword: password
      severity: high
      tags: [auth]
      status: match
```

What the fields of an object mean, how hits turn into severity and tags, and the statuses a hit can have are
described in [Objects, hits and scoring](../scoring.md). The objects each parser produces are in
[Parsers](../parsers/index.md).

## Reports and CI/CD

`--output-type sarif` writes SARIF 2.1.0 that vulnerability management systems import (DefectDojo: "SARIF" scan
type). Each object is one result with its hits in `properties.hits`; hits that wait for a decision
(`pending_review` / `need_more_info`) are results of `kind: review`.

```bash
appsec-discovery --source . --config conf.yaml --output report.sarif --output-type sarif --fail-on-severity high
```

![DefectDojo import](https://github.com/dmarushkin/appsec-discovery/blob/main/dojo1.png?raw=true)

## Python API

```python
import appsec_discovery

result = appsec_discovery.scan("path/to/project", "conf.yaml")           # a path, a dict or a ScoreConfig
result = appsec_discovery.scan("path/to/project", {"score_tags": {...}}, project="grp/payments-api")
objects, failed = result.objects, result.errors                            # {parser name: error message}
report = appsec_discovery.render_report(objects, "sarif")

# apply decisions stored elsewhere (the service does this) and recompute the scores
appsec_discovery.apply_hit_statuses(objects, {hit.key(obj.hash): "match"})
```

`scan(source, config=None, *, ai=None, only_scored=False, project=None, llm_backend=None)` returns a `ScanResult`
(`objects`, `errors`, `parsers`); parser failures do not raise. `project` scopes the rules with a `project` /
`projects` glob; `llm_backend` runs the LLM rules on an injected `LlmBackend` (tests, the service's external
executor). `load_config`, `load_config_file`, `run_parsers`, `ScanPipeline`, `AiScorer`, `REPORT_FORMATS` are
exported too. `appsec_discovery.affected_parsers(changed_paths, parser_names)` and `parser_file_patterns()`
(core 1.1.0) tell which parsers a set of changed files can affect (`Parser.file_patterns`); the service's
[diff-based scan skip](../service/scanning.md#diff-based-scan-skip) uses them.

Errors: `ConfigError` (bad config), `UnknownParserError`, `SemgrepError`, all subclasses of
`AppsecDiscoveryError`; the CLI maps them to the exit codes above.
