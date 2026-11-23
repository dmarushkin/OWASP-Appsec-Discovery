---
hide:
  - footer
---

# LLM scoring in the CLI

Keyword rules only know names. An LLM rule asks a model about the object and its fields, so it finds sensitive data
without a keyword list. The CLI talks to every model through one OpenAI-compatible client (the `ai_api` section);
models never run inside the CLI process.

## 1. An endpoint

**Local model** - the official [llama.cpp server](https://github.com/ggml-org/llama.cpp/tree/master/tools/server)
with any GGUF model from Hugging Face serves an OpenAI-compatible API on `http://localhost:8080/v1`:

```bash
docker run -d --name llm -p 127.0.0.1:8080:8080 -v llm_cache:/root/.cache \
  ghcr.io/ggml-org/llama.cpp:server-b12098 -hf Qwen/Qwen2.5-3B-Instruct-GGUF:Q4_K_M
# or: docker compose -f docs/local-llm.compose.yml up -d     (LLM_HF_REPO / LLM_MODEL_FILE / LLM_MODELS_DIR)
```

The first start downloads the model into the `llm_cache` volume; later starts work offline. A GGUF file you
already have: `-v /path/to/models:/models -m /models/<file>.gguf`. Small instruct models (3B, Q4) are fast on
common hardware and good enough for this classification task; try other
[models](https://huggingface.co/models?library=gguf) and prompts.

**External API** - any OpenAI-compatible endpoint works the same way (`base_url`, `api_key`, `model`).

```yaml
ai_api:
  base_url: "http://localhost:8080/v1"   # or https://api.deepseek.com, ...
  model: "local-model"                   # llama.cpp serves its one model under any name
  # api_key: "..."                       # not needed for a local server
  # system_prompt: "You are a data security bot ..."   # the built-in classifier's prompt
  # timeout: 120                         # seconds per request
  # max_retries: 2                       # connection errors, 429 and 5xx are retried
  # max_tokens: 8192
  # structured: auto                     # auto | json_schema | json_object | none (response_format)
```

```bash
appsec-discovery --source tests/swagger_samples --config tests/config_samples/ai_conf_local_server.yaml
```

## 2. The built-in classifier

An `ai_api` section alone runs one implicit rule (`llm-default`): the **classifier**. Each object is one request:
the model gets the object name and its candidate fields (ids, dates, paging fields are skipped) and answers with
JSON `{"fields": [{"name": ..., "category": "pii|finance|auth|other"}]}`, enforced with `response_format` where
the server supports it. Every flagged field gets severity `medium` and an `llm-<category>` tag; an object whose
request fails is reported without LLM tags.

```yaml
- object_name: GET /user/login
  object_type: route
  severity: medium
  tags: [llm-pii, llm-auth]
  fields:
    Input.password:
      severity: medium
      tags: [llm-auth]
```

## 3. `llm_rules`

`llm_rules` replaces the classifier with any number of rules that all run on the `ai_api` endpoint
(`llm_rules: []` disables LLM scoring):

```yaml
llm_rules:
  - name: pci-fields
    category: pci                # hit tag llm-pci (or set tag)
    severity: high
    system_prompt: You look for payment card data (PAN, CVV, expiry) in API fields.
    prompt_version: 1            # bump on every prompt change; stored with each hit
    target: field                # field: the model picks matching candidate fields; object: judges the whole object
    mode: review                 # auto (default) | review
    object_types: [route, dto]   # optional scope: object_types, parsers, projects (globs)
  - name: person
    category: pii
    target: object
    mark_fields: true            # object rules only: the fields the model names get hits too
    tags: [personal-data]        # object tags once the hit is a match
```

* **Field rules** (`target: field`) get the object and its candidate fields and name the matching fields: one hit
  per field. A field rule without `category` and `tag` is the classifier with your `system_prompt`.
* **Object rules** (`target: object`) get the whole object (type, file, properties, every field with its type,
  comments and samples) and judge it: one hit, with the fields that make it match in `fields`. An object rule needs
  a `category` (or `tag`). The prompt can describe combinations ("match only when the object identifies a person:
  a last name together with a phone, document or birth date; a first name alone is not enough").
* **`mark_fields: true`** (object rules): the same single call also gives one field hit per named field, with the
  rule's status, tag, severity, reason and version. Field hits are ordinary field hits and are decided
  independently of the object hit.
* The model answers `match`, `no_match` or `need_more_info`; `need_more_info` hits never score and wait for triage.

The code-derived text (names, comments, samples) is sent inside a delimited `<object>` block that the prompts
declare as untrusted data, never as instructions. The core prompts are versioned (`PROMPT_VERSION` of the
classifier, `RULE_PROMPT_VERSION` of the rules, both `3`); every hit stores the rule's `prompt_version` and the
`model`.

## Migrating from `ai_local`

The in-process llama.cpp backend (`llama-cpp-python`) was removed. An `ai_local` section is a deprecated alias of
`ai_api` with `base_url: http://localhost:8080/v1` (override with `ai_local.base_url`) and `model: <model_id>`;
`model_folder` and `gguf_file` are ignored with a warning. Serve the same model with a llama.cpp server (`-hf
<model_id>`, or `-m` with your GGUF file) and switch the section to `ai_api` when convenient.
