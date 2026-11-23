---
hide:
  - footer
---

# Parsers

`parsers: [all]` (the default; `PARSERS=all` in the service) runs every parser below except the deprecated ones.
Parsers based on Semgrep run the engine with the bundled `scanner_rules/*.yaml`; the others have their own file
scanners. Files are read only inside the scanned folder (symlinks pointing out of it, FIFOs and devices are
skipped), up to 5 MB (Terraform and specs 10 MB); non-UTF-8 files are decoded with replacement.

| parser | reads (`file_patterns`) | objects |
|---|---|---|
| `swagger` | `*.yaml` / `*.yml` / `*.json`: OpenAPI 3.x and Swagger 2.0 (2.0, e.g. protoc-gen-openapiv2 / grpc-gateway output, is converted to 3.0); a file counts when its top-level key is `openapi` / `swagger` and it has `paths` | `route` `<METHOD> <path>` per operation: `<in>.param.<name>`, `input.*` (request body, 2.0 `body` / `formData`), `output.*` (the first response defining a field); recursive schemas are cut at the self reference, remote `$ref` are not fetched, a broken spec / operation is skipped with a warning |
| `protobuf` | `*.proto` | `rpc` `/<package>.<Service>/<Method>`: request / response messages with nested messages, oneofs and maps (at most 2000 fields per request / response) |
| `graphql` | `*.graphql` / `*.gql` schemas (graphql-core) | `query` / `mutation` / `subscription` `<Type>.<field>`: an operation of a root type (the roots declared in `schema { ... }`, else `Query` / `Mutation` / `Subscription`; a business `type Subscription` used as a field type is an entity): args by name (`id`, `card.number`), result type up to 5 levels as `output.*`; fields of `extend type` are operations. The files of a directory are one schema, a directory joins its parent's schema unless both define a type of the same name (two services of a monorepo are two schemas) |
| `javascript` | `gql` tagged templates in `*.js` / `*.jsx` / `*.ts` / `*.tsx` / `*.mjs` / `*.cjs` (graphql-core) | `query` / `mutation` / `subscription` `<Operation>.<field>`: a resolver call of a client operation: arguments (typed from the operation variables) as `input.*`, the requested selection with fragments (from any file) as `output.*` |
| `migrations` | `*.sql`: PostgreSQL migrations - goose / sql-migrate (Up part), golang-migrate `*.up.sql`, numbered `.sql` files | `table` `<schema>.<table>` of the final schema of a migrations directory (statements replayed in version order: CREATE / ALTER / DROP / RENAME, partitions folded into their parent), one field per column |
| `terraform` | `*.tf`, `*.tf.json` (own HCL scanner; `.terraform/` skipped) | `resource`, `data`, `module`, `variable`, `output`, `provider` blocks named by their address (`aws_s3_bucket.logs`, `x`): attributes as fields (nested blocks as `block.attr`), the value kind as the type (string / number / bool / list / map / reference / expression); modules with `vm_*` attributes are the `vm` objects of earlier versions. Secret attributes (`password` / `token` / `key`..., `sensitive = true`, PEM / token-like values) never become samples: they are listed in the `sensitive_fields` property |
| `java` | `*.java` (own source scanner + the Semgrep `@Table` / `@Column` rule; test sources, `build/`, `target/`, generated dirs skipped) | `dto` `<Class>` (`@Table(name)` classes), `entity` `<Outer.Inner>` (JPA `@Entity` / `@Table` / `@MappedSuperclass` / `@Embeddable`, javax / jakarta / spring-data / hibernate, JDBI `@ColumnName`: fields named by their column), `dto` `<Outer.Inner>` (records, Lombok `@Data` / `@Value` / `@Builder`, Jackson, Gson, `@Schema` classes: Java field names). Add `entity` to `object_types` filters that list types |
| `golang` | `*.go` (Semgrep; files up to 5 MB, generated `*.pb.go` included) | `dto` `<Name>`: struct fields of basic types (`type X struct`, grouped `type ( ... )`, generic structs, `A, B T`; fields of anonymous nested structs as `Outer.Inner.Field`) |
| `python` | `*.py` / `*.pyi` (Semgrep) | `dto`: pydantic / dataclass (`@dataclass(...)` too) / sqlalchemy / django / mongo / marshmallow models (fields with defaults included); `route` `<METHOD> <path> (<handler>)`: fastapi / flask / django / bottle / starlette routes |
| `client`, `db` | nothing | deprecated: find nothing, not part of `all`, accepted in an explicit list with a warning for one release |

`migrations`: each migrations directory is its own schema. ClickHouse DDL, `test(s)` / `testdata` / `fixtures` /
`seeds` / `datafixes` directories are skipped, and next to migration histories so are schema dumps
(`structure.sql`). DDL built at run time (`EXECUTE '...'` in `DO` blocks) and the columns of
`CREATE TABLE ... AS SELECT` are not known.

The `file_patterns` are also what the service's [diff-based scan skip](../service/scanning.md#diff-based-scan-skip)
compares the changed files of a commit against (`appsec_discovery.affected_parsers`).

## Comments and samples

Objects get a `comment` and fields a `comment` and `samples` taken from the code (omitted when the code has none;
a comment is cut at 1000 characters, at most 5 samples of 200 characters):

| parser | comment | samples |
|---|---|---|
| `protobuf` | `//` / `/* */` above the rpc / field or at the end of its line | values of enum fields |
| `graphql` | descriptions (`"..."`) and `#` comments | defaults, values of enum types |
| `javascript` | the JS comment above the `gql` template, `#` comments in it | literal arguments, variable defaults |
| `migrations` | `--` above `CREATE TABLE` / a column or after it, `COMMENT ON` | `DEFAULT`, `CHECK (col IN (...))` |
| `swagger` | summary / description, property / parameter description | `example(s)`, `x-example`, `enum`, `default` |
| `golang`, `java`, `python`, `terraform` | comments / javadoc / docstrings above the struct, class, field, route, module | `example` / `enums` / `default` tags, `@Schema(example)`, `allowableValues`, pydantic `Field(example=...)` and literal defaults |

Secrets never become samples, whatever the parser (see [Objects, hits and scoring](../scoring.md)). Comments and
samples are shown next to the fields in the LLM prompts, in the UI and over MCP (`get_object`,
`list_objects(comment=...)`), and are accepted by `POST /ingest` (send masked or synthetic samples).

## Examples

### Swagger

```yaml
openapi: 3.0.3
paths:
  /user/login:
    get:
      summary: Logs user into the system
      parameters:
        - name: username
          in: query
          schema: {type: string}
        - name: password
          in: query
          description: The password for login in clear text
          schema: {type: string}
      responses:
        '200':
          content:
            application/json:
              schema: {type: string}
```

```yaml
appsec-discovery --source tests/swagger_samples

- object_name: GET /user/login
  object_type: route
  parser: swagger
  severity: high
  tags: [auth]
  file: swagger.yaml
  comment: Logs user into the system
  properties:
    path: {prop_name: path, prop_value: /user/login, severity: medium, tags: [auth]}
    method: {prop_name: method, prop_value: GET}
  fields:
    query.param.username: {field_name: query.param.username, field_type: string, severity: medium, tags: [auth]}
    query.param.password: {field_name: query.param.password, field_type: string, severity: high, tags: [auth],
                           comment: The password for login in clear text}
    output: {field_name: output, field_type: string}
```

### Protobuf

```protobuf
package com.example.grpc;

service SumService {
  rpc Sum(SumInput) returns (SumOutput) {}
}
message SumInput { int32 n1 = 1; int32 n2 = 2; }
message SumOutput { int32 result = 1; }
```

```yaml
- object_name: /com.example.grpc.SumService/Sum
  object_type: rpc
  parser: protobuf
  fields:
    input.SumInput.n1: {field_name: SumInput.n1, field_type: int32}
    input.SumInput.n2: {field_name: SumInput.n2, field_type: int32}
    output.SumOutput.result: {field_name: SumOutput.result, field_type: int32}
```

### GraphQL

```graphql
type MgmQueries
extend type Query { mgm: MgmQueries! }
extend type MgmQueries {
    promoterInfo(input: MgmPromoterInfoInput!): MgmPromoterInfoPayload!
}
input MgmPromoterInfoInput { link: String! }
type MgmPromoterInfoPayload { firstName: String!  lastName: String! }
```

```yaml
- object_name: MgmQueries.promoterInfo
  object_type: query
  parser: graphql
  severity: high
  tags: [pii]
  fields:
    input.MgmPromoterInfoInput.link: {field_name: input.MgmPromoterInfoInput.link, field_type: String}
    output.MgmPromoterInfoPayload.firstName: {field_name: output.MgmPromoterInfoPayload.firstName, field_type: String,
                                              severity: high, tags: [pii]}
    output.MgmPromoterInfoPayload.lastName: {field_name: output.MgmPromoterInfoPayload.lastName, field_type: String,
                                             severity: high, tags: [pii]}
```

### SQL migrations

```sql
-- 0001_clients.sql
CREATE TABLE public.clients (
    id bigserial PRIMARY KEY,
    last_name varchar(100) NOT NULL,   -- as in the passport
    phone varchar(20),
    status text DEFAULT 'active' CHECK (status IN ('active', 'blocked'))
);
-- 0002_clients_email.sql
ALTER TABLE public.clients ADD COLUMN email varchar(200);
```

```yaml
- object_name: public.clients
  object_type: table
  parser: migrations
  severity: high
  tags: [pii, auth]
  fields:
    id: {field_name: id, field_type: bigserial}
    last_name: {field_name: last_name, field_type: varchar(100), comment: as in the passport, severity: high, tags: [pii]}
    phone: {field_name: phone, field_type: varchar(20), severity: high, tags: [pii, auth]}
    status: {field_name: status, field_type: text, samples: [active, blocked]}
    email: {field_name: email, field_type: varchar(200), severity: medium, tags: [pii, auth]}
```

The sample folders under `tests/*_samples` hold inputs for every parser.
