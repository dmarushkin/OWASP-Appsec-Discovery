"""Native terraform parser: blocks -> objects, fields, comments, samples, secrets, vm compatibility."""
import json
import os
import time
from pathlib import Path

from appsec_discovery.models import object_identity
from appsec_discovery.parsers import ParserFactory
from appsec_discovery.parsers.terraform import hcl
from appsec_discovery.parsers.terraform.parser import TerraformParser

SAMPLES = os.path.join(str(Path(__file__).resolve().parent), "terraform_samples")


def scan(folder):
    return TerraformParser(parser='terraform', source_folder=str(folder)).run_scan()


def by_name(objects):
    return {obj.object_name: obj for obj in objects}


def write(folder, rel, text):
    path = Path(folder) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_parser_terraform_get_parser():
    assert ParserFactory().get_parser('terraform').__qualname__ == "TerraformParser"


def test_parser_terraform_parse_folder():
    results = scan(SAMPLES)
    vms = [obj for obj in results if obj.object_type == 'vm']

    assert len(vms) == 3
    assert vms[0].parser == 'terraform'
    assert vms[0].object_name == 'keycloak01-dc1.v.pci-prod.example.local'
    assert vms[0].properties['vm_template'].prop_value == 'ubuntu-2204'
    assert vms[-1].properties['vm_domain'].prop_value == 'v.pci-prod.example.local'
    # .terraform/ (downloaded modules) is not scanned
    assert not any(obj.file.startswith('/.terraform/') for obj in results)


def test_vm_objects_keep_the_former_identity_line_and_properties(tmp_path):
    write(tmp_path, 'main.tf', '''# Keycloak node
module "kc01" {
  source  = "git@example.com:infra/vm.git"
  vm_pool = "app"
  vm_name = "kc01"
  vm_domain = "v.example.local"
  vm_cpu_cores = 4
  nested {
    vm_desc = "inner"
  }
}

module "label" {
  vm_template = "ubuntu"
  vm_name     = "other-name"
}

module "only_name" {
  vm_name = "different"
}

module "plain" {
  source = "./modules/x"
}
''')
    objects = by_name(scan(tmp_path))

    vm = objects['kc01.v.example.local']
    assert vm.object_type == 'vm'
    assert vm.hash == object_identity('terraform', '/main.tf', 'vm', 'kc01')
    assert vm.line == 5                                     # the vm_name line
    assert vm.comment == 'Keycloak node'
    assert {k: v.prop_value for k, v in vm.properties.items()} == {
        'vm_name': 'kc01', 'vm_pool': 'app', 'vm_domain': 'v.example.local', 'vm_desc': 'inner'}
    assert vm.fields['vm_cpu_cores'].field_type == 'number'
    assert vm.fields['nested.vm_desc'].samples == ['inner']

    # label != vm_name: keyed, named and located as the former rules did (by the label, first vm_* line)
    label = objects['label']
    assert label.hash == object_identity('terraform', '/main.tf', 'vm', 'label')
    assert label.properties['vm_name'].prop_value == 'label'
    assert label.line == 14

    # what the former rules did not see is an ordinary module
    assert objects['only_name'].object_type == 'module'
    plain = objects['plain']
    assert plain.hash == object_identity('terraform', '/main.tf', 'module', 'plain')
    assert plain.properties['source'].prop_value == './modules/x'


def test_vm_objects_match_the_former_golden_except_fields():
    golden = json.loads((Path(__file__).resolve().parent / 'golden' / 'terraform.parsed.json').read_text())
    old = {obj['hash']: obj for obj in golden if obj['object_type'] == 'vm'}
    new = {obj.hash: obj.dict(exclude_none=True) for obj in scan(SAMPLES) if obj.object_type == 'vm'}
    assert set(old) == set(new)
    for key, obj in new.items():
        for name in ('object_name', 'line', 'file', 'properties', 'parser'):
            assert obj[name] == old[key][name]


def test_blocks_kinds_names_and_identity():
    objects = by_name(scan(SAMPLES))

    bucket = objects['aws_s3_bucket.logs']
    assert bucket.object_type == 'resource'
    assert bucket.hash == object_identity('terraform', '/network/main.tf', 'resource', 'aws_s3_bucket.logs')
    assert bucket.properties['type'].prop_value == 'aws_s3_bucket'
    assert objects['aws_ami.ubuntu'].object_type == 'data'
    module = objects['vpc']
    assert {k: module.properties[k].prop_value for k in ('source', 'version')} == {
        'source': 'terraform-aws-modules/vpc/aws', 'version': '5.1.0'}
    assert objects['aws'].object_type == 'provider'
    assert objects['aws.us'].hash == object_identity('terraform', '/network/main.tf', 'provider', 'aws.us')
    assert objects['prefix'].object_type == 'variable'
    assert objects['db_endpoint'].object_type == 'output'


def test_fields_types_nested_blocks_and_dynamic():
    objects = by_name(scan(SAMPLES))
    bucket = objects['aws_s3_bucket.logs'].fields
    db = objects['aws_db_instance.orders'].fields

    assert bucket['bucket'].field_type == 'string'
    assert bucket['force_destroy'].field_type == 'bool'
    assert bucket['tags'].field_type == 'map'
    assert bucket['lifecycle_rule.expiration.days'].field_type == 'number'
    # repeated nested blocks: one index-free field, samples merged
    assert bucket['lifecycle_rule.enabled'].samples == ['true', 'false']
    assert db['subnet_ids'].field_type == 'list'
    assert db['vpc_security_group_ids'].samples == ['sg-0123']           # only the literal items
    assert db['storage_type'].field_type == 'reference'
    assert db['name'].field_type == 'expression'                          # "${var.prefix}-orders"
    assert db['replica'].field_type == 'expression'
    # dynamic "ingress" { content { ... } } -> ingress.*
    assert db['ingress.for_each'].field_type == 'reference'
    assert db['ingress.from_port'].field_type == 'reference'             # ingress.value
    assert db['ingress.protocol'].samples == ['tcp']


def test_comments():
    objects = by_name(scan(SAMPLES))
    bucket = objects['aws_s3_bucket.logs']

    assert bucket.comment == 'Public bucket with the access logs of the shop.'   # /* */ above
    assert bucket.fields['bucket'].comment == 'the bucket name'                  # trailing #
    # a nested block's comment goes to its fields, unless the block is repeated (merged fields)
    assert bucket.fields['lifecycle_rule.expiration.days'].comment == 'keep logs for a year'
    assert bucket.fields['lifecycle_rule.enabled'].comment is None
    assert bucket.fields['acl'].comment is None
    # a variable / output: its description first, then the code comment
    assert objects['prefix'].comment == 'Name prefix\nThe prefix of every resource name'
    assert objects['db_endpoint'].comment == 'Endpoint of the orders database'
    assert objects['prefix'].fields['type'].samples == ['string']
    assert objects['ingress_ports'].fields['type'].samples == ['list(number)']


def test_secrets_are_never_sampled():
    objects = by_name(scan(SAMPLES))
    every_sample = {sample for obj in objects.values() for field in obj.fields.values() for sample in field.samples or []}

    for secret in ('Sup3rS3cret!', 'changeme', 'admin-login-value', 'do-not-sample'):
        assert secret not in every_sample
    db = objects['aws_db_instance.orders']
    assert db.fields['password'].samples is None
    assert db.fields['endpoint'].samples is None             # a URL with a password
    assert db.properties['sensitive_fields'].prop_value == 'password'
    assert objects['db_password'].properties['sensitive_fields'].prop_value == 'default'
    assert objects['admin_login'].fields['default'].samples is None     # sensitive = true
    assert objects['admin_login'].fields['sensitive'].samples == ['true']
    assert objects['vpc'].properties['sensitive_fields'].prop_value == 'api_token'


def test_secret_heuristics(tmp_path):
    write(tmp_path, 'main.tf', '''resource "x_thing" "a" {
  tls_cert      = "plain-looking"
  ssh_key       = "plain-looking"
  name          = "ro-k8s-stg-team-ticket-PROJECT-12345-and-more"
  blob          = "AbCdEfGh1234567890AbCdEfGh1234567890xyz"
  vault         = "hvs.CAESIJ0123456789abcdef"
  pem           = "-----BEGIN RSA PRIVATE KEY-----"
  credentials {
    user = "deployer"
  }
}
''')
    (obj,) = scan(tmp_path)
    samples = {name: field.samples for name, field in obj.fields.items()}
    assert samples['tls_cert'] is None and samples['ssh_key'] is None
    assert samples['credentials.user'] is None
    assert samples['name'] == ['ro-k8s-stg-team-ticket-PROJECT-12345-and-more']    # a name, not a token
    assert samples['blob'] is None and samples['vault'] is None and samples['pem'] is None


def test_secret_name_value_pairs_are_never_sampled(tmp_path):
    # k8s ``env`` / helm ``set``: the name of the pair says the value is a secret
    write(tmp_path, 'main.tf', '''resource "kubernetes_deployment" "app" {
  spec {
    container {
      env {
        name  = "DB_PASSWORD"
        value = "fake-env-pw-000"
      }
      env {
        name  = "LOG_LEVEL"
        value = "fake-after-secret"
      }
    }
  }
}
resource "helm_release" "r" {
  set {
    name  = "auth.apiKey"
    value = "fake-helm-key-000"
  }
}
resource "x_thing" "plain" {
  env {
    name  = "LOG_LEVEL"
    value = "debug"
  }
}
''')
    objects = by_name(scan(tmp_path))
    every_sample = {sample for obj in objects.values() for field in obj.fields.values() for sample in field.samples or []}
    assert not every_sample & {'fake-env-pw-000', 'fake-after-secret', 'fake-helm-key-000'}
    app = objects['kubernetes_deployment.app']
    assert app.fields['spec.container.env.name'].samples == ['DB_PASSWORD', 'LOG_LEVEL']    # names stay
    assert app.properties['sensitive_fields'].prop_value == 'spec.container.env.value'
    assert objects['helm_release.r'].properties['sensitive_fields'].prop_value == 'set.value'
    assert objects['x_thing.plain'].fields['env.value'].samples == ['debug']
    assert 'sensitive_fields' not in objects['x_thing.plain'].properties


def test_sensitive_object_default_in_tf_json_is_never_sampled(tmp_path):
    write(tmp_path, 'vars.tf.json', json.dumps({'variable': {
        'db': {'sensitive': True, 'default': {'user': 'fake-user', 'pw': 'fake-json-pw-000'}},
        'db_secret': {'default': {'host': 'fake-host', 'nested': {'x': 'fake-json-pw-001'}}},
        'plain': {'default': {'host': 'db.example.test'}},
    }}))
    objects = by_name(scan(tmp_path))
    db, db_secret = objects['db'], objects['db_secret']
    assert db.fields['default.user'].samples is None and db.fields['default.pw'].samples is None
    assert db.properties['sensitive_fields'].prop_value == 'default.pw, default.user'
    assert db_secret.fields['default.nested.x'].samples is None and db_secret.fields['default.host'].samples is None
    assert objects['plain'].fields['default.host'].samples == ['db.example.test']


def test_connection_strings_and_authorization_headers_are_never_sampled(tmp_path):
    write(tmp_path, 'main.tf', '''resource "x_thing" "a" {
  conn    = "Server=db;User Id=sa;Password=fake-pw-000"
  url     = "postgres://svc:fake-pw-001@db.example.test/app"
  headers = ["Authorization: Basic dXNlcjpmYWtl", "Accept: application/json"]
  auth    = "Bearer fake0token0value"
  plain   = "Server=db;Database=app"
}
''')
    (obj,) = scan(tmp_path)
    samples = {name: field.samples for name, field in obj.fields.items()}
    assert samples['conn'] is None and samples['url'] is None and samples['auth'] is None
    assert samples['headers'] == ['Accept: application/json']
    assert samples['plain'] == ['Server=db;Database=app']


def test_broken_files_never_break_the_scan(tmp_path):
    write(tmp_path, 'good.tf', 'resource "a_b" "ok" {\n  x = 1\n}\n')
    write(tmp_path, 'unterminated.tf', 'resource "a_b" "s" {\n  path = "/x/\n  y = 2\n}\n'
                                       'resource "a_b" "t" {\n  z = <<EOT\nnever closed\n')
    write(tmp_path, 'garbage.tf', '}}} = = "\x00 ((( [ /* never closed\nresource "a_b" "lost" {}\n')
    write(tmp_path, 'bad.tf.json', '{"resource": ')
    write(tmp_path, 'open_paren.tf', 'module "m" {\n  a = (1 +\n')
    objects = by_name(scan(tmp_path))

    assert 'a_b.ok' in objects
    assert objects['a_b.s'].fields['y'].samples == ['2']
    assert 'a_b.t' in objects
    assert 'm' in objects


def test_tf_json(tmp_path):
    write(tmp_path, 'main.tf.json', json.dumps({
        'resource': {'aws_sqs_queue': {'q': {'name': 'orders', 'tags': {'team': 'x'}, 'token': 'abc'}}},
        'module': {'m': {'source': './m', 'version': '1.0'}},
    }, indent=2))
    objects = by_name(scan(tmp_path))
    queue = objects['aws_sqs_queue.q']
    assert queue.line == 4
    assert queue.fields['name'].samples == ['orders']
    assert queue.fields['tags.team'].samples == ['x']
    assert queue.fields['token'].samples is None
    assert objects['m'].properties['version'].prop_value == '1.0'


def test_hcl_scanner_strings_heredocs_and_lines():
    blocks = hcl.parse('resource "a" "b" {\n'
                       '  s = "x ${jsonencode({ "k" = "}" })} y"\n'
                       '  h = <<-EOT\n    one\n    two\n  EOT\n'
                       '  m = {\n    a = 1\n  }\n'
                       '  e = "a\\"b"\n'
                       '  inline { x = 1 }\n'
                       '}\n')
    (block,) = blocks
    attrs = {attr.name: attr for attr in block.attributes()}
    assert hcl.classify(attrs['s'].expr).kind == 'expression'
    assert attrs['h'].line == 3 and attrs['m'].line == 7 and attrs['e'].line == 10
    assert hcl.classify(attrs['e'].expr).samples == ['a"b']
    assert block.blocks()[0].attributes()[0].line == 11


def test_large_repository_is_fast(tmp_path):
    module = 'module "vm{i}" {{\n  source = "git::x"\n  vm_name = "vm{i}"\n  vm_pool = "p"\n' + \
             ''.join(f'  attr_{n} = "value {n}" # note\n' for n in range(15)) + '}}\n\n'
    for f in range(20):
        write(tmp_path, f'd{f}/main.tf', ''.join(module.format(i=f * 100 + i) for i in range(100)))
    start = time.time()
    objects = scan(tmp_path)
    assert len(objects) == 2000
    assert time.time() - start < 20
