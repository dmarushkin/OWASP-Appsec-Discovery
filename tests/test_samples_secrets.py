"""Secrets never become samples, whatever the parser (``appsec_discovery.models.secrets``),
and fields of nested classes / anonymous structs stay with their own structure.

Every value below is an obviously fake placeholder."""
from pathlib import Path

import pytest

from appsec_discovery.models import CodeObjectField
from appsec_discovery.models.code_object import clean_samples
from appsec_discovery.models.secrets import is_secret_name, looks_like_secret
from appsec_discovery.parsers.golang.parser import GolangParser
from appsec_discovery.parsers.java.parser import JavaParser
from appsec_discovery.parsers.python.parser import PythonParser, enclosing_class_line

# Fake credentials, assembled at run time so that the source holds no literal a secret scanner
# (GitHub push protection) takes for a real token.
FAKE_GITLAB_TOKEN = "glpat" + "-FakeFakeFakeFake0000"
FAKE_VAULT_TOKEN = "hvs" + ".FAKEfake0000000000000000"
FAKE_GITHUB_TOKEN = "ghp" + "_FakeFakeFakeFakeFake0000"
FAKE_SLACK_TOKEN = "xoxb" + "-0000000000-fakefakefake"


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel.lstrip('/')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def by_name(objects):
    return {obj.object_name: obj for obj in objects}


def all_samples(objects):
    return {sample for obj in objects for field in obj.fields.values() for sample in field.samples or []}


# --- the heuristics ------------------------------------------------------------------------

@pytest.mark.parametrize('name', [
    'password', 'db_password', 'DbPassword', 'DB_PASSWORD', 'passwd', 'pwd', 'db_pass', 'passphrase',
    'secret', 'client_secret', 'clientSecret', 'aws_secret_access_key', 'token', 'gitlab_token',
    'accessToken', 'refresh_token', 'x-auth-token', 'api_key', 'apiKey', 'APIKey', 'x-api-key', 'apikey',
    'private_key', 'privateKey', 'signing_key', 'credentials', 'creds', 'basic_auth', 'Authorization',
    'headers.Authorization', 'input.user.password', 'password.value', 'connection_string', 'dsn', 'cvv',
    'password_hash',
])
def test_secret_names(name):
    assert is_secret_name(name)


@pytest.mark.parametrize('name', [
    'name', 'email', 'token_type', 'tokenType', 'secret_question_id', 'secret_name', 'api_key_id',
    'password_min_length', 'password_policy', 'token_expires_in', 'max_tokens', 'total_tokens',
    'next_page_token', 'nextPageToken', 'auth_method', 'auth_type', 'author', 'authority', 'key',
    'primary_key', 'sort_key', 'passport', 'compass', 'bypass', 'spec.container.env.value', 'secret_ref',
    'output.password.policy',
])
def test_not_secret_names(name):
    assert not is_secret_name(name)


@pytest.mark.parametrize('value', [
    '-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA',
    'postgres://svc:fake-pw@db.example.test/app', 'Server=db;User Id=sa;Password=fake-pw-000',
    'host=db user=app password=fake-pw-000', 'Authorization: Basic dXNlcjpmYWtl', 'Basic dXNlcjpmYWtl',
    'Bearer fake0token0value', 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJmYWtlIn0.', 'AKIAFAKEFAKEFAKEFAKE',
    FAKE_GITLAB_TOKEN, FAKE_GITHUB_TOKEN, 'sk-fake-0000000000000000',
    FAKE_VAULT_TOKEN, FAKE_SLACK_TOKEN, 'FakeBase64Blob0000FakeBase64Blob0000xyz',
])
def test_secret_values(value):
    assert looks_like_secret(value)


@pytest.mark.parametrize('value', [
    'john@example.com', 'https://example.test/a?b=c', 'postgres://db.example.test/app', '2024-01-01T00:00:00Z',
    '550e8400-e29b-41d4-a716-446655440000', 'Basic authentication', 'Bearer token', 'active',
    'ro-k8s-stg-team-ticket-PROJECT-12345-and-more', 'task-0000000000000000', 'Server=db;Database=app',
    '978-3-16-148410-0', 'Accept: application/json',
])
def test_not_secret_values(value):
    assert not looks_like_secret(value)


# --- the model: every parser goes through it ----------------------------------------------

def test_code_object_field_drops_secret_samples():
    secret = CodeObjectField(field_name='db_password', field_type='str', samples=['fake-pw-000'])
    assert secret.samples is None
    mixed = CodeObjectField(field_name='header', field_type='str',
                            samples=['Bearer fake0token0value', 'text/plain', 'Basic dXNlcjpmYWtl'])
    assert mixed.samples == ['text/plain']
    plain = CodeObjectField(field_name='token_type', field_type='str', samples=['bearer'])
    assert plain.samples == ['bearer']


def test_assigned_samples_are_filtered_too():
    # parsers (swagger examples) set ``field.samples`` after construction
    field = CodeObjectField(field_name='input.password', field_type='string')
    field.samples = ['fake-pw-000']
    assert field.samples is None
    field = CodeObjectField(field_name='input.note', field_type='string')
    field.samples = ['ok', FAKE_GITLAB_TOKEN]
    assert field.samples == ['ok']


def test_clean_samples_without_a_name_filters_values_only():
    assert clean_samples(['fine', 'AKIAFAKEFAKEFAKEFAKE']) == ['fine']
    assert clean_samples(['fine'], 'api_key') is None


# --- parsers end to end -----------------------------------------------------------------------

PY_SETTINGS = '''from pydantic import BaseModel, Field


class Settings(BaseModel):
    gitlab_token: str = FAKE_GITLAB_TOKEN
    db_password: str = Field(default="fake-pw-000")
    aws_secret_access_key: str = "FakeBase64Blob0000FakeBase64Blob0000xyz"
    database_url: str = "postgres://svc:fake-pw-001@db.example.test/app"
    region: str = "eu-fake-1"

    class Inner(BaseModel):
        card_pan: str = "0000000000000000"

    timeout: int = 5


class Plain(BaseModel):
    name: str

    class Config:
        orm_mode = True
'''


@pytest.mark.semgrep
def test_python_secrets_and_nested_classes(tmp_path):
    write(tmp_path, '/app/settings.py', PY_SETTINGS)
    objects = PythonParser(parser='python', source_folder=str(tmp_path)).run_scan()
    found = by_name(objects)

    assert not all_samples(objects) & {FAKE_GITLAB_TOKEN, 'fake-pw-000',
                                       'FakeBase64Blob0000FakeBase64Blob0000xyz',
                                       'postgres://svc:fake-pw-001@db.example.test/app'}
    settings = found['Settings']
    assert list(settings.fields) == ['gitlab_token', 'db_password', 'aws_secret_access_key', 'database_url',
                                     'region', 'timeout']               # no card_pan of Inner
    assert settings.fields['region'].samples == ['eu-fake-1']
    assert settings.fields['timeout'].samples == ['5']
    assert list(found['Inner'].fields) == ['card_pan']
    assert list(found['Plain'].fields) == ['name']


def test_enclosing_class_line():
    lines = PY_SETTINGS.splitlines()
    assert enclosing_class_line(lines, 5) == 4          # gitlab_token -> Settings
    assert enclosing_class_line(lines, 12) == 11        # card_pan -> Inner
    assert enclosing_class_line(lines, 14) == 4         # timeout -> Settings again
    assert enclosing_class_line(lines, 1) is None


GO_CONFIG = '''package cfg

type Config struct {
	Name string `example:"svc"`
	Billing struct {
		// card number
		CardPan string
	}
	Shipping struct {
		CardPan int
	}
	Items []struct {
		Sku string `json:"sku" example:"a{b"` // { in a tag and a comment
	}
	DbPassword string `default:"fake-pw-000"`
	Endpoint string `example:"https://svc:fake-pw-001@api.example.test"`
	Last bool
}

type (
	Group struct {
		Title string
		Inner struct {
			Code string
		}
	}
	Other struct {
		Value int
	}
)
'''


@pytest.mark.semgrep
def test_golang_secrets_and_anonymous_structs(tmp_path):
    write(tmp_path, '/cfg/config.go', GO_CONFIG)
    objects = GolangParser(parser='golang', source_folder=str(tmp_path)).run_scan()
    found = by_name(objects)

    assert not all_samples(objects) & {'fake-pw-000', 'https://svc:fake-pw-001@api.example.test'}
    config = found['Config']
    assert list(config.fields) == ['Name', 'Billing.CardPan', 'Shipping.CardPan', 'Items.Sku', 'DbPassword',
                                   'Endpoint', 'Last']
    assert config.fields['Billing.CardPan'].field_type == 'string'
    assert config.fields['Billing.CardPan'].comment == 'card number'
    assert config.fields['Shipping.CardPan'].field_type == 'int'
    assert config.fields['Items.Sku'].samples == ['a{b']
    assert config.fields['Name'].samples == ['svc']
    # an anonymous struct of a grouped type is no type of its own
    assert set(found) == {'Config', 'Group', 'Other'}
    assert list(found['Group'].fields) == ['Title', 'Inner.Code']


JAVA_DTO = '''package app.api;

import lombok.Data;

@Data
public class LoginRequest {
    private String login = "fake-user";
    private String password = "fake-pw-000";
    private String apiKey = "fake-key-000";
    private String note = "Bearer fake0token0value";
}
'''


def test_java_secrets(tmp_path):
    write(tmp_path, '/app/api/LoginRequest.java', JAVA_DTO)
    objects = JavaParser(source_folder=str(tmp_path)).parse_report([])
    samples = all_samples(objects)
    assert 'fake-user' in samples                       # the parser does sample literal defaults
    assert not samples & {'fake-pw-000', 'fake-key-000', 'Bearer fake0token0value'}
