"""java parser: records, Lombok / Jackson DTOs, JPA / JDBI entities read by the native scanner,
and the fixes of the legacy ``@Table`` objects (nested classes, comments, samples, paths)."""
import shutil
from pathlib import Path

import pytest

from appsec_discovery.models import object_identity
from appsec_discovery.parsers.java.parser import JavaParser, is_excluded_path, literal_default
from appsec_discovery.parsers.java.source import JavaSource, normalize_type, unescape_java


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel.lstrip('/')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def scan(root: Path, findings=None):
    """Objects of the native scanner (plus ``findings``) by object name."""
    objects = JavaParser(source_folder=str(root)).parse_report(findings or [])
    return {obj.object_name: obj for obj in objects}


RECORD = '''package app.api;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A registered user.
 *
 * @param id the user id
 * @param tags free form labels
 */
public record UserDto(
    @JsonProperty("user_id") long id,
    /** the login */ String login, // the trailing one
    @Schema(example = "a\\"b\\u0041") String email,
    Map<String, List<Long>> tags,
    Outer.@Nullable Inner inner
) implements Serializable {
    public static final int VERSION = 1;
}
'''


def test_record_components(tmp_path):
    write(tmp_path, '/src/main/java/app/api/UserDto.java', RECORD)
    obj = scan(tmp_path)['UserDto']

    assert obj.object_type == 'dto'
    assert obj.hash == object_identity('java', '/src/main/java/app/api/UserDto.java', 'dto', 'UserDto')
    assert obj.line == 11                                   # the record declaration
    assert obj.properties['framework'].prop_value == 'record'
    assert obj.comment.startswith('A registered user.')
    assert list(obj.fields) == ['id', 'login', 'email', 'tags', 'inner']   # Java names, no static fields
    assert obj.fields['id'].field_type == 'long'
    assert obj.fields['id'].line == 12
    assert obj.fields['id'].comment == 'the user id'        # javadoc @param
    assert obj.fields['login'].comment == 'the login\nthe trailing one'
    assert obj.fields['email'].samples == ['a"bA']          # Java escapes resolved
    assert obj.fields['tags'].field_type == 'Map<String, List<Long>>'
    assert obj.fields['tags'].comment == 'free form labels'
    assert obj.fields['inner'].field_type == 'Outer.Inner'


LOMBOK = '''package app.model;

import lombok.Data;

// A customer profile
@Data
@Builder
public class Profile {
    private static final long serialVersionUID = 1L;

    private String email; // the mail
    /** Phone number */
    @Schema(
        description = "phone", // in the annotation
        example = "+7 900")
    private String phone = "+7 000";
    private int retries = 3, delay;
    private transient List<String> cache;

    public String display() { String local = ""; return local; }

    @Value
    public static class Address {
        String city;
    }

    public static class Plain {
        String ignored;
    }
}
'''


def test_lombok_class_and_nested_classes(tmp_path):
    write(tmp_path, '/src/main/java/app/model/Profile.java', LOMBOK)
    objects = scan(tmp_path)

    profile = objects['Profile']
    assert profile.line == 8
    assert profile.comment == 'A customer profile'
    assert list(profile.fields) == ['email', 'phone', 'retries', 'delay', 'cache']   # no static, no locals
    assert profile.fields['email'].comment == 'the mail'
    assert profile.fields['phone'].comment == 'Phone number\nin the annotation'
    assert profile.fields['phone'].samples == ['+7 900', '+7 000']                # example, literal default
    assert profile.fields['retries'].samples == ['3']
    assert profile.fields['delay'].samples is None
    assert profile.fields['cache'].field_type == 'List<String>'

    address = objects['Profile.Address']                 # nested: Outer.Inner
    assert address.hash == object_identity('java', '/src/main/java/app/model/Profile.java', 'dto', 'Profile.Address')
    assert list(address.fields) == ['city']
    assert 'Profile.Plain' not in objects                # not a data class itself
    assert 'city' not in profile.fields and 'ignored' not in profile.fields


JACKSON = '''package app.dto;

@JsonInclude(JsonInclude.Include.NON_NULL)
class Settings {
    private String mode;
}

class Payment {
    @JsonProperty("card_number")
    private String cardNumber;
    private String holder;
}

public class TrinoStyle {
    private final String user;

    @JsonCreator
    public TrinoStyle(@JsonProperty("user") String user) {
        this.user = user;
    }

    @JsonProperty
    public String getUser() { return user; }
}

class NotADto {
    private String state;
}
'''


def test_jackson_classes(tmp_path):
    write(tmp_path, '/src/main/java/app/dto/Jackson.java', JACKSON)
    objects = scan(tmp_path)
    assert set(objects) == {'Settings', 'Payment', 'TrinoStyle'}
    assert list(objects['Payment'].fields) == ['cardNumber', 'holder']
    assert list(objects['TrinoStyle'].fields) == ['user']


ENTITY = '''package app.db;

import jakarta.persistence.*;

/** An order. */
@Entity
public class OrderEntity {
    @Id
    private Long id;

    @Column(nullable = false)
    private String status;

    @Column(name = "total_sum")
    private BigDecimal total;

    @ManyToOne
    @JoinColumn(name = "customer_id")
    private Customer customer;

    @OneToMany(mappedBy = "order")
    private List<Item> items;

    @Transient
    private String cached;

    private transient String temp;
    private static String CONSTANT;

    private String note;
}

@Entity
class PropertyAccess {
    private String raw;

    @Id
    public Long getId() { return id; }

    @Column(name = "full_name")
    public String getFullName() { return raw; }

    public boolean isActive() { return true; }

    @Transient
    public String getComputed() { return raw; }
}

@jakarta.persistence.Table(name = "accounts")
public class Account {
    @jakarta.persistence.Column(name = "iban")
    private String iban;
}

public record JdbiRow(@ColumnName("user_id") long userId, String email) {}
'''


def test_jpa_and_jdbi_entities(tmp_path):
    write(tmp_path, '/src/main/java/app/db/Entities.java', ENTITY)
    objects = scan(tmp_path)

    order = objects['OrderEntity']
    assert order.object_type == 'entity'
    assert order.hash == object_identity('java', '/src/main/java/app/db/Entities.java', 'entity', 'OrderEntity')
    assert order.line == 7
    assert order.comment == 'An order.'
    # column name or field name; no relations to many, transient or static fields
    assert list(order.fields) == ['id', 'status', 'total_sum', 'customer_id', 'note']
    assert order.fields['total_sum'].field_type == 'BigDecimal'
    assert 'db_table' not in order.properties

    access = objects['PropertyAccess']               # @Id on a getter: property access
    assert list(access.fields) == ['id', 'full_name', 'active']

    account = objects['Account']                     # fully qualified jakarta annotations
    assert account.properties['db_table'].prop_value == 'accounts'
    assert list(account.fields) == ['iban']

    row = objects['JdbiRow']
    assert list(row.fields) == ['user_id', 'email']


NESTED_TYPES = '''package app;

public interface Api {
    record Request(String query) {}

    enum Kind { A, B; record Meta(String label) {} }

    default void run() {
        record Local(String hidden) {}
    }
}
'''


def test_types_in_interfaces_and_enums_but_not_local(tmp_path):
    write(tmp_path, '/src/main/java/app/Api.java', NESTED_TYPES)
    assert set(scan(tmp_path)) == {'Api.Request', 'Api.Kind.Meta'}


def test_test_sources_and_build_output_are_skipped(tmp_path):
    for rel in ('/src/test/java/a/UserDto.java', '/mod/src/test/java/a/UserDto.java', '/src/main/java/a/UserDtoTest.java',
                '/build/generated/a/UserDto.java', '/target/classes/a/UserDto.java',
                '/src/main/generated/a/UserDto.java'):
        write(tmp_path, rel, RECORD)
    write(tmp_path, '/src/main/java/a/target/UserDto.java', RECORD)   # a package named target is a package
    assert [obj.file for obj in scan(tmp_path).values()] == ['/src/main/java/a/target/UserDto.java']


@pytest.mark.parametrize('rel, excluded', [
    ('/src/test/java/X.java', True), ('/app/src/testFixtures/X.java', True), ('/src/main/java/XTest.java', True),
    ('/src/main/java/XIT.java', True), ('/build/X.java', True), ('/app/target/X.java', True),
    ('/src/main/java/com/test/X.java', False), ('/src/main/java/x/build/X.java', False), ('/X.java', False),
])
def test_is_excluded_path(rel, excluded):
    assert is_excluded_path(rel) is excluded


# --- legacy @Table objects ----------------------------------------------------------------------

LEGACY = '''package models;

/** Users table. */
@Entity
@Table(name = "users")
public class UserEntity {
    /** The key. */
    @Column(
        name = "user_id",
        nullable = false)
    private Long userId;

    @Column(name = "email")
    private String email; // the mail

    @Deprecated @Column(name = "pwd") @Schema(example = "s\\"ecret") String password = "x";

    @Column(nullable = false)
    private String nickname;

    @Table(name = "user_roles")
    public static class Role {
        @Column(name = "role_name")
        private String roleName;
    }
}
'''


def legacy_finding(path, field, field_line, start, end, obj='UserEntity', obj_line=6, table='"users"', type_='String'):
    return {
        'check_id': 'rules.dto-javax-data-object', 'path': path,
        'start': {'line': start, 'col': 5, 'offset': 0}, 'end': {'line': end, 'col': 5, 'offset': 0},
        'extra': {'metadata': {'parser': 'java', 'object_type': 'dto', 'framework': 'javax'},
                  'metavars': {'$OBJECT': {'abstract_content': obj, 'start': {'line': obj_line}},
                               '$DB_NAME': {'abstract_content': table, 'start': {'line': 5}},
                               '$DB_FIELD': {'abstract_content': f'"{field}"', 'start': {'line': field_line}},
                               '$TYPE': {'abstract_content': type_, 'start': {'line': end}}}},
    }


def test_legacy_objects_keep_identity_and_get_fixed_docs(tmp_path):
    path = '/models/UserEntity.java'
    write(tmp_path, path, LEGACY)
    findings = [
        legacy_finding(path, 'user_id', 9, 8, 11, type_='Long'),
        legacy_finding(path, 'email', 13, 13, 14),
        legacy_finding(path, 'pwd', 16, 16, 16),
        # what semgrep also reports: the nested class column for the outer class, and for the inner one
        legacy_finding(path, 'role_name', 23, 23, 24),
        legacy_finding(path, 'role_name', 23, 23, 24, obj='Role', obj_line=22, table='"user_roles"'),
    ]
    objects = scan(tmp_path, findings)

    user = objects['UserEntity']
    assert user.object_type == 'dto'
    assert user.hash == object_identity('java', path, 'dto', 'UserEntity')
    assert user.line == 9                                   # unchanged: the first column
    assert user.comment == 'Users table.'
    assert user.fields['user_id'].comment == 'The key.'     # above a multi-line @Column
    assert user.fields['email'].comment == 'the mail'       # trailing on the declaration line
    assert user.fields['pwd'].samples is None               # a password: never sampled (models.secrets)
    assert user.fields['nickname'].line == 19               # @Column without name: the field name
    assert 'role_name' not in user.fields                   # belongs to the nested class only

    role = objects['Role']                        # old identity: the simple name
    assert role.hash == object_identity('java', path, 'dto', 'Role')
    assert list(role.fields) == ['role_name']


def test_legacy_object_without_semgrep_has_the_same_identity(tmp_path):
    path = '/models/UserEntity.java'
    write(tmp_path, path, LEGACY)
    native = scan(tmp_path)['UserEntity']
    from_findings = scan(tmp_path, [legacy_finding(path, 'user_id', 9, 8, 11, type_='Long')])['UserEntity']
    assert (native.hash, native.line, native.properties) == (from_findings.hash, from_findings.line, from_findings.properties)


def test_legacy_findings_in_test_sources_are_dropped(tmp_path):
    path = '/src/test/java/models/UserEntity.java'
    write(tmp_path, path, LEGACY)
    assert scan(tmp_path, [legacy_finding(path, 'email', 13, 13, 14)]) == {}


def test_legacy_docs_without_structure(tmp_path, monkeypatch):
    """Fallback when the scanner has no structure for the file: the comment above the first
    annotation of the match, the trailing one of the declaration line, samples that stop at a
    line that ends a declaration."""
    path = '/models/Fallback.java'
    write(tmp_path, path, '''class X {
    @Schema(example = "not mine") @Column(name = "a") String a;
    // the b
    @Schema(example = "b\\\\1")
    @Column(
        name = "b")
    String b; // trailing b
}
''')
    monkeypatch.setattr(JavaParser, 'java_source', lambda self, p: None)
    monkeypatch.setattr(JavaParser, 'collect_extra', lambda self, c: None)
    [obj] = JavaParser(source_folder=str(tmp_path)).parse_report(
        [legacy_finding(path, 'b', 6, 4, 7, obj='X', obj_line=1)])
    assert obj.fields['b'].comment == 'the b\ntrailing b'
    assert obj.fields['b'].samples == ['b\\1']


@pytest.mark.semgrep
def test_legacy_live_semgrep_nested_table(tmp_path):
    if not shutil.which('semgrep'):
        pytest.skip('semgrep not installed')
    write(tmp_path, '/models/UserEntity.java', LEGACY)
    objects = {obj.object_name: obj for obj in JavaParser(source_folder=str(tmp_path)).run_scan()}
    assert set(objects) == {'UserEntity', 'Role'}
    assert set(objects['UserEntity'].fields) == {'user_id', 'email', 'pwd', 'nickname'}
    assert objects['UserEntity'].fields['user_id'].field_type == 'Long'
    assert objects['UserEntity'].line == 9


# --- helpers ------------------------------------------------------------------------------------

def test_unescape_java():
    assert unescape_java(r'a\"b\\c\n\tA\101') == 'a"b\\c\n\tAA'


def test_normalize_type():
    assert normalize_type('Map< String ,List<@NotNull Long> >') == 'Map<String, List<Long>>'
    assert normalize_type('java.util . List<? extends  Foo>[]') == 'java.util.List<? extends Foo>[]'


@pytest.mark.parametrize('init, value', [
    ('"x\\"y"', 'x"y'), ('42', '42'), ('10L', '10'), ('1_000', '1000'), ('0.5f', '0.5'), ('0xFF', '0xFF'),
    ('null', None), ('true', None), ('List.of()', None), ('"a" + B', None), (None, None),
])
def test_literal_default(init, value):
    assert literal_default(init) == value


def test_scanner_survives_broken_code():
    source = JavaSource('class A { @Column(name = "x" String broken; record R(int a, ) { } class B { int c; ')
    assert [t.qualname for t in source.all_types][:1] == ['A']
