"""
The LDAP-syntax registry in sambautils.

sambautils wraps every ldb syntax constant in getattr(ldb, NAME, 1),
because python3-ldb does not export all of them. Any constant that falls
back collides with every other constant that falls back, since they all
become the integer 1 and OID_SCHEMA_SYNTAX_DICT is keyed by that value.

These tests pin the current behaviour so a future fix is a visible,
deliberate change rather than an accident.
"""
import pytest


def test_registry_is_keyed_by_oid(sambautils):
    for oid, syntax in sambautils.OID_SCHEMA_SYNTAX_DICT.items():
        assert syntax.oid == oid


def test_known_syntaxes_resolve(sambautils):
    """The syntaxes python3-ldb does export must round-trip cleanly."""
    import ldb
    expected = {
        ldb.SYNTAX_DIRECTORY_STRING: 'UnicodeString',
        ldb.SYNTAX_INTEGER: 'Integer',
        ldb.SYNTAX_BOOLEAN: 'Boolean',
        ldb.SYNTAX_OCTET_STRING: 'OctetString',
        ldb.SYNTAX_DN: 'DSDNString',
        ldb.SYNTAX_UTC_TIME: 'UTCTimeString',
        ldb.SYNTAX_GENERALIZED_TIME: 'GeneralizedTimeString',
    }
    for oid, name in expected.items():
        assert sambautils.OID_SCHEMA_SYNTAX_DICT[oid].ldap_syntax == name


def test_octet_string_is_base64_typed(sambautils):
    import ldb
    syntax = sambautils.OID_SCHEMA_SYNTAX_DICT[ldb.SYNTAX_OCTET_STRING]
    assert syntax.xsi_type == 'xsd:base64Binary'


def test_fallback_constants_collide(sambautils):
    """
    Documents the getattr(..., 1) collision.

    SYNTAX_LARGE_INTEGER and SYNTAX_OBJECT_IDENTIFIER both fall back to
    1, so the registry holds only the last one defined in
    SCHEMA_SYNTAX_LIST. That means LargeInteger attributes --
    pwdLastSet, lastLogonTimestamp, accountExpires, all extremely
    common under -Properties * -- are annotated as ObjectIdentifier.

    This test asserts the CURRENT (wrong) behaviour on purpose. When the
    syntax registry is fixed in the Tier 3 work, this test should fail
    and be rewritten to assert the correct mapping.
    """
    assert sambautils.SYNTAX_LARGE_INTEGER == 1
    assert sambautils.SYNTAX_OBJECT_IDENTIFIER == 1
    assert sambautils.OID_SCHEMA_SYNTAX_DICT[1].ldap_syntax == 'ObjectIdentifier'

    names = [s.ldap_syntax for s in sambautils.SCHEMA_SYNTAX_LIST]
    assert 'LargeInteger' in names, 'LargeInteger is declared...'
    assert not any(
        s.ldap_syntax == 'LargeInteger'
        for s in sambautils.OID_SCHEMA_SYNTAX_DICT.values()
    ), '...but is unreachable through the OID registry'


@pytest.mark.xfail(
    strict=True,
    reason='The build_attr_list fallback sets ldap_syntax to the literal OID '
           '1.3.6.1.4.1.1466.115.121.1.15, but every real entry uses a NAME '
           '(UnicodeString). Windows expects the name, so unknown attributes '
           'are annotated in a format the client does not understand.',
)
def test_unknown_attribute_fallback_uses_syntax_name(sambautils, recording):
    from tests import replay
    import ldb

    rec = recording()
    # No add_syntax() call, so the schema lookup returns None and
    # build_attr_list takes the fallback branch.
    msg = ldb.Message(dn='CN=x,DC=vlab,DC=test',
                      attrs={'someUnknownAttr': [b'value']})

    with replay.using(rec):
        helper = sambautils.SamDBHelper()
        attrs = helper.build_attr_list(msg, attr_names=['someUnknownAttr'])

    assert attrs[0].ldap_syntax == 'UnicodeString'
