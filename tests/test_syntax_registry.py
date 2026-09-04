"""
The LDAP-syntax registry in sambautils.

FIXED 2026-09-04. This registry used to be built via
getattr(ldb, 'SYNTAX_X', 1), on the theory that python3-ldb might not
export every constant on every Samba version. In practice it never
exports SYNTAX_LARGE_INTEGER, SYNTAX_OBJECT_IDENTIFIER or
SYNTAX_GENERALIZED_TIME -- confirmed live, 2026-09-04 -- so all three
fell back to the same value and collided in OID_SCHEMA_SYNTAX_DICT.

That collision was not academic: objectClass's real LDAP syntax is
Object Identifier, objectClass is in Get-ADObject's default property
set, and a live capture showed the collision rendering
<addata:objectClass LdapSyntax="1.3.6.1.4.1.1466.115.121.1.15"> on
every object in the response -- a value the AD PowerShell client's WCF
deserializer does not recognise. That is a confirmed, reproduced cause
of Get-ADObject returning ADServerDownException against a live DC: the
proxy sent a response every time, the client silently rejected it,
retried identically, and gave up.

The fix hardcodes all nine syntax OIDs as literals in sambautils.py --
they are RFC 4517 (and one MS-ADTS) protocol constants, not Samba
implementation details, so there is no reason to source them from the
`ldb` module at all. sambautils.py no longer touches ldb.SYNTAX_* for
anything. tests/stubs/ldb.py's own SYNTAX_* constants remain, but only
as fixture-authoring convenience values for these tests -- they are not
load-bearing for production correctness any more, unlike before this
fix. See tests/test_stub_fidelity.py for what still depends on the
real ldb module's shape.
"""
import ldb


def test_registry_is_keyed_by_oid(sambautils):
    for oid, syntax in sambautils.OID_SCHEMA_SYNTAX_DICT.items():
        assert syntax.oid == oid


def test_registry_has_no_duplicate_oids(sambautils):
    """
    Regression guard for the fix: nine distinct constants must produce
    nine distinct dict entries. Before the fix this was 7 (three
    constants collided down to one).
    """
    oids = [s.oid for s in sambautils.SCHEMA_SYNTAX_LIST]
    assert len(oids) == len(set(oids)), (
        'SCHEMA_SYNTAX_LIST has colliding OIDs: %r' % oids
    )
    assert len(sambautils.OID_SCHEMA_SYNTAX_DICT) == len(oids)


def test_all_nine_syntaxes_resolve(sambautils):
    """Every declared syntax must be independently reachable by OID."""
    expected = {
        sambautils.SYNTAX_INTEGER: 'Integer',
        sambautils.SYNTAX_LARGE_INTEGER: 'LargeInteger',
        sambautils.SYNTAX_BOOLEAN: 'Boolean',
        sambautils.SYNTAX_DIRECTORY_STRING: 'UnicodeString',
        sambautils.SYNTAX_OCTET_STRING: 'OctetString',
        sambautils.SYNTAX_DN: 'DSDNString',
        sambautils.SYNTAX_UTC_TIME: 'UTCTimeString',
        sambautils.SYNTAX_GENERALIZED_TIME: 'GeneralizedTimeString',
        sambautils.SYNTAX_OBJECT_IDENTIFIER: 'ObjectIdentifier',
    }
    for oid, name in expected.items():
        assert sambautils.OID_SCHEMA_SYNTAX_DICT[oid].ldap_syntax == name


def test_object_identifier_syntax_is_correct(sambautils):
    """
    Direct regression test for the confirmed failure: objectClass's
    real syntax (Object Identifier) must resolve to the name
    'ObjectIdentifier', not collide with LargeInteger or
    GeneralizedTimeString, and not fall back to 1.
    """
    assert sambautils.SYNTAX_OBJECT_IDENTIFIER != 1
    assert sambautils.SYNTAX_OBJECT_IDENTIFIER != sambautils.SYNTAX_LARGE_INTEGER
    assert sambautils.SYNTAX_OBJECT_IDENTIFIER != sambautils.SYNTAX_GENERALIZED_TIME

    syntax = sambautils.OID_SCHEMA_SYNTAX_DICT[sambautils.SYNTAX_OBJECT_IDENTIFIER]
    assert syntax.ldap_syntax == 'ObjectIdentifier'


def test_octet_string_is_base64_typed(sambautils):
    syntax = sambautils.OID_SCHEMA_SYNTAX_DICT[sambautils.SYNTAX_OCTET_STRING]
    assert syntax.xsi_type == 'xsd:base64Binary'


def test_syntax_constants_no_longer_depend_on_ldb_module(sambautils):
    """
    The whole point of the fix: these are literal OID strings now, not
    values fished out of the `ldb` module. Deleting every SYNTAX_*
    export from tests/stubs/ldb.py should not change any of them.
    """
    for name in ('SYNTAX_INTEGER', 'SYNTAX_LARGE_INTEGER', 'SYNTAX_BOOLEAN',
                 'SYNTAX_DIRECTORY_STRING', 'SYNTAX_OCTET_STRING',
                 'SYNTAX_DN', 'SYNTAX_UTC_TIME', 'SYNTAX_GENERALIZED_TIME',
                 'SYNTAX_OBJECT_IDENTIFIER'):
        value = getattr(sambautils, name)
        assert isinstance(value, str) and value.count('.') >= 5, (
            '%s = %r does not look like a literal OID string' % (name, value)
        )


def test_unknown_attribute_fallback_uses_syntax_name(sambautils, recording):
    """
    Regression test for the second half of the fix: an attribute whose
    syntax truly cannot be resolved (not just objectClass, which is now
    fixed by registering Object Identifier -- this is a genuinely
    unknown/custom attribute) must fall back to the NAME
    'UnicodeString', not the OID string that used to be hardcoded here
    by mistake.
    """
    from tests import replay

    rec = recording()
    # No add_syntax() call, so the schema lookup returns None and
    # build_attr_list takes the fallback branch.
    msg = ldb.Message(dn='CN=x,DC=vlab,DC=test',
                      attrs={'someUnknownAttr': [b'value']})

    with replay.using(rec):
        helper = sambautils.SamDBHelper()
        attrs = helper.build_attr_list(msg, attr_names=['someUnknownAttr'])

    assert attrs[0].ldap_syntax == 'UnicodeString'
