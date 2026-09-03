"""
Attribute-level rendering: LdapAttr and SyntheticAttr.

These are the smallest units in the response path and need no directory
data, so they run without a Recording installed.
"""
import pytest
from lxml import etree

NSMAP = {
    'addata': 'http://schemas.microsoft.com/2008/1/ActiveDirectory/Data',
    'ad': 'http://schemas.microsoft.com/2008/1/ActiveDirectory',
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
    'xsd': 'http://www.w3.org/2001/XMLSchema',
}

# to_xml() emits a bare fragment with undeclared prefixes; wrap it before
# handing it to a parser.
WRAPPER = (
    '<root xmlns:addata="%(addata)s" xmlns:ad="%(ad)s" '
    'xmlns:xsi="%(xsi)s" xmlns:xsd="%(xsd)s">%%s</root>' % NSMAP
)


def parse_fragment(fragment):
    return etree.fromstring(WRAPPER % fragment)


def test_string_value_renders_as_text(sambautils):
    attr = sambautils.LdapAttr('cn', [b'alice'], 'UnicodeString')
    root = parse_fragment(attr.to_xml())

    value = root.find('addata:cn/ad:value', NSMAP)
    assert value.text == 'alice'
    assert value.get('{%s}type' % NSMAP['xsi']) == 'xsd:string'
    assert root.find('addata:cn', NSMAP).get('LdapSyntax') == 'UnicodeString'


def test_multivalued_attribute_emits_one_value_element_each(sambautils):
    attr = sambautils.LdapAttr(
        'objectClass', [b'top', b'person', b'user'], 'UnicodeString')
    root = parse_fragment(attr.to_xml())

    values = [v.text for v in root.findall('addata:objectClass/ad:value', NSMAP)]
    assert values == ['top', 'person', 'user']


def test_undecodable_bytes_are_base64_and_retyped(sambautils):
    """
    A binary objectSid must be base64-encoded AND have its xsi:type
    switched, or Windows reads the base64 as literal text.
    """
    raw = b'\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xff\xfe'
    attr = sambautils.LdapAttr('objectSid', [raw], 'OctetString')
    root = parse_fragment(attr.to_xml())

    value = root.find('addata:objectSid/ad:value', NSMAP)
    assert value.get('{%s}type' % NSMAP['xsi']) == 'xsd:base64Binary'

    from base64 import b64decode
    assert b64decode(value.text) == raw


def test_xml_illegal_control_char_is_base64(sambautils):
    """
    Regression guard for sambautils change log v1.1.1: \\x01 is valid
    UTF-8 but illegal in XML 1.0, and used to crash Get-ADGroup.
    """
    raw = 'group\x01name'.encode('utf-8')
    attr = sambautils.LdapAttr('sAMAccountName', [raw], 'UnicodeString')

    # Must parse at all -- this is the crash the fix prevented.
    root = parse_fragment(attr.to_xml())

    value = root.find('addata:sAMAccountName/ad:value', NSMAP)
    assert value.get('{%s}type' % NSMAP['xsi']) == 'xsd:base64Binary'


def test_message_element_is_not_a_list(sambautils):
    """
    LdapAttr must cope with LDB's read-only C sequence type, not just
    plain lists (sambautils change log v1.1.8 was caused by assuming
    mutability elsewhere in the same area).
    """
    import ldb
    element = ldb.MessageElement([b'one', b'two'], name='cn')
    assert not isinstance(element, list)

    attr = sambautils.LdapAttr('cn', element, 'UnicodeString')
    root = parse_fragment(attr.to_xml())
    assert [v.text for v in root.findall('addata:cn/ad:value', NSMAP)] == \
        ['one', 'two']


def test_synthetic_attr_rejects_unknown_names(sambautils):
    with pytest.raises(AssertionError):
        sambautils.SyntheticAttr('notARealSyntheticAttr', ['x'])


def test_synthetic_attr_uses_ad_namespace(sambautils):
    attr = sambautils.SyntheticAttr(
        'distinguishedName', ['CN=alice,DC=vlab,DC=test'])
    root = parse_fragment(attr.to_xml())

    assert root.find('ad:distinguishedName/ad:value', NSMAP).text == \
        'CN=alice,DC=vlab,DC=test'


# ========================================================================== #
# Known defect                                                               #
# ========================================================================== #

@pytest.mark.xfail(
    strict=True,
    reason='LDAP_ATTR_TEMPLATE is a bare jinja2.Template, so autoescape is '
           'OFF -- only ENV-loaded .xml templates get select_autoescape. '
           'Pull.xml then applies |safe. An attribute value containing & or '
           '< therefore produces malformed XML and lxml raises in '
           'print_xml(), dropping the connection. Remove this marker when '
           'the escaping is fixed.',
)
def test_xml_metacharacters_in_value_are_escaped(sambautils):
    """
    'Research & Development' is an entirely ordinary description value.
    """
    attr = sambautils.LdapAttr(
        'description', ['Research & Development <test>'.encode('utf-8')],
        'UnicodeString')

    root = parse_fragment(attr.to_xml())
    assert root.find('addata:description/ad:value', NSMAP).text == \
        'Research & Development <test>'
