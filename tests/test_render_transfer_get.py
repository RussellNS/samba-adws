"""
render_transfer_get() -- the WS-Transfer Get path (Identity lookups).

Also covers render_root_dse_xml(), which shares the same request action.
"""
import ldb
import pytest
from lxml import etree

from tests import replay

NSMAP = {
    's': 'http://www.w3.org/2003/05/soap-envelope',
    'a': 'http://www.w3.org/2005/08/addressing',
    'da': 'http://schemas.microsoft.com/2006/11/IdentityManagement/'
          'DirectoryAccess',
    'addata': 'http://schemas.microsoft.com/2008/1/ActiveDirectory/Data',
    'ad': 'http://schemas.microsoft.com/2008/1/ActiveDirectory',
}

DOMAIN_DN = 'DC=vlab,DC=test'
GUID_REF = '<GUID=07a4e8b1-3f2c-4d5e-9a6b-1c2d3e4f5a6b>'

SYNTAXES = {
    'sAMAccountName': ldb.SYNTAX_DIRECTORY_STRING,
    'cn': ldb.SYNTAX_DIRECTORY_STRING,
    'description': ldb.SYNTAX_DIRECTORY_STRING,
    'objectClass': ldb.SYNTAX_DIRECTORY_STRING,
    'member': ldb.SYNTAX_DN,
}


def base_context(**overrides):
    context = {
        'MessageID': 'urn:uuid:aaaabbbb-cccc-dddd-eeee-ffff00001111',
        'objectReferenceProperty': GUID_REF,
        'Action': 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Get',
        'To': 'net.tcp://dc1.vlab.test:9389/ActiveDirectoryWebServices'
              '/Windows/Resource',
        'AttributeType_List': ['addata:sAMAccountName', 'addata:cn'],
    }
    context.update(overrides)
    return context


def render(sambautils, rec, context):
    with replay.using(rec):
        helper = sambautils.SamDBHelper()
        return helper.render_transfer_get(**context)


def parse(xml):
    return etree.fromstring(xml.encode('utf-8'))


def partial_attribute_names(root):
    return [
        etree.QName(child).localname
        for pa in root.findall('.//da:PartialAttribute', NSMAP)
        for child in pa
    ]


def test_requested_attributes_are_returned(sambautils, recording):
    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [('CN=alice,CN=Users,' + DOMAIN_DN, {
            'sAMAccountName': [b'alice'], 'cn': [b'alice']})],
        base=GUID_REF, attrs=['sAMAccountName', 'cn'],
    )

    root = parse(render(sambautils, rec, base_context()))
    assert partial_attribute_names(root) == ['sAMAccountName', 'cn']


def test_guid_reference_is_passed_to_ldb_as_search_base(
        sambautils, recording):
    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [('CN=alice,' + DOMAIN_DN, {'cn': [b'alice']})],
        base=GUID_REF, attrs=['sAMAccountName', 'cn'])

    render(sambautils, rec, base_context())
    assert rec.searches()[0]['base'] == GUID_REF


def test_ad_all_wildcard_fetches_everything(sambautils, recording):
    """change log v1.1.13 -- 'all' must not reach LDB as an attr name."""
    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [('CN=alice,' + DOMAIN_DN, {
            'sAMAccountName': [b'alice'], 'description': [b'hi']})],
        base=GUID_REF, attrs=None)

    context = base_context(
        AttributeType_List=['addata:sAMAccountName', 'ad:all'])
    root = parse(render(sambautils, rec, context))

    assert rec.searches()[0]['attrs'] is None
    assert 'description' in partial_attribute_names(root)


def test_empty_attribute_list_fetches_everything(sambautils, recording):
    """change log v1.1.14 -- an empty list must behave like the wildcard."""
    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [('CN=alice,' + DOMAIN_DN, {'cn': [b'alice']})],
        base=GUID_REF, attrs=None)

    render(sambautils, rec, base_context(AttributeType_List=[]))
    assert rec.searches()[0]['attrs'] is None


def test_dn_is_not_rendered_as_an_attribute(sambautils, recording):
    """
    'dn' appears in msg.keys() but is not an ADWS attribute; leaking it
    produces the 'Encountered attribute' client error that v1.1.13 was
    chasing.
    """
    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [('CN=alice,' + DOMAIN_DN, {'cn': [b'alice']})],
        base=GUID_REF, attrs=None)

    root = parse(render(sambautils, rec, base_context(AttributeType_List=[])))
    assert 'dn' not in partial_attribute_names(root)


# ========================================================================== #
# Root DSE                                                                   #
# ========================================================================== #

def test_root_dse_synthetic_attribute_ordering(sambautils, recording):
    """
    The ADWS protocol fixes the position of the synthetic attributes:
    objectReferenceProperty first, then the hierarchy trio last in order.
    """
    rec = recording()
    rec.add_search(
        [('', {
            'defaultNamingContext': [DOMAIN_DN.encode()],
            'dnsHostName': [b'dc1.vlab.test'],
        })],
        base='', scope=ldb.SCOPE_BASE,
    )

    context = base_context(
        objectReferenceProperty=sambautils.ROOT_DSE_GUID,
        AttributeType_List=[])

    with replay.using(rec):
        helper = sambautils.SamDBHelper()
        xml = helper.render_root_dse_xml(**context)

    root = parse(xml)
    top = root.find('.//addata:top', NSMAP)
    names = [etree.QName(e).localname for e in top]

    assert names[0] == 'objectReferenceProperty'
    assert names[-3:] == [
        'container-hierarchy-parent',
        'relativeDistinguishedName',
        'distinguishedName',
    ]


def test_is_root_dse_matches_sentinel_guid(sambautils):
    assert sambautils.is_rootDSE(sambautils.ROOT_DSE_GUID)
    assert sambautils.is_rootDSE('  %s  ' % sambautils.ROOT_DSE_GUID)
    assert not sambautils.is_rootDSE(GUID_REF)


# ========================================================================== #
# extendedAttributeInfo                                                      #
# ========================================================================== #
# Regression coverage for the fix confirmed live, 2026-09-04: Samba's LDB
# already computes this attribute correctly and live (1499 real entries
# on the test domain's Aggregate schema object, confirmed via a captured
# search()). A prior version of transfer-Get.xml discarded that real data
# and substituted a static 1472-entry dump captured from an unrelated
# environment in 2018, leaving attributeTypes (live) and
# extendedAttributeInfo (stale) internally inconsistent in the same
# response. render_transfer_get() now needs no special case at all:
# extendedAttributeInfo is an ordinary multi-valued UnicodeString
# attribute like any other, once nothing intercepts it.

def test_extended_attribute_info_renders_the_real_ldb_value(
        sambautils, recording):
    rec = recording().add_syntax({
        'extendedAttributeInfo': sambautils.SYNTAX_DIRECTORY_STRING,
        'attributeTypes': sambautils.SYNTAX_DIRECTORY_STRING,
    })
    live_value = (
        "( 1.2.840.113556.1.4.1693 NAME 'msFRS-Hub-Member' "
        "PROPERTY-GUID '81FF4356B635A94C9512BAF0BD0A2772' "
        "PROPERTY-SET-GUID '00000000000000000000000000000000' )"
    )
    rec.add_search(
        [('CN=Aggregate,CN=Schema,CN=Configuration,' + DOMAIN_DN, {
            'extendedAttributeInfo': [live_value.encode('utf-8')],
        })],
        base='CN=Aggregate,CN=Schema,CN=Configuration,' + DOMAIN_DN,
        attrs=['extendedAttributeInfo'],
    )

    context = base_context(
        objectReferenceProperty=(
            'CN=Aggregate,CN=Schema,CN=Configuration,' + DOMAIN_DN),
        AttributeType_List=['addata:extendedAttributeInfo'])
    root = parse(render(sambautils, rec, context))

    value_elem = root.find(
        './/addata:extendedAttributeInfo/ad:value', NSMAP)
    assert value_elem is not None, (
        'extendedAttributeInfo did not render at all')
    assert value_elem.text == live_value


def test_extended_attribute_info_template_file_is_gone():
    """
    The static 2018 dump must not come back. If this ever needs to
    change, it should be a deliberate, reviewed decision, not a merge
    that silently resurrects the file.
    """
    from os.path import dirname, join, exists

    templates_dir = join(dirname(dirname(__file__)), 'adws', 'templates')
    assert not exists(join(templates_dir, 'extendedAttr.xml'))


# ========================================================================== #
# Attribute value range retrieval                                            #
# ========================================================================== #
# [MS-ADDM] 2.7: a client can ask for only part of a large multivalued
# attribute via RangeLow/RangeHigh XML attributes on the request's
# da:AttributeType element, and the server marks a partial response the
# same way on the response element. This module's own budget logic can
# also decide unilaterally to return only part of an attribute the
# client did not range at all, confirmed live 2026-09-05 as the actual
# blocker behind a 923KB WS-Transfer Get response the AD PowerShell
# client silently rejected.

def _count_values_measurer(xml):
    return xml.count('<ad:value')


def test_client_requested_bounded_range_is_honoured_exactly(
        sambautils, recording):
    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [(GUID_REF, {
            'member': [('CN=user%d,%s' % (i, DOMAIN_DN)).encode()
                       for i in range(10)],
        })],
        base=GUID_REF, attrs=['member'],
    )

    context = base_context(
        AttributeType_List=['addata:member'],
        AttributeRanges={'member': ('2', '3')})
    root = parse(render(sambautils, rec, context))

    member_elem = root.find('.//addata:member', NSMAP)
    assert member_elem.get('RangeLow') == '2'
    assert member_elem.get('RangeHigh') == '3'
    values = [v.text for v in member_elem.findall('ad:value', NSMAP)]
    assert values == ['CN=user2,%s' % DOMAIN_DN, 'CN=user3,%s' % DOMAIN_DN]


def test_open_ended_range_resolves_to_the_true_last_index(
        sambautils, recording):
    """RangeHigh='*' means 'everything from RangeLow onward'."""
    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [(GUID_REF, {
            'member': [('CN=user%d,%s' % (i, DOMAIN_DN)).encode()
                       for i in range(5)],
        })],
        base=GUID_REF, attrs=['member'],
    )

    context = base_context(
        AttributeType_List=['addata:member'],
        AttributeRanges={'member': ('2', '*')})
    root = parse(render(sambautils, rec, context))

    member_elem = root.find('.//addata:member', NSMAP)
    assert member_elem.get('RangeLow') == '2'
    assert member_elem.get('RangeHigh') == '4'
    assert len(member_elem.findall('ad:value', NSMAP)) == 3


def test_unranged_oversized_attribute_is_shrunk_by_the_server(
        sambautils, recording, monkeypatch):
    """
    The confirmed live scenario: the client's FIRST request for this
    object carries no range at all, and the full attribute would make
    the response too large. The server ranges it unilaterally.
    """
    monkeypatch.setattr(sambautils, 'WCF_RESPONSE_SIZE_BUDGET_BYTES', 2)
    monkeypatch.setattr(sambautils, 'WCF_RESPONSE_SIZE_CHECK_EVERY', 1)

    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [(GUID_REF, {
            'member': [('CN=user%d,%s' % (i, DOMAIN_DN)).encode()
                       for i in range(5)],
        })],
        base=GUID_REF, attrs=['member'],
    )

    context = base_context(
        AttributeType_List=['addata:member'],
        measure_wcf_size=_count_values_measurer)
    root = parse(render(sambautils, rec, context))

    member_elem = root.find('.//addata:member', NSMAP)
    assert member_elem.get('RangeLow') == '0'
    assert member_elem.get('RangeHigh') == '0', (
        'budget of 2 values total, and this object has no other '
        'attributes, so member alone must be cut to a single value'
    )


def test_client_open_ended_continuation_can_still_be_shrunk(
        sambautils, recording, monkeypatch):
    """
    The client's follow-up request for 'whatever is left' (RangeHigh
    absent or '*') is documented as still subject to server limits,
    unlike an explicitly bounded request. If the remainder is itself
    still too large, the server ranges it again.
    """
    monkeypatch.setattr(sambautils, 'WCF_RESPONSE_SIZE_BUDGET_BYTES', 2)
    monkeypatch.setattr(sambautils, 'WCF_RESPONSE_SIZE_CHECK_EVERY', 1)

    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [(GUID_REF, {
            'member': [('CN=user%d,%s' % (i, DOMAIN_DN)).encode()
                       for i in range(10)],
        })],
        base=GUID_REF, attrs=['member'],
    )

    # Continuing a previous fetch that already delivered values 0-4.
    context = base_context(
        AttributeType_List=['addata:member'],
        AttributeRanges={'member': ('5', '*')},
        measure_wcf_size=_count_values_measurer)
    root = parse(render(sambautils, rec, context))

    member_elem = root.find('.//addata:member', NSMAP)
    assert member_elem.get('RangeLow') == '5'
    assert member_elem.get('RangeHigh') == '5', (
        'the open-ended continuation itself had 5 values left (5-9), '
        'still over budget, so it must be shrunk again rather than '
        'sent whole because the client already supplied a range'
    )


def test_client_bounded_range_is_not_shrunk_even_if_still_oversized(
        sambautils, recording, monkeypatch):
    """
    An explicitly bounded request (numeric RangeHigh, not '*') is
    honoured exactly per [MS-ADDM] 2.7.1, even if that exact range is
    what makes the response too large -- only open-ended requests and
    unranged attributes are eligible for further server shrinking.
    """
    monkeypatch.setattr(sambautils, 'WCF_RESPONSE_SIZE_BUDGET_BYTES', 2)
    monkeypatch.setattr(sambautils, 'WCF_RESPONSE_SIZE_CHECK_EVERY', 1)

    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [(GUID_REF, {
            'member': [('CN=user%d,%s' % (i, DOMAIN_DN)).encode()
                       for i in range(10)],
        })],
        base=GUID_REF, attrs=['member'],
    )

    context = base_context(
        AttributeType_List=['addata:member'],
        AttributeRanges={'member': ('0', '4')},  # explicit, bounded
        measure_wcf_size=_count_values_measurer)
    root = parse(render(sambautils, rec, context))

    member_elem = root.find('.//addata:member', NSMAP)
    assert member_elem.get('RangeHigh') == '4', (
        'the client asked for exactly 0-4; that must be honoured even '
        'though 5 values still exceeds the tiny test budget'
    )
    assert len(member_elem.findall('ad:value', NSMAP)) == 5


def test_small_attribute_is_never_given_a_range(sambautils, recording,
                                                 monkeypatch):
    """
    An attribute with too few values to matter for the size budget
    must never gain RangeLow/RangeHigh -- doing so would mark a
    complete attribute as partial, which [MS-ADDM] 2.3.3 reserves for
    a genuinely incomplete one.
    """
    monkeypatch.setattr(sambautils, 'WCF_RESPONSE_SIZE_BUDGET_BYTES', 2)
    monkeypatch.setattr(sambautils, 'WCF_RESPONSE_SIZE_CHECK_EVERY', 10)

    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [(GUID_REF, {'member': [b'CN=user0,' + DOMAIN_DN.encode()]})],
        base=GUID_REF, attrs=['member'],
    )

    context = base_context(
        AttributeType_List=['addata:member'],
        measure_wcf_size=_count_values_measurer)
    root = parse(render(sambautils, rec, context))

    member_elem = root.find('.//addata:member', NSMAP)
    assert member_elem.get('RangeLow') is None
    assert member_elem.get('RangeHigh') is None


def test_no_measurer_means_attribute_is_never_ranged(
        sambautils, recording, monkeypatch):
    """
    Without a measurer supplied, behaviour is identical to before this
    feature existed: the full attribute renders, unranged, regardless
    of WCF_RESPONSE_SIZE_BUDGET_BYTES.
    """
    monkeypatch.setattr(sambautils, 'WCF_RESPONSE_SIZE_BUDGET_BYTES', 2)

    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [(GUID_REF, {
            'member': [('CN=user%d,%s' % (i, DOMAIN_DN)).encode()
                       for i in range(5)],
        })],
        base=GUID_REF, attrs=['member'],
    )

    context = base_context(AttributeType_List=['addata:member'])
    root = parse(render(sambautils, rec, context))

    member_elem = root.find('.//addata:member', NSMAP)
    assert member_elem.get('RangeLow') is None
    assert len(member_elem.findall('ad:value', NSMAP)) == 5


# ========================================================================== #
# Known defect                                                               #
# ========================================================================== #

@pytest.mark.xfail(
    strict=True,
    reason='render_transfer_get does result[0] with no guard, so a lookup '
           'for a nonexistent object raises IndexError out of handle() and '
           'drops the TCP connection. PowerShell reports ADServerDown '
           'instead of ADIdentityNotFound. Fix in the fault-handling phase.',
)
def test_missing_object_does_not_raise_indexerror(sambautils, recording):
    rec = recording().add_syntax(SYNTAXES)
    rec.add_search([], base=GUID_REF, attrs=['sAMAccountName', 'cn'])

    # Should produce a fault response, not explode.
    render(sambautils, rec, base_context())
