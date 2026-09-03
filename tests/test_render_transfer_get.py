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
