"""
render_pull() -- the WS-Enumeration Pull path.

This is where most cmdlet output comes from, and where the object-class,
wildcard and multi-NC fixes all landed. Every test here replays canned
LDB results through a Recording, so no DC is needed.
"""
import ldb
import pytest
from lxml import etree

from tests import replay

NSMAP = {
    's': 'http://www.w3.org/2003/05/soap-envelope',
    'a': 'http://www.w3.org/2005/08/addressing',
    'wsen': 'http://schemas.xmlsoap.org/ws/2004/09/enumeration',
    'addata': 'http://schemas.microsoft.com/2008/1/ActiveDirectory/Data',
    'ad': 'http://schemas.microsoft.com/2008/1/ActiveDirectory',
}

DOMAIN_DN = 'DC=vlab,DC=test'

# The syntax OIDs sambautils will look up for the attributes used below.
SYNTAXES = {
    'sAMAccountName': ldb.SYNTAX_DIRECTORY_STRING,
    'cn': ldb.SYNTAX_DIRECTORY_STRING,
    'objectClass': ldb.SYNTAX_DIRECTORY_STRING,
    'description': ldb.SYNTAX_DIRECTORY_STRING,
    'userAccountControl': ldb.SYNTAX_INTEGER,
    'primaryGroupID': ldb.SYNTAX_INTEGER,
}


def base_context(**overrides):
    """A Pull request context of the shape main.py builds."""
    context = {
        'MessageID': 'urn:uuid:11112222-3333-4444-5555-666677778888',
        'objectReferenceProperty': '',
        'Action': 'http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull',
        'To': 'net.tcp://dc1.vlab.test:9389/ActiveDirectoryWebServices'
              '/Windows/Enumeration',
        'AttributeType_List': [],
        'MaxElements': '256',
        'EnumerationContext': {},
        'SelectionProperty_List': ['addata:sAMAccountName', 'addata:cn'],
        'LdapQuery': {
            'BaseObject': DOMAIN_DN,
            'Scope': 'subtree',
            'Filter': '(objectClass=user)',
        },
    }
    context.update(overrides)
    return context


def render(sambautils, rec, context):
    with replay.using(rec):
        helper = sambautils.SamDBHelper()
        return helper.render_pull(**context)


def parse(xml):
    return etree.fromstring(xml.encode('utf-8'))


def items(root):
    return root.find('.//wsen:Items', NSMAP)


# ========================================================================== #
# Object class handling (change log v1.1.0)                                  #
# ========================================================================== #

@pytest.mark.parametrize('object_class,dn', [
    ('user', 'CN=alice,CN=Users,' + DOMAIN_DN),
    ('group', 'CN=Admins,CN=Users,' + DOMAIN_DN),
    ('organizationalUnit', 'OU=Servers,' + DOMAIN_DN),
    ('computer', 'CN=DC1,OU=Domain Controllers,' + DOMAIN_DN),
])
def test_result_is_wrapped_in_its_own_object_class(
        sambautils, recording, object_class, dn):
    """
    Every object type gets its own <addata:X> wrapper. Before v1.1.0
    this was hardcoded to <addata:computer>, so only Get-ADComputer
    worked.
    """
    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [(dn, {
            'sAMAccountName': [b'thing'],
            'cn': [b'thing'],
            'objectClass': [b'top', object_class.encode()],
            'userAccountControl': [b'512'],
            'primaryGroupID': [b'513'],
        })],
        base=DOMAIN_DN, scope=ldb.SCOPE_SUBTREE,
        expression='(objectClass=user)',
        attrs=['sAMAccountName', 'cn', 'objectClass',
               'userAccountControl', 'primaryGroupID'],
    )

    root = parse(render(sambautils, rec, base_context()))
    children = list(items(root))

    assert len(children) == 1
    assert etree.QName(children[0]).localname == object_class


def test_most_derived_object_class_wins(sambautils, recording):
    """objectClass is ordered least- to most-derived; the last one is used."""
    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [('CN=alice,' + DOMAIN_DN, {
            'sAMAccountName': [b'alice'],
            'cn': [b'alice'],
            'objectClass': [b'top', b'person', b'organizationalPerson', b'user'],
            'userAccountControl': [b'512'],
            'primaryGroupID': [b'513'],
        })],
        base=DOMAIN_DN, scope=ldb.SCOPE_SUBTREE,
        expression='(objectClass=user)',
        attrs=['sAMAccountName', 'cn', 'objectClass',
               'userAccountControl', 'primaryGroupID'],
    )

    root = parse(render(sambautils, rec, base_context()))
    assert etree.QName(list(items(root))[0]).localname == 'user'


def test_object_class_not_rendered_unless_requested(sambautils, recording):
    """
    objectClass is always fetched from LDB (needed for the wrapper tag)
    but must not leak into the response body when the client did not
    ask for it.
    """
    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [('CN=alice,' + DOMAIN_DN, {
            'sAMAccountName': [b'alice'],
            'cn': [b'alice'],
            'objectClass': [b'top', b'user'],
            'userAccountControl': [b'512'],
            'primaryGroupID': [b'513'],
        })],
        base=DOMAIN_DN, scope=ldb.SCOPE_SUBTREE,
        expression='(objectClass=user)',
        attrs=['sAMAccountName', 'cn', 'objectClass',
               'userAccountControl', 'primaryGroupID'],
    )

    root = parse(render(sambautils, rec, base_context()))
    rendered = [etree.QName(e).localname for e in list(items(root))[0]]

    assert 'sAMAccountName' in rendered
    assert 'objectClass' not in rendered


# ========================================================================== #
# Wildcard handling (change log v1.1.3)                                      #
# ========================================================================== #

def test_ad_all_wildcard_fetches_every_attribute(sambautils, recording):
    """
    -Properties * arrives as a trailing 'ad:all' SelectionProperty. It
    must become attrs=None on the LDB search, not a literal attribute
    named 'all'.
    """
    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [('CN=alice,' + DOMAIN_DN, {
            'sAMAccountName': [b'alice'],
            'cn': [b'alice'],
            'description': [b'a user'],
            'objectClass': [b'top', b'user'],
        })],
        base=DOMAIN_DN, scope=ldb.SCOPE_SUBTREE,
        expression='(objectClass=user)', attrs=None,
    )

    context = base_context(
        SelectionProperty_List=['addata:sAMAccountName', 'ad:all'])
    root = parse(render(sambautils, rec, context))

    assert rec.searches()[0]['attrs'] is None, \
        "'all' must not be passed to LDB as an attribute name"

    rendered = [etree.QName(e).localname for e in list(items(root))[0]]
    assert 'description' in rendered


# ========================================================================== #
# DC qualification (change log v1.1.9 / v1.1.10)                             #
# ========================================================================== #

def test_dc_qual_attrs_always_fetched(sambautils, recording):
    """
    userAccountControl and primaryGroupID must be added to the LDB
    fetch list even when unrequested -- v1.1.9 checked for them without
    fetching them, so they were never there.
    """
    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [('CN=DC1,OU=Domain Controllers,' + DOMAIN_DN, {
            'sAMAccountName': [b'DC1$'],
            'cn': [b'DC1'],
            'objectClass': [b'top', b'computer'],
            'userAccountControl': [b'8192'],
            'primaryGroupID': [b'516'],
        })],
        base=DOMAIN_DN, scope=ldb.SCOPE_SUBTREE,
        expression='(objectClass=computer)',
        attrs=['sAMAccountName', 'cn', 'objectClass',
               'userAccountControl', 'primaryGroupID'],
    )

    context = base_context()
    context['LdapQuery']['Filter'] = '(objectClass=computer)'
    root = parse(render(sambautils, rec, context))

    fetched = rec.searches()[0]['attrs']
    assert 'userAccountControl' in fetched
    assert 'primaryGroupID' in fetched

    rendered = [etree.QName(e).localname for e in list(items(root))[0]]
    assert 'userAccountControl' in rendered
    assert 'primaryGroupID' in rendered


def test_dc_qual_attrs_not_injected_into_non_computers(sambautils, recording):
    """The injection is computer-only; a user must not gain the attrs."""
    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [('CN=alice,' + DOMAIN_DN, {
            'sAMAccountName': [b'alice'],
            'cn': [b'alice'],
            'objectClass': [b'top', b'user'],
            'userAccountControl': [b'512'],
            'primaryGroupID': [b'513'],
        })],
        base=DOMAIN_DN, scope=ldb.SCOPE_SUBTREE,
        expression='(objectClass=user)',
        attrs=['sAMAccountName', 'cn', 'objectClass',
               'userAccountControl', 'primaryGroupID'],
    )

    root = parse(render(sambautils, rec, base_context()))
    rendered = [etree.QName(e).localname for e in list(items(root))[0]]
    assert 'userAccountControl' not in rendered


# ========================================================================== #
# Paging                                                                     #
# ========================================================================== #

def test_end_of_sequence_emitted_on_last_page(sambautils, recording):
    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [], base=DOMAIN_DN, scope=ldb.SCOPE_SUBTREE,
        expression='(objectClass=user)',
        attrs=['sAMAccountName', 'cn', 'objectClass',
               'userAccountControl', 'primaryGroupID'],
        controls=[],
    )

    root = parse(render(sambautils, rec, base_context()))
    assert root.find('.//wsen:EndOfSequence', NSMAP) is not None


# The response-side paged_results control string format is INFERRED from
# the parser in render_pull(), which rsplit(':', 3)s it and requires
# exactly three parts -- i.e. 'paged_results:<critical>:<cookie>'. It has
# not been confirmed against a real Samba capture. Confirming it is a
# good first use of a recorded fixture: run a search large enough to page
# with ADWS_RECORD_DIR set and read the controls out of calls.jsonl.
PAGED_MORE = 'paged_results:1:COOKIEBYTES'


def test_end_of_sequence_withheld_when_more_pages_remain(
        sambautils, recording):
    """A non-empty paged_results cookie means the client must Pull again."""
    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [('CN=alice,' + DOMAIN_DN, {
            'sAMAccountName': [b'alice'], 'cn': [b'alice'],
            'objectClass': [b'top', b'user'],
            'userAccountControl': [b'512'], 'primaryGroupID': [b'513'],
        })],
        base=DOMAIN_DN, scope=ldb.SCOPE_SUBTREE,
        expression='(objectClass=user)',
        attrs=['sAMAccountName', 'cn', 'objectClass',
               'userAccountControl', 'primaryGroupID'],
        controls=[PAGED_MORE],
    )

    context = base_context()
    root = parse(render(sambautils, rec, context))

    assert root.find('.//wsen:EndOfSequence', NSMAP) is None
    assert context['EnumerationContext'].get('cookie') == ':COOKIEBYTES'


def test_cookie_containing_a_colon_is_read_as_end_of_sequence(
        sambautils, recording):
    """
    Documents a fragility rather than asserting desired behaviour.

    The cookie is parsed positionally with rsplit(':', 3) and a
    len == 3 check, so any cookie containing a colon yields four parts
    and is silently treated as 'no more pages' -- the client stops
    early and the caller sees a truncated result set with no error.

    Whether Samba can actually emit such a cookie is unconfirmed; if a
    recorded fixture shows it can, this becomes a real bug and the
    parse should move to a bounded split from the left.
    """
    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [], base=DOMAIN_DN, scope=ldb.SCOPE_SUBTREE,
        expression='(objectClass=user)',
        attrs=['sAMAccountName', 'cn', 'objectClass',
               'userAccountControl', 'primaryGroupID'],
        controls=['paged_results:1:COOKIE:WITH:COLONS'],
    )

    context = base_context()
    root = parse(render(sambautils, rec, context))

    assert root.find('.//wsen:EndOfSequence', NSMAP) is not None
    assert 'cookie' not in context['EnumerationContext']


# ========================================================================== #
# Empty BaseObject / multi-NC search (change log v1.1.4 - v1.1.8)            #
# ========================================================================== #

def test_empty_base_object_searches_domain_and_config_nc(
        sambautils, recording):
    """
    An empty BaseObject means 'search the whole directory'. Samba
    rejects a literal empty base DN, so the current code searches the
    domain NC and Configuration NC and merges.
    """
    rec = recording().add_syntax(SYNTAXES).set_domain_dn(DOMAIN_DN)
    config_dn = 'CN=Configuration,' + DOMAIN_DN
    common = dict(
        scope=ldb.SCOPE_SUBTREE, expression='(objectClass=nTDSDSA)',
        attrs=['cn', 'objectClass', 'userAccountControl', 'primaryGroupID'],
    )
    rec.add_search([('CN=DC1,OU=Domain Controllers,' + DOMAIN_DN, {
        'cn': [b'DC1'], 'objectClass': [b'top', b'computer'],
    })], base=DOMAIN_DN, **common)
    rec.add_search([('CN=NTDS Settings,CN=DC1,CN=Servers,' + config_dn, {
        'cn': [b'NTDS Settings'], 'objectClass': [b'top', b'nTDSDSA'],
    })], base=config_dn, **common)

    context = base_context(SelectionProperty_List=['addata:cn'])
    context['LdapQuery'] = {
        'BaseObject': '', 'Scope': 'subtree',
        'Filter': '(objectClass=nTDSDSA)',
    }

    root = parse(render(sambautils, rec, context))

    bases = [c['base'] for c in rec.searches()]
    assert DOMAIN_DN in bases
    assert config_dn in bases
    assert len(list(items(root))) == 2


@pytest.mark.xfail(
    strict=True,
    reason='The multi-NC branch searches only the domain and Configuration '
           'NCs. The Schema NC and application partitions '
           '(DomainDnsZones/ForestDnsZones) are never searched, so a global '
           'query cannot find objects that live there. Superseded once the '
           'phantom-root search control is passed through.',
)
def test_empty_base_object_also_searches_schema_nc(sambautils, recording):
    schema_dn = 'CN=Schema,CN=Configuration,' + DOMAIN_DN
    rec = (recording().add_syntax(SYNTAXES)
           .set_domain_dn(DOMAIN_DN).set_schema_basedn(schema_dn))
    common = dict(
        scope=ldb.SCOPE_SUBTREE, expression='(objectClass=attributeSchema)',
        attrs=['cn', 'objectClass', 'userAccountControl', 'primaryGroupID'],
    )
    for base in (DOMAIN_DN, 'CN=Configuration,' + DOMAIN_DN, schema_dn):
        rec.add_search([], base=base, **common)

    context = base_context(SelectionProperty_List=['addata:cn'])
    context['LdapQuery'] = {
        'BaseObject': '', 'Scope': 'subtree',
        'Filter': '(objectClass=attributeSchema)',
    }
    render(sambautils, rec, context)

    assert schema_dn in [c['base'] for c in rec.searches()]


@pytest.mark.xfail(
    strict=True,
    reason='The multi-NC branch hardcodes is_end=True (change log v1.1.8), '
           'so a global search that spans more than one page silently '
           'truncates -- the client is told the sequence ended.',
)
def test_multi_nc_search_honours_paging(sambautils, recording):
    rec = recording().add_syntax(SYNTAXES).set_domain_dn(DOMAIN_DN)
    common = dict(
        scope=ldb.SCOPE_SUBTREE, expression='(objectClass=user)',
        attrs=['cn', 'objectClass', 'userAccountControl', 'primaryGroupID'],
        controls=['paged_results:1:0:MORE'],
    )
    rec.add_search([('CN=a,' + DOMAIN_DN, {
        'cn': [b'a'], 'objectClass': [b'top', b'user']})],
        base=DOMAIN_DN, **common)
    rec.add_search([], base='CN=Configuration,' + DOMAIN_DN, **common)

    context = base_context(SelectionProperty_List=['addata:cn'])
    context['LdapQuery'] = {
        'BaseObject': '', 'Scope': 'subtree', 'Filter': '(objectClass=user)'}

    root = parse(render(sambautils, rec, context))
    assert root.find('.//wsen:EndOfSequence', NSMAP) is None


# ========================================================================== #
# Response envelope                                                          #
# ========================================================================== #

def test_relates_to_echoes_request_message_id(sambautils, recording):
    rec = recording().add_syntax(SYNTAXES)
    rec.add_search(
        [], base=DOMAIN_DN, scope=ldb.SCOPE_SUBTREE,
        expression='(objectClass=user)',
        attrs=['sAMAccountName', 'cn', 'objectClass',
               'userAccountControl', 'primaryGroupID'],
    )

    context = base_context()
    root = parse(render(sambautils, rec, context))

    assert root.find('.//a:RelatesTo', NSMAP).text == context['MessageID']
