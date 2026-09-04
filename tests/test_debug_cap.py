"""
adws/debug_cap.py, the message size bisection tool.

This is not production behaviour, so coverage here is narrow: confirm
each knob is off by default, confirm each truncates when configured,
confirm they compose (both set at once), and confirm the object count
knob leaves controls (the paged_results cookie) untouched.
"""
import ldb
import pytest

from adws import debug_cap, sambautils


@pytest.fixture(autouse=True)
def reset_patches(monkeypatch):
    """
    Undo any patch a previous test left behind and restore the real
    methods afterwards, so tests do not leak state into each other or
    into the rest of the suite.
    """
    real_ldapattr_init = sambautils.LdapAttr.__init__
    real_search = sambautils.SamDBHelper.search

    monkeypatch.delenv(debug_cap.ATTR_VALUES_ENV_VAR, raising=False)
    monkeypatch.delenv(debug_cap.OBJECTS_ENV_VAR, raising=False)
    debug_cap._original_ldapattr_init = None
    debug_cap._original_search = None

    yield

    sambautils.LdapAttr.__init__ = real_ldapattr_init
    sambautils.SamDBHelper.search = real_search
    debug_cap._original_ldapattr_init = None
    debug_cap._original_search = None


# ========================================================================== #
# ADWS_DEBUG_MAX_ATTR_VALUES                                                 #
# ========================================================================== #

def test_attr_values_disabled_by_default():
    debug_cap.enable_if_configured()
    attr = sambautils.LdapAttr('cn', [b'a', b'b', b'c'], 'UnicodeString')
    assert attr.vals == ['a', 'b', 'c']


def test_attr_values_truncates_when_configured(monkeypatch):
    monkeypatch.setenv(debug_cap.ATTR_VALUES_ENV_VAR, '2')
    debug_cap.enable_if_configured()

    attr = sambautils.LdapAttr('cn', [b'a', b'b', b'c'], 'UnicodeString')

    assert attr.vals == ['a', 'b']


def test_attr_values_does_not_pad_a_shorter_list(monkeypatch):
    monkeypatch.setenv(debug_cap.ATTR_VALUES_ENV_VAR, '10')
    debug_cap.enable_if_configured()

    attr = sambautils.LdapAttr('cn', [b'a'], 'UnicodeString')

    assert attr.vals == ['a']


# ========================================================================== #
# ADWS_DEBUG_MAX_OBJECTS                                                     #
# ========================================================================== #

def test_object_count_disabled_by_default(recording):
    rec = recording()
    rec.add_search(
        [('CN=a,DC=vlab,DC=test', {'cn': [b'a']}),
         ('CN=b,DC=vlab,DC=test', {'cn': [b'b']}),
         ('CN=c,DC=vlab,DC=test', {'cn': [b'c']})],
        base='DC=vlab,DC=test', scope=ldb.SCOPE_SUBTREE,
    )
    debug_cap.enable_if_configured()

    from tests import replay
    with replay.using(rec):
        helper = sambautils.SamDBHelper()
        result = helper.search(base='DC=vlab,DC=test', scope=ldb.SCOPE_SUBTREE)

    assert len(list(result.msgs)) == 3


def test_object_count_truncates_when_configured(monkeypatch, recording):
    monkeypatch.setenv(debug_cap.OBJECTS_ENV_VAR, '2')
    rec = recording()
    rec.add_search(
        [('CN=a,DC=vlab,DC=test', {'cn': [b'a']}),
         ('CN=b,DC=vlab,DC=test', {'cn': [b'b']}),
         ('CN=c,DC=vlab,DC=test', {'cn': [b'c']})],
        base='DC=vlab,DC=test', scope=ldb.SCOPE_SUBTREE,
    )
    debug_cap.enable_if_configured()

    from tests import replay
    with replay.using(rec):
        helper = sambautils.SamDBHelper()
        result = helper.search(base='DC=vlab,DC=test', scope=ldb.SCOPE_SUBTREE)

    msgs = list(result.msgs)
    assert len(msgs) == 2
    assert str(msgs[0]['dn']) == 'CN=a,DC=vlab,DC=test'
    assert str(msgs[1]['dn']) == 'CN=b,DC=vlab,DC=test'


def test_object_count_cap_preserves_paging_controls(monkeypatch, recording):
    """
    render_pull() reads result.controls for the paged_results cookie.
    Capping object count must not also silently drop paging state, or
    a capped bisection run would look like it always ends the
    sequence even when the real query had more pages.
    """
    monkeypatch.setenv(debug_cap.OBJECTS_ENV_VAR, '1')
    rec = recording()
    rec.add_search(
        [('CN=a,DC=vlab,DC=test', {'cn': [b'a']}),
         ('CN=b,DC=vlab,DC=test', {'cn': [b'b']})],
        base='DC=vlab,DC=test', scope=ldb.SCOPE_SUBTREE,
        controls=['paged_results:1:0:COOKIEBYTES'],
    )
    debug_cap.enable_if_configured()

    from tests import replay
    with replay.using(rec):
        helper = sambautils.SamDBHelper()
        result = helper.search(base='DC=vlab,DC=test', scope=ldb.SCOPE_SUBTREE)

    assert len(list(result.msgs)) == 1
    assert any(
        str(c).startswith('paged_results') for c in result.controls)


def test_object_count_cap_shrinks_a_real_render_pull_response(
        monkeypatch, recording):
    """
    End to end through render_pull(), not just search() in isolation,
    since that is the actual call path main.py uses and the one that
    matters for the real bisection this tool exists for.
    """
    from lxml import etree

    from tests import replay

    monkeypatch.setenv(debug_cap.OBJECTS_ENV_VAR, '1')
    rec = recording()
    rec.add_syntax({'cn': ldb.SYNTAX_DIRECTORY_STRING,
                    'objectClass': ldb.SYNTAX_DIRECTORY_STRING})
    rec.add_search(
        [('CN=a,DC=vlab,DC=test', {
            'cn': [b'a'], 'objectClass': [b'top', b'user']}),
         ('CN=b,DC=vlab,DC=test', {
            'cn': [b'b'], 'objectClass': [b'top', b'user']})],
        base='DC=vlab,DC=test', scope=ldb.SCOPE_SUBTREE,
        expression='(objectClass=user)',
        attrs=['cn', 'objectClass', 'userAccountControl', 'primaryGroupID'],
    )
    debug_cap.enable_if_configured()

    context = {
        'MessageID': 'urn:uuid:x',
        'MaxElements': '256',
        'EnumerationContext': {},
        'SelectionProperty_List': ['addata:cn'],
        'LdapQuery': {
            'BaseObject': 'DC=vlab,DC=test', 'Scope': 'subtree',
            'Filter': '(objectClass=user)',
        },
    }
    with replay.using(rec):
        helper = sambautils.SamDBHelper()
        xml = helper.render_pull(**context)

    root = etree.fromstring(xml.encode('utf-8'))
    items = root.find(
        './/{http://schemas.xmlsoap.org/ws/2004/09/enumeration}Items')
    assert len(list(items)) == 1


def test_second_enable_call_does_not_double_patch(monkeypatch, recording):
    monkeypatch.setenv(debug_cap.ATTR_VALUES_ENV_VAR, '1')
    monkeypatch.setenv(debug_cap.OBJECTS_ENV_VAR, '1')
    debug_cap.enable_if_configured()
    debug_cap.enable_if_configured()

    attr = sambautils.LdapAttr('cn', [b'a', b'b'], 'UnicodeString')
    assert attr.vals == ['a']

    rec = recording()
    rec.add_search(
        [('CN=a,DC=vlab,DC=test', {'cn': [b'a']}),
         ('CN=b,DC=vlab,DC=test', {'cn': [b'b']})],
        base='DC=vlab,DC=test', scope=ldb.SCOPE_SUBTREE,
    )
    from tests import replay
    with replay.using(rec):
        helper = sambautils.SamDBHelper()
        result = helper.search(base='DC=vlab,DC=test', scope=ldb.SCOPE_SUBTREE)
    assert len(list(result.msgs)) == 1
