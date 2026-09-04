"""
Stub fidelity -- run inside the container with `pytest -m live`.

The stubbed suite is only as trustworthy as the assumptions baked into
tests/stubs/. These tests compare those assumptions against the real
python3-samba and fail when they drift.

If one of these fails, the fix is to correct tests/stubs/ -- NOT to
weaken the assertion. A stub that disagrees with reality turns every
other passing test into a false negative.

NOTE on the SYNTAX_* checks below: as of the 2026-09-04 syntax-registry
fix, sambautils.py no longer sources these from the `ldb` module at all
-- see tests/test_syntax_registry.py for why (a live capture showed the
old getattr(ldb, NAME, 1) approach silently mis-annotating objectClass
on every object in a Get-ADObject response, which broke the cmdlet
outright). These EXPECTED_PRESENT/EXPECTED_ABSENT checks are therefore
no longer guarding production correctness -- they only document the
real ldb module's shape, for whoever next writes a stub or fixture
against it. tests/stubs/ldb.py's own SYNTAX_* constants remain for
fixture-authoring convenience in the other test files.
"""
import importlib

import pytest

pytestmark = pytest.mark.live

# Names tests/stubs/ldb.py asserts python3-ldb DOES export.
EXPECTED_PRESENT = [
    'SCOPE_BASE', 'SCOPE_ONELEVEL', 'SCOPE_SUBTREE',
    'SYNTAX_DIRECTORY_STRING', 'SYNTAX_INTEGER', 'SYNTAX_BOOLEAN',
    'SYNTAX_OCTET_STRING', 'SYNTAX_DN', 'SYNTAX_UTC_TIME',
]

# Names tests/stubs/ldb.py asserts python3-ldb does NOT export. If one of
# these starts existing, the syntax-registry collision documented in
# test_syntax_registry.py has partly resolved itself and that test needs
# revisiting.
#
# SYNTAX_GENERALIZED_TIME's absence was CONFIRMED live on 2026-09-04
# (this file previously listed it under EXPECTED_PRESENT by mistake,
# which is exactly the failure mode this suite exists to catch).
# SYNTAX_LARGE_INTEGER and SYNTAX_OBJECT_IDENTIFIER are unconfirmed --
# carried over from the original (unverified) reading of the bindings.
EXPECTED_ABSENT = [
    'SYNTAX_LARGE_INTEGER',
    'SYNTAX_OBJECT_IDENTIFIER',
    'SYNTAX_GENERALIZED_TIME',
]


def real_ldb():
    return importlib.import_module('ldb')


@pytest.mark.parametrize('name', EXPECTED_PRESENT)
def test_expected_constants_exist(name):
    assert hasattr(real_ldb(), name), (
        '%s is missing from the real ldb module, but tests/stubs/ldb.py '
        'assumes it exists.' % name
    )


@pytest.mark.parametrize('name', EXPECTED_ABSENT)
def test_expected_absent_constants_are_absent(name):
    assert not hasattr(real_ldb(), name), (
        '%s now EXISTS in the real ldb module. tests/stubs/ldb.py omits it '
        'deliberately to reproduce the getattr() fallback collision. Add it '
        'to the stub and revisit test_syntax_registry.py.' % name
    )


def test_scope_values_match_stub():
    import sys
    import os
    stubs = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'stubs')
    sys.path.insert(0, stubs)
    try:
        spec = importlib.util.spec_from_file_location(
            '_stub_ldb', os.path.join(stubs, 'ldb.py'))
        stub = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(stub)
    finally:
        sys.path.remove(stubs)

    real = real_ldb()
    for name in ('SCOPE_BASE', 'SCOPE_ONELEVEL', 'SCOPE_SUBTREE'):
        assert getattr(stub, name) == getattr(real, name), \
            'stub %s disagrees with real ldb' % name


def test_samdb_exposes_methods_the_proxy_calls():
    """
    tests/stubs/samba/samdb.py implements only these. If production code
    starts calling something else, the stub raises AttributeError and the
    stubbed suite fails -- but only if the real class actually has it,
    which is what this checks.
    """
    from samba.samdb import SamDB
    for name in ('search', 'domain_dn', 'get_schema_basedn',
                 'get_syntax_oid_from_lDAPDisplayName'):
        assert hasattr(SamDB, name), \
            '%s no longer exists on the real SamDB' % name


def test_message_element_is_not_a_list():
    """
    LdapAttr's list() conversion exists because MessageElement is a
    read-only C sequence. If that ever became a plain list the stub
    would be misleading.
    """
    import ldb
    element = ldb.MessageElement([b'x'], ldb.FLAG_MOD_REPLACE, 'cn')
    assert not isinstance(element, list)


def test_attribute_values_are_bytes_that_str_to_text():
    """
    THE load-bearing stub assumption.

    Production code needs both of these to hold for the SAME value:

      isinstance(v, bytes)  -- LdapAttr's base64 fallback depends on it
      str(v) == 'user'      -- render_pull builds the <addata:X> tag name
                               from str(msg['objectClass'][-1])

    Plain bytes fails the second (str(b'user') is "b'user'", which
    yields the malformed tag <addata:b'user'>), so Samba must be
    returning a bytes subclass with a decoding __str__. If this test
    fails, tests/stubs/ldb.py needs to match whatever it actually
    returns -- and render_pull's tag construction needs re-examining.
    """
    import ldb

    lp = None
    try:
        from samba.param import LoadParm
        lp = LoadParm()
        lp.load_default()
    except Exception:
        pytest.skip('no smb.conf available to open a real SamDB')

    from samba.auth import system_session
    from samba.samdb import SamDB

    samdb = SamDB(lp=lp, session_info=system_session())
    result = samdb.search(
        base=samdb.domain_dn(), scope=ldb.SCOPE_SUBTREE,
        expression='(objectClass=user)', attrs=['objectClass'])
    assert len(result), 'no user objects found to sample'

    value = result[0]['objectClass'][-1]
    assert isinstance(value, bytes), 'LDB value is not bytes-like'
    assert str(value) == value.decode('utf-8'), (
        'str() on an LDB value produced %r rather than the decoded text. '
        'render_pull builds XML tag names with str() and will emit '
        'malformed XML.' % str(value)
    )


def test_result_msgs_is_read_only():
    """
    Regression guard for sambautils change log v1.1.8, which was caused
    by assuming result.msgs was assignable.

    ldb.Result is a C extension type that cannot be constructed
    directly (ldb.Result() raises TypeError: cannot create 'ldb.Result'
    instances -- confirmed live on 2026-09-04, this test's first version
    tried exactly that and failed for the wrong reason). A real instance
    can only be obtained from search(), so get one that way.
    """
    import ldb

    try:
        from samba.param import LoadParm
        lp = LoadParm()
        lp.load_default()
    except Exception:
        pytest.skip('no smb.conf available to open a real SamDB')

    from samba.auth import system_session
    from samba.samdb import SamDB

    samdb = SamDB(lp=lp, session_info=system_session())
    result = samdb.search(
        base=samdb.domain_dn(), scope=ldb.SCOPE_BASE, attrs=['objectClass'])

    with pytest.raises((AttributeError, TypeError)):
        result.msgs = []
