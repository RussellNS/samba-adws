"""
adws/debug_cap.py, the message size bisection tool.

This is not production behaviour, so coverage here is narrow: confirm
it is off by default, confirm it truncates when configured, and
confirm it does not touch a value list shorter than the cap.
"""
import pytest

from adws import debug_cap, sambautils


@pytest.fixture(autouse=True)
def reset_patch(monkeypatch):
    """
    Undo any patch a previous test left behind and restore the real
    LdapAttr.__init__ afterwards, so tests do not leak state into
    each other or into the rest of the suite.
    """
    real_init = sambautils.LdapAttr.__init__
    monkeypatch.delenv(debug_cap.ENV_VAR, raising=False)
    debug_cap._original_init = None
    yield
    sambautils.LdapAttr.__init__ = real_init
    debug_cap._original_init = None


def test_disabled_by_default():
    debug_cap.enable_if_configured()
    attr = sambautils.LdapAttr(
        'cn', [b'a', b'b', b'c'], 'UnicodeString')
    assert attr.vals == ['a', 'b', 'c']


def test_truncates_when_configured(monkeypatch):
    monkeypatch.setenv(debug_cap.ENV_VAR, '2')
    debug_cap.enable_if_configured()

    attr = sambautils.LdapAttr(
        'cn', [b'a', b'b', b'c'], 'UnicodeString')

    assert attr.vals == ['a', 'b']


def test_does_not_pad_a_shorter_list(monkeypatch):
    monkeypatch.setenv(debug_cap.ENV_VAR, '10')
    debug_cap.enable_if_configured()

    attr = sambautils.LdapAttr('cn', [b'a'], 'UnicodeString')

    assert attr.vals == ['a']


def test_second_enable_call_does_not_double_patch(monkeypatch):
    monkeypatch.setenv(debug_cap.ENV_VAR, '1')
    debug_cap.enable_if_configured()
    debug_cap.enable_if_configured()

    attr = sambautils.LdapAttr('cn', [b'a', b'b'], 'UnicodeString')

    assert attr.vals == ['a']
