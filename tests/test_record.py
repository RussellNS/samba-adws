"""
adws/record.py, the LDB call capture layer.

Regression coverage for the bug found live on 2026-09-04: a second
capture attempt still came back with an empty calls.jsonl even after
the truncation race was fixed. The real cause was the recorder's
original design, a composition wrapper with __getattr__ delegation.
Every LDB call in sambautils.py happens as self.search(...) from
inside a render_* method, where self is always the original,
unwrapped helper, so a wrapper object never sees those calls at all.

These tests exercise maybe_wrap() against an object shaped like
SamDBHelper, calling its methods the way sambautils.py actually does,
from inside another method on the same instance, rather than calling
the recorded methods directly from the test. Calling them directly
would have made the original wrapper bug look correct.
"""
import json

import pytest

from adws import record


class FakeResult(object):
    """
    Stands in for ldb.Result: iterable of messages, with the
    controls and referals attributes _encode_result() reads.
    Empty is enough here since these tests check that a call was
    captured, not what its result looked like.
    """

    controls = []
    referals = []

    def __iter__(self):
        return iter([])


class FakeHelper(object):
    """
    Stands in for SamDBHelper. search_from_inside() calls
    self.search(...) exactly the way every render_* method in
    sambautils.py does, which is the behaviour that broke the
    original composition wrapper.
    """

    def search(self, base=None, scope=None, expression=None,
               attrs=None, controls=None):
        return FakeResult()

    def domain_dn(self):
        return 'DC=vlab,DC=test'

    def get_schema_basedn(self):
        return 'CN=Schema,CN=Configuration,DC=vlab,DC=test'

    def get_syntax_oid_from_lDAPDisplayName(self, attr):
        return None

    def search_from_inside(self, base):
        # This is the pattern every render_* method uses: self.search
        # called on the object's own self, not on some external
        # reference to the helper.
        return self.search(base=base, scope=0)


@pytest.fixture
def record_dir(tmp_path, monkeypatch):
    monkeypatch.setenv(record.ENV_VAR, str(tmp_path))
    return tmp_path


def read_calls(record_dir):
    path = record_dir / 'calls.jsonl'
    if not path.exists():
        return []
    lines = path.read_text().splitlines()
    return [json.loads(line) for line in lines if line]


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv(record.ENV_VAR, raising=False)
    helper = FakeHelper()

    wrapped = record.maybe_wrap(helper)

    assert wrapped is helper
    assert not hasattr(helper, '_adws_record_session')


def test_call_made_from_inside_another_method_is_captured(record_dir):
    """
    The exact scenario that broke the original wrapper: search()
    called as self.search(...) from within another method on the
    same instance, not called directly by the test.
    """
    helper = FakeHelper()
    record.maybe_wrap(helper)

    helper.search_from_inside('CN=alice,DC=vlab,DC=test')

    calls = read_calls(record_dir)
    assert len(calls) == 1
    assert calls[0]['method'] == 'search'
    assert calls[0]['args']['base'] == 'CN=alice,DC=vlab,DC=test'


def test_maybe_wrap_returns_the_same_instance(record_dir):
    """
    maybe_wrap() must patch the instance in place, not return a
    different wrapper object, or main.py's samdbhelper reference and
    sambautils.py's internal self would point at different objects.
    """
    helper = FakeHelper()

    wrapped = record.maybe_wrap(helper)

    assert wrapped is helper


def test_exchange_index_is_recorded(record_dir):
    helper = FakeHelper()
    record.maybe_wrap(helper)

    record.set_exchange(helper, 3)
    helper.search_from_inside('CN=alice,DC=vlab,DC=test')

    calls = read_calls(record_dir)
    assert calls[0]['exchange'] == 3


def test_set_exchange_is_a_no_op_on_an_unwrapped_helper():
    helper = FakeHelper()
    # Must not raise.
    record.set_exchange(helper, 5)


def test_session_file_truncates_once_not_per_wrap(record_dir):
    """
    Regression guard for the earlier truncation race: calling
    maybe_wrap() twice against the same ADWS_RECORD_DIR, simulating
    two connections in two forked processes, must not wipe out calls
    already written by the first.
    """
    first = FakeHelper()
    record.maybe_wrap(first)
    first.search_from_inside('CN=alice,DC=vlab,DC=test')

    second = FakeHelper()
    record.maybe_wrap(second)
    second.search_from_inside('CN=bob,DC=vlab,DC=test')

    calls = read_calls(record_dir)
    assert len(calls) == 2
    assert calls[0]['args']['base'] == 'CN=alice,DC=vlab,DC=test'
    assert calls[1]['args']['base'] == 'CN=bob,DC=vlab,DC=test'


def test_omitted_optional_argument_is_not_forced_to_none(record_dir):
    """
    Regression test for a bug the recorder itself introduced, found
    live on 2026-09-04: render_transfer_get() calls
    self.search(base=..., attrs=..., controls=[]), deliberately
    omitting scope so the real search() method's own default applies.
    A wrapper declared as def _search(base=None, scope=None, ...)
    turns that omission into an explicit scope=None on the forwarded
    call. The real python-ldb search() cannot accept None for scope,
    only a truly absent argument, so the wrapped call raised
    TypeError: 'NoneType' object cannot be interpreted as an integer
    on a request that would have worked fine unwrapped.
    """
    seen = {}

    class HelperWithRequiredScopeDefault(object):
        SENTINEL_DEFAULT_SCOPE = 2

        def search(self, base=None, scope=SENTINEL_DEFAULT_SCOPE,
                   expression=None, attrs=None, controls=None):
            # A real ldb-backed search() would raise here if scope
            # were explicitly None instead of truly omitted. This
            # fake instead records what it actually received, since
            # that is easier to assert on than reproducing the C
            # extension's exact failure mode.
            seen['scope'] = scope
            return FakeResult()

        def domain_dn(self):
            return 'DC=vlab,DC=test'

        def get_schema_basedn(self):
            return 'CN=Schema,CN=Configuration,DC=vlab,DC=test'

        def get_syntax_oid_from_lDAPDisplayName(self, attr):
            return None

        def search_without_scope(self, base):
            # Mirrors render_transfer_get(): scope is omitted, not
            # passed as None.
            return self.search(base=base, attrs=None, controls=[])

    helper = HelperWithRequiredScopeDefault()
    record.maybe_wrap(helper)

    helper.search_without_scope('CN=Aggregate,CN=Schema,DC=vlab,DC=test')

    assert seen['scope'] == HelperWithRequiredScopeDefault.SENTINEL_DEFAULT_SCOPE, (
        'the wrapper forwarded an explicit scope, overriding the '
        'real method\'s own default for an argument the caller '
        'never passed'
    )


def test_domain_dn_is_captured(record_dir):
    helper = FakeHelper()
    record.maybe_wrap(helper)

    result = helper.domain_dn()

    assert result == 'DC=vlab,DC=test'
    calls = read_calls(record_dir)
    assert calls[0]['method'] == 'domain_dn'
    assert calls[0]['result'] == 'DC=vlab,DC=test'
