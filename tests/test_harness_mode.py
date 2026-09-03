"""
The harness's own mode selection.

Getting this wrong is expensive in a way that is easy to miss: reading a
marker expression as 'live' when it is not makes the stubbed suite demand
python3-samba, and reading it as 'stubbed' when it IS live would silently
run the fidelity tests against the very stubs they exist to check.
"""
import pytest

from tests.conftest import marker_selects_live


@pytest.mark.parametrize('expr', [
    'live',
    'live or slow',
    'slow or live',
    'slow and live',
])
def test_expressions_that_select_live(expr):
    assert marker_selects_live(expr) is True


@pytest.mark.parametrize('expr', [
    '',
    None,
    'not live',
    'not  live',
    'slow and not live',
    'not live and not slow',
])
def test_expressions_that_do_not_select_live(expr):
    assert marker_selects_live(expr) is False


@pytest.mark.parametrize('expr', [
    'liveness',
    'alive',
    'notlive',
])
def test_substrings_are_not_the_live_marker(expr):
    """Word-boundary matching: 'liveness' is not the 'live' marker."""
    assert marker_selects_live(expr) is False
