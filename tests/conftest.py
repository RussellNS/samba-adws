"""
------------------------------------------------------------------------------
Script Name:      tests/conftest.py
Script Author:    Neal Russell
Script Created:   2026-09-03
Script Version:   1.0.0
Script Purpose:   Chooses between the stubbed and real Samba backends and
                  makes the repository importable from the test suite.

Script Desc:      TWO MODES
                  ---------
                  stubbed (default)
                      Fake `ldb` and `samba` modules from tests/stubs are
                      installed into sys.modules BEFORE adws.sambautils is
                      imported. Runs anywhere with jinja2 + lxml. This is
                      the fast development loop.

                  live (`pytest -m live`)
                      No stubs are installed; the real python3-samba is
                      used. Only meaningful inside the container. These
                      tests validate that the stubs still match reality
                      and that the proxy talks to an actual DC.

                  Mode is decided by whether `-m live` was requested, not
                  by what happens to be installed -- otherwise a missing
                  Samba would silently downgrade a live run to a stubbed
                  one and report a pass that means nothing.

                  IMPORT ORDER MATTERS
                  --------------------
                  adws.sambautils does `import ldb` at module scope, so
                  the stubs must be in sys.modules before anything
                  imports it. pytest loads conftest.py before collecting
                  test modules, which is what makes this work.
------------------------------------------------------------------------------
"""
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STUBS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'stubs')

# Make `adws`, `wcf` and `nettcp` importable without installing the package.
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _want_live(config):
    """True when the run was explicitly asked for live tests."""
    expr = config.getoption('-m', default='') or ''
    return 'live' in expr


def _install_stubs():
    """
    Put tests/stubs at the front of sys.path so `import ldb` and
    `import samba` resolve to the fakes.

    Path manipulation rather than direct sys.modules assignment, so that
    submodule imports (samba.samdb, samba.param, ...) resolve naturally
    through the normal import machinery.
    """
    if STUBS_DIR not in sys.path:
        sys.path.insert(0, STUBS_DIR)

    # Guard against a real samba having been imported already by
    # something else in the process -- that would defeat the stubs
    # silently, which is exactly the failure mode this harness exists
    # to avoid.
    for name in list(sys.modules):
        if name == 'ldb' or name == 'samba' or name.startswith('samba.'):
            module = sys.modules[name]
            origin = getattr(module, '__file__', '') or ''
            if not origin.startswith(STUBS_DIR):
                del sys.modules[name]

    import ldb  # noqa: F401  -- force resolution now so failures are loud
    import samba.samdb  # noqa: F401


def pytest_configure(config):
    config.addinivalue_line(
        'markers',
        'live: requires a real python3-samba (and for some tests a running '
        'AD DC). Run inside the container: pytest -m live',
    )

    if _want_live(config):
        # Real Samba. Fail loudly rather than silently falling back.
        try:
            import ldb  # noqa: F401
            import samba.samdb  # noqa: F401
        except ImportError as exc:
            raise pytest.UsageError(
                'pytest -m live requires python3-samba, which is not '
                'importable here (%s). Run this inside the '
                'samba-ad-dc container.' % exc
            )
        config._adws_mode = 'live'
    else:
        _install_stubs()
        config._adws_mode = 'stubbed'


def pytest_report_header(config):
    return 'adws backend: %s' % getattr(config, '_adws_mode', 'unknown')


def pytest_collection_modifyitems(config, items):
    """Skip live-marked tests unless the run asked for them."""
    if _want_live(config):
        return
    skip = pytest.mark.skip(reason='needs real python3-samba; run pytest -m live')
    for item in items:
        if 'live' in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def sambautils():
    """The module under test, imported after the backend is decided."""
    from adws import sambautils as module
    return module


@pytest.fixture
def recording():
    """
    Factory for an empty Recording, auto-uninstalled after the test.

    Usage:
        def test_x(recording, sambautils):
            rec = recording()
            rec.add_search([...], base='...', scope=0)
            with replay.using(rec):
                ...
    """
    from tests import replay

    created = []

    def _make(name='<inline>'):
        rec = replay.Recording(name=name)
        created.append(rec)
        return rec

    yield _make

    from samba import samdb as stub_samdb
    stub_samdb.clear_backend()
