"""
------------------------------------------------------------------------------
Script Name:      tests/stubs/samba/samdb.py
Script Author:    Neal Russell
Script Created:   2026-09-03
Script Version:   1.0.0
Script Purpose:   Stand-in for samba.samdb.SamDB. Routes every directory
                  call to a pluggable backend so tests can replay
                  recorded LDB traffic instead of talking to a real DC.

Script Desc:      SamDBHelper subclasses SamDB, so the stub has to be a
                  real base class rather than a mock -- the subclass
                  calls SamDB.__init__ and then inherits search(),
                  domain_dn(), get_schema_basedn() and
                  get_syntax_oid_from_lDAPDisplayName().

                  The backend is installed per-test by tests/replay.py
                  via install_backend(). With no backend installed every
                  directory call raises, which is deliberate: a test that
                  forgot its fixture should fail loudly rather than
                  silently exercise empty results.
------------------------------------------------------------------------------
Execution Context: Installed into sys.modules by tests/conftest.py.
                   Never used in production.
------------------------------------------------------------------------------
"""

# The active backend. tests/replay.py sets and clears this around each
# test via install_backend() / clear_backend(). Module-level rather than
# instance-level because SamDBHelper.__init__ takes no arguments and so
# offers nowhere to inject a dependency -- changing that signature is a
# production change, and this harness is deliberately non-invasive.
_BACKEND = None


class NoBackendInstalled(RuntimeError):
    """Raised when directory access is attempted with no fixture loaded."""


def install_backend(backend):
    global _BACKEND
    _BACKEND = backend


def clear_backend():
    global _BACKEND
    _BACKEND = None


def get_backend():
    if _BACKEND is None:
        raise NoBackendInstalled(
            "No LDB fixture is installed. Wrap the call in the `recording` "
            "context manager or request the `recorded` fixture so replay "
            "data is available."
        )
    return _BACKEND


class SamDB(object):
    """
    Minimal stand-in for samba.samdb.SamDB.

    Only the methods sambautils.py actually calls are implemented. Any
    other attribute access raises AttributeError as usual, which keeps
    the stub honest -- if production code starts calling a new SamDB
    method, the stubbed suite fails rather than quietly passing.
    """

    def __init__(self, url=None, lp=None, session_info=None,
                 credentials=None, **kwargs):
        self.lp = lp
        self.session_info = session_info

    # -- directory access -------------------------------------------------

    def search(self, base=None, scope=None, expression=None,
               attrs=None, controls=None):
        return get_backend().search(
            base=base, scope=scope, expression=expression,
            attrs=attrs, controls=controls,
        )

    def domain_dn(self):
        return get_backend().domain_dn()

    def get_schema_basedn(self):
        return get_backend().get_schema_basedn()

    def get_syntax_oid_from_lDAPDisplayName(self, attr):
        return get_backend().get_syntax_oid_from_lDAPDisplayName(attr)
