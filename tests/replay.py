"""
------------------------------------------------------------------------------
Script Name:      tests/replay.py
Script Author:    Neal Russell
Script Created:   2026-09-03
Script Version:   1.0.0
Script Purpose:   Replays LDB traffic captured by adws/record.py so the
                  render_* methods can be exercised offline.

Script Desc:      A Recording is a lookup table from directory-call
                  signature to result. It can be built two ways:

                    Recording.from_dir(path)   load a captured fixture
                    Recording().add_search(..) hand-build in a test

                  Both produce the same object, which is installed as the
                  backend behind the stubbed samba.samdb.SamDB for the
                  duration of a test.

                  MATCHING
                  --------
                  Calls are keyed on (method, base, scope, expression,
                  attrs) -- deliberately NOT on controls, because the
                  paged_results control carries a cookie that changes
                  between pages and would make every page a cache miss.
                  Repeated identical calls are served in capture order,
                  which is what makes multi-page paging replayable; once
                  a queue is exhausted the last result is served again,
                  so a test that loops more than the capture did degrades
                  to repetition rather than an error.
------------------------------------------------------------------------------
Execution Context: Imported by tests only. Requires the stub modules to be
                   installed first (tests/conftest.py does this).
------------------------------------------------------------------------------
"""
import json
import os

# These names resolve to the stubs, which conftest.py has already
# installed into sys.modules under the real names.
import ldb
from samba import samdb as stub_samdb


CALLS_FILENAME = 'calls.jsonl'


def _key(method, base=None, scope=None, expression=None, attrs=None):
    """
    Canonical signature for a directory call.

    Controls are excluded on purpose -- see MATCHING in the module
    docstring. attrs is sorted because the order sambautils builds it in
    depends on which branch of the wildcard logic ran, and that is not a
    meaningful difference to the directory.
    """
    return (
        method,
        str(base) if base is not None else None,
        scope,
        expression,
        tuple(sorted(attrs)) if attrs else None,
    )


class Recording(object):
    """Replayable set of directory-call results."""

    def __init__(self, name='<inline>'):
        self.name = name
        # key -> list of pending results (FIFO)
        self._queues = {}
        # key -> last result served, for post-exhaustion reuse
        self._last = {}
        # attribute name -> syntax OID
        self._syntax = {}
        self._domain_dn = 'DC=vlab,DC=test'
        self._schema_basedn = 'CN=Schema,CN=Configuration,DC=vlab,DC=test'
        # Every call made during replay, for assertions about what the
        # code under test actually asked the directory for.
        self.calls = []

    # -- construction -----------------------------------------------------

    @classmethod
    def from_dir(cls, path):
        """Load a fixture directory produced by adws/record.py."""
        rec = cls(name=os.path.basename(path.rstrip('/')))
        calls_path = os.path.join(path, CALLS_FILENAME)
        if not os.path.exists(calls_path):
            raise FileNotFoundError(
                'No %s in %s -- capture one with '
                'ADWS_RECORD_DIR (see adws/record.py)'
                % (CALLS_FILENAME, path)
            )
        with open(calls_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    rec._load_entry(json.loads(line))
        return rec

    def _load_entry(self, entry):
        method = entry.get('method')
        args = entry.get('args') or {}
        result = entry.get('result')

        if method == 'search':
            if result is None:
                # A recorded failure. Replay it as an empty result --
                # error replay is deliberately out of scope until the
                # fault-handling phase gives errors a defined shape.
                self._enqueue(_key('search', **_search_args(args)),
                              ldb.Result())
                return
            self._enqueue(
                _key('search', **_search_args(args)),
                ldb.Result(
                    msgs=[ldb.message_from_dict(m)
                          for m in result.get('msgs', [])],
                    controls=result.get('controls') or [],
                    referals=result.get('referals') or [],
                ),
            )
        elif method == 'get_syntax_oid_from_lDAPDisplayName':
            self._syntax[args.get('attr')] = result
        elif method == 'domain_dn' and result:
            self._domain_dn = result
        elif method == 'get_schema_basedn' and result:
            self._schema_basedn = result

    def _enqueue(self, key, value):
        self._queues.setdefault(key, []).append(value)

    # -- hand-built fixtures ---------------------------------------------

    def add_search(self, msgs, base=None, scope=None, expression=None,
                   attrs=None, controls=None):
        """
        Register a canned search result.

        `msgs` may be ldb.Message objects or (dn, attrs-dict) pairs, in
        which case attribute values are taken as str/bytes and encoded
        the way LDB would return them.
        """
        built = []
        for m in msgs:
            if isinstance(m, ldb.Message):
                built.append(m)
            else:
                dn, attrs_dict = m
                built.append(ldb.Message(dn=dn, attrs=attrs_dict))
        self._enqueue(
            _key('search', base=base, scope=scope,
                 expression=expression, attrs=attrs),
            ldb.Result(msgs=built, controls=controls or []),
        )
        return self

    def add_syntax(self, mapping):
        """Register attribute-name -> syntax-OID lookups."""
        self._syntax.update(mapping)
        return self

    def set_domain_dn(self, dn):
        self._domain_dn = dn
        return self

    def set_schema_basedn(self, dn):
        self._schema_basedn = dn
        return self

    # -- backend interface (called by the stubbed SamDB) ------------------

    def search(self, base=None, scope=None, expression=None,
               attrs=None, controls=None):
        self.calls.append({
            'method': 'search', 'base': str(base) if base is not None else None,
            'scope': scope, 'expression': expression,
            'attrs': list(attrs) if attrs else attrs,
            'controls': list(controls) if controls else controls,
        })

        key = _key('search', base=base, scope=scope,
                   expression=expression, attrs=attrs)

        queue = self._queues.get(key)
        if queue:
            value = queue.pop(0)
            self._last[key] = value
            return value
        if key in self._last:
            # Exhausted, but this call was seen before -- repeat the
            # final page rather than failing the test outright.
            return self._last[key]

        raise AssertionError(
            "Recording %r has no result for search:\n"
            "  base       = %r\n"
            "  scope      = %r\n"
            "  expression = %r\n"
            "  attrs      = %r\n"
            "Recorded search keys:\n%s"
            % (
                self.name, str(base), scope, expression, attrs,
                '\n'.join('  %r' % (k,) for k in self._queues)
                or '  (none)',
            )
        )

    def domain_dn(self):
        self.calls.append({'method': 'domain_dn'})
        return self._domain_dn

    def get_schema_basedn(self):
        self.calls.append({'method': 'get_schema_basedn'})
        return self._schema_basedn

    def get_syntax_oid_from_lDAPDisplayName(self, attr):
        self.calls.append({
            'method': 'get_syntax_oid_from_lDAPDisplayName', 'attr': attr})
        # An unknown attribute returns None, which is what a real schema
        # lookup does for an attribute that is not in the schema. That
        # drives the fallback branch in build_attr_list().
        return self._syntax.get(attr)

    # -- assertions helpers ----------------------------------------------

    def searches(self):
        """Every search call made during the test, in order."""
        return [c for c in self.calls if c['method'] == 'search']


def _search_args(args):
    return {
        'base': args.get('base'),
        'scope': args.get('scope'),
        'expression': args.get('expression'),
        'attrs': args.get('attrs'),
    }


class _Installed(object):
    """Context manager installing a Recording as the active backend."""

    def __init__(self, recording):
        self.recording = recording

    def __enter__(self):
        stub_samdb.install_backend(self.recording)
        return self.recording

    def __exit__(self, *exc):
        stub_samdb.clear_backend()
        return False


def using(recording):
    """Install a Recording for the duration of a `with` block."""
    return _Installed(recording)


def load(name, fixtures_dir=None):
    """Load a captured fixture directory by name and return a Recording."""
    base = fixtures_dir or os.path.join(os.path.dirname(__file__), 'fixtures')
    return Recording.from_dir(os.path.join(base, name))
