"""
------------------------------------------------------------------------------
Script Name:      record.py
Script Author:    Neal Russell
Author's Company: N/A (fork of gitlab.com/catalyst-samba/samba-adws)
Script Created:   2026-09-03
Script Modified:  2026-09-04
Script Version:   1.2.1
Script Purpose:   Optional recording layer for the ADWS proxy. When
                  enabled, captures every LDB call the proxy makes,
                  arguments and results, so those exchanges can be
                  replayed offline by the test suite without a live
                  Samba AD DC.

Script Desc:      Recording is OFF unless the ADWS_RECORD_DIR
                  environment variable is set. When it is set,
                  maybe_wrap() patches four methods directly onto the
                  SamDBHelper instance: search, domain_dn,
                  get_schema_basedn, and get_syntax_oid_from_lDAPDisplayName.
                  Patching the instance, not wrapping it in a separate
                  object, is required here. Every LDB call in
                  sambautils.py happens as self.search(...) from
                  inside a render_* method, so self is always the
                  original helper. A composition wrapper with
                  __getattr__ delegation only intercepts calls made
                  from outside the object. It cannot see a call made
                  by one of the helper's own methods against its own
                  self, so nothing is ever captured. Patching the
                  instance's own attributes means self.search resolves
                  to the patched version everywhere, including from
                  inside render_pull, render_transfer_get, and every
                  other method that calls self.search(...) directly.

                  Typical capture session, inside the container:

                    supervisorctl stop adws
                    ADWS_RECORD_DIR=/tmp/rec \\
                      python3 /opt/samba-adws/main.py -b 0.0.0.0 -p 9389

                  then from the Windows client run the cmdlet under
                  investigation, e.g.

                    Get-ADUser -Filter * -Properties *

                  and copy /tmp/rec back out of the container into
                  tests/fixtures/<name>/.

                  Output layout under ADWS_RECORD_DIR:

                    .session      sentinel, presence means this
                                  directory already holds a capture
                    calls.jsonl   one JSON object per LDB call
                    <n>.xml       SOAP exchange n, the decoded request
                                  followed by the rendered response
                                  (written by xmlutils.print_xml)

                  calls.jsonl is append only within one capture
                  session and each record carries the exchange index
                  it belongs to, so LDB traffic can be correlated with
                  the SOAP request that provoked it. main.py is a
                  ForkingTCPServer, so a single cmdlet routinely opens
                  several overlapping connections, one per ADWS
                  endpoint it touches, and this module runs once per
                  connection, in a separate forked process each time.
                  The .session sentinel keeps that from truncating
                  calls.jsonl on every connection instead of once per
                  session. See _start_session().

                  To start a new capture and discard the old one,
                  remove the whole directory first:

                    rm -rf /tmp/rec

Script Desc:      Values returned by LDB are arbitrary bytes (SIDs,
                  GUIDs, security descriptors). The base64 encoding
                  used in the fixture format is defined once, in
                  tests/stubs/ldb.py (message_to_dict and
                  message_from_dict). This module reimplements the
                  encode half rather than importing it, because the
                  tests package is not shipped into the container
                  image. See FIXTURE FORMAT below. Keep the two in
                  step.
------------------------------------------------------------------------------
Execution Context: Imported by main.py. A no-op unless ADWS_RECORD_DIR
                   is set in the environment.
------------------------------------------------------------------------------
FIXTURE FORMAT (must match tests/stubs/ldb.py message_from_dict):
  message := {"dn": "<string>", "attrs": {"<name>": ["<base64>", ...]}}
  call    := {"exchange": <int>, "method": "<name>", "args": {...},
              "result": <method-specific>, "error": "<repr>"|null}
------------------------------------------------------------------------------
Change Log:
  1.0.0 - Initial recording layer as a composition wrapper around
            SamDBHelper.
  1.1.0 - Added a session sentinel so calls.jsonl is truncated once
            per capture session instead of once per connection.
  1.2.0 - Replaced the composition wrapper with instance method
            patching. The wrapper never actually captured anything,
            since every LDB call in sambautils.py is made as
            self.search(...) from inside a render_* method, where
            self is the original unwrapped helper.
  1.2.1 - Fixed a crash the recorder itself introduced. The search
            wrapper declared named parameters with None defaults,
            which turned an omitted scope argument into an explicit
            scope=None on the forwarded call and crashed a request
            the recorder was only supposed to be observing. All
            wrapped methods now forward *args and **kwargs exactly
            as received instead of re-declaring a signature.
------------------------------------------------------------------------------
"""
import json
import logging
import os
from base64 import b64encode

log = logging.getLogger(__name__)

ENV_VAR = 'ADWS_RECORD_DIR'

# Methods patched onto the SamDBHelper instance when recording is on.
RECORDED_METHODS = (
    'search',
    'domain_dn',
    'get_schema_basedn',
    'get_syntax_oid_from_lDAPDisplayName',
)


# ---- _encode_message ----
def _encode_message(msg):
    """
    Serialise one ldb.Message to the JSON safe fixture form.

    Mirrors tests/stubs/ldb.py message_to_dict(). Every attribute
    value is base64 encoded because LDB values are bytes and may be
    binary.
    """
    attrs = {}
    for key in msg.keys():
        if key == 'dn':
            continue
        vals = msg.get(key)
        if vals is None:
            continue
        encoded = []
        for v in vals:
            if not isinstance(v, bytes):
                v = str(v).encode('utf-8')
            encoded.append(b64encode(v).decode('ascii'))
        attrs[key] = encoded
    return {'dn': str(msg.get('dn')), 'attrs': attrs}


# ---- _encode_result ----
def _encode_result(result):
    """
    Serialise an ldb.Result: its messages and its controls.

    result.controls carries the paged_results cookie that
    render_pull() depends on for paging, so it must be captured
    alongside the messages or replayed paging tests would be
    meaningless.
    """
    return {
        'msgs': [_encode_message(m) for m in result],
        'controls': [str(c) for c in getattr(result, 'controls', []) or []],
        'referals': [str(r) for r in getattr(result, 'referals', []) or []],
    }


class _Session(object):
    """
    Per capture session state: where to write, and which exchange
    the next write belongs to.

    One instance is created per connection (main.py forks a fresh
    process per connection), but _start_session() ensures only the
    first one to reach the record directory truncates calls.jsonl.
    """

    # ---- __init__ ----
    def __init__(self, record_dir):
        """
        Resolve the output path and truncate calls.jsonl once per
        capture session, using an atomic sentinel so overlapping
        connections in separate forked processes do not race.
        """
        self.exchange = 0
        os.makedirs(record_dir, exist_ok=True)
        self.path = os.path.join(record_dir, 'calls.jsonl')
        self._start_session(record_dir)
        log.info('ADWS recording enabled -> %s', record_dir)

    # ---- _start_session ----
    def _start_session(self, record_dir):
        """
        Truncate calls.jsonl exactly once per capture session.

        main.py is a ForkingTCPServer. Every connection runs handle()
        in a freshly forked child process, and each child builds its
        own SamDBHelper and calls maybe_wrap() on it, so this runs
        once per connection, in a separate process each time, with no
        shared in memory state to say this is not the first one.
        Confirmed live, 2026-09-04: a four connection capture came
        back with a 0 byte calls.jsonl because the last connection to
        reach this code truncated the file and then never got far
        enough to write anything before being reset.

        A sentinel file created with O_CREAT | O_EXCL is atomic
        across processes at the OS level. Exactly one connection's
        open() call can win the race and see the file not yet exist,
        so exactly one connection truncates calls.jsonl. Every other
        connection, concurrent or later, gets FileExistsError and
        appends instead.
        """
        sentinel = os.path.join(record_dir, '.session')
        try:
            fd = os.open(sentinel, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            with open(self.path, 'w'):
                pass
        except FileExistsError:
            pass

    # ---- write ----
    def write(self, entry):
        """
        Append one JSON record to calls.jsonl, tagged with the
        current exchange index.
        """
        entry['exchange'] = self.exchange
        try:
            with open(self.path, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception:
            # Recording must never take down the proxy. A capture
            # session that loses a line is recoverable. A crashed DC
            # during capture is not.
            log.exception('failed to write recording entry')

    # ---- record ----
    def record(self, method, args, call):
        """
        Run call(), log its arguments and result (or its exception)
        to calls.jsonl, then return the result or re-raise.
        """
        try:
            value = call()
        except Exception as exc:
            self.write({
                'method': method, 'args': args,
                'result': None, 'error': repr(exc),
            })
            raise

        if method == 'search':
            encoded = _encode_result(value)
        else:
            encoded = str(value) if value is not None else None

        self.write({
            'method': method, 'args': args,
            'result': encoded, 'error': None,
        })
        return value


# ---- _make_search_wrapper ----
def _make_search_wrapper(session, original):
    """
    Build a replacement for helper.search that logs its call through
    session before delegating to the real, unpatched search() bound
    method captured in original.

    Forwards *args and **kwargs exactly as received, rather than
    re-declaring named parameters with None defaults. Confirmed live,
    2026-09-04: render_transfer_get() calls self.search(base=...,
    attrs=..., controls=[]), deliberately omitting scope so the real
    search() method's own default applies. A wrapper declared as
    def _search(base=None, scope=None, ...) turns that omission into
    an explicit scope=None on the forwarded call, and the underlying
    C extension search() cannot accept None there, only a truly
    absent argument. That crashed a request the recorder was only
    supposed to be observing. Passing through the caller's exact
    args and kwargs, whatever they are, is the only way to guarantee
    the wrapped call behaves identically to the unwrapped one.
    """
    def _search(*args, **kwargs):
        base = kwargs.get('base')
        attrs = kwargs.get('attrs')
        controls = kwargs.get('controls')
        logged = {
            'base': str(base) if base is not None else None,
            'scope': kwargs.get('scope'),
            'expression': kwargs.get('expression'),
            'attrs': list(attrs) if attrs is not None else None,
            'controls': list(controls) if controls is not None else None,
        }
        return session.record(
            'search', logged, lambda: original(*args, **kwargs))
    return _search


# ---- _make_simple_wrapper ----
def _make_simple_wrapper(session, method_name, original):
    """
    Build a replacement for a zero or one argument helper method
    (domain_dn, get_schema_basedn, get_syntax_oid_from_lDAPDisplayName)
    that logs its call through session before delegating to original.

    Forwards *args and **kwargs exactly as received rather than
    re-declaring named parameters. See _make_search_wrapper for why
    that matters: a wrapper signature that does not exactly match the
    real method's own defaults can change a call's behaviour.
    """
    if method_name == 'get_syntax_oid_from_lDAPDisplayName':
        def _wrapped(*args, **kwargs):
            attr = args[0] if args else kwargs.get('attr')
            return session.record(
                method_name, {'attr': attr},
                lambda: original(*args, **kwargs))
        return _wrapped

    def _wrapped(*args, **kwargs):
        return session.record(
            method_name, {}, lambda: original(*args, **kwargs))
    return _wrapped


# ---- record_dir ----
def record_dir():
    """Return the configured recording directory, or None if off."""
    return os.environ.get(ENV_VAR) or None


# ---- maybe_wrap ----
def maybe_wrap(helper):
    """
    Patch recording onto a SamDBHelper instance if ADWS_RECORD_DIR is
    set, then return the same instance.

    Patches search, domain_dn, get_schema_basedn, and
    get_syntax_oid_from_lDAPDisplayName directly onto helper's own
    __dict__. Python attribute lookup checks the instance dict before
    the class, so self.search resolves to the patched version from
    everywhere, including from inside the helper's own render_*
    methods, which is the whole point. A composition wrapper cannot
    do this. See the module docstring.

    Returns the helper unchanged when recording is disabled, so the
    call site in main.py is a single unconditional line.
    """
    target = record_dir()
    if not target:
        return helper
    try:
        session = _Session(target)
        for name in RECORDED_METHODS:
            original = getattr(helper, name)
            if name == 'search':
                wrapped = _make_search_wrapper(session, original)
            else:
                wrapped = _make_simple_wrapper(session, name, original)
            setattr(helper, name, wrapped)
        setattr(helper, '_adws_record_session', session)
    except Exception:
        log.exception('could not enable recording, continuing without it')
    return helper


# ---- set_exchange ----
def set_exchange(helper, index):
    """
    Tag subsequent recorded calls with the SOAP exchange index they
    serve, if recording is active on this helper.

    Safe to call on a helper that was never wrapped. It is a no-op
    then, which keeps main.py free of recording related conditionals.
    """
    session = getattr(helper, '_adws_record_session', None)
    if session is not None:
        session.exchange = index
