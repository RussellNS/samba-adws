"""
------------------------------------------------------------------------------
Script Name:      record.py
Script Author:    Neal Russell
Author's Company: N/A (fork of gitlab.com/catalyst-samba/samba-adws)
Script Created:   2026-09-03
Script Version:   1.0.0
Script Purpose:   Optional recording layer for the ADWS proxy. When
                  enabled, captures every LDB call the proxy makes --
                  arguments and results -- so those exchanges can be
                  replayed offline by the test suite without a live
                  Samba AD DC.

Script Desc:      Recording is OFF unless the ADWS_RECORD_DIR environment
                  variable is set, and the wrapper is a transparent
                  proxy, so this module is inert in normal operation.

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

                    calls.jsonl   one JSON object per LDB call
                    <n>.xml       SOAP exchange n -- the decoded request
                                  followed by the rendered response
                                  (written by xmlutils.print_xml)

                  calls.jsonl is append-only and each record carries the
                  exchange index it belongs to, so LDB traffic can be
                  correlated with the SOAP request that provoked it.

Script Desc:      Values returned by LDB are arbitrary bytes (SIDs, GUIDs,
                  security descriptors). The base64 encoding used in the
                  fixture format is defined once, in tests/stubs/ldb.py
                  (message_to_dict / message_from_dict). This module
                  reimplements the encode half rather than importing it,
                  because the tests/ package is not shipped into the
                  container image -- see FIXTURE FORMAT below. Keep the
                  two in step.
------------------------------------------------------------------------------
Execution Context: Imported by main.py. A no-op unless ADWS_RECORD_DIR is
                   set in the environment.
------------------------------------------------------------------------------
FIXTURE FORMAT (must match tests/stubs/ldb.py message_from_dict):
  message := {"dn": "<string>", "attrs": {"<name>": ["<base64>", ...]}}
  call    := {"exchange": <int>, "method": "<name>", "args": {...},
              "result": <method-specific>, "error": "<repr>"|null}
------------------------------------------------------------------------------
Change Log:
  1.0.0  - Initial recording layer supporting search(), domain_dn(),
           get_schema_basedn() and get_syntax_oid_from_lDAPDisplayName().
------------------------------------------------------------------------------
"""
import json
import logging
import os
from base64 import b64encode

log = logging.getLogger(__name__)

ENV_VAR = 'ADWS_RECORD_DIR'

# Methods intercepted on the SamDBHelper. Anything not listed here is
# passed straight through to the wrapped object untouched.
RECORDED_METHODS = (
    'search',
    'domain_dn',
    'get_schema_basedn',
    'get_syntax_oid_from_lDAPDisplayName',
)


def _encode_message(msg):
    """
    Serialise one ldb.Message to the JSON-safe fixture form.

    Mirrors tests/stubs/ldb.py message_to_dict(). Every attribute value
    is base64-encoded because LDB values are bytes and may be binary.
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


def _encode_result(result):
    """
    Serialise an ldb.Result -- its messages and its controls.

    result.controls carries the paged_results cookie that render_pull()
    depends on for paging, so it must be captured alongside the messages
    or replayed paging tests would be meaningless.
    """
    return {
        'msgs': [_encode_message(m) for m in result],
        'controls': [str(c) for c in getattr(result, 'controls', []) or []],
        'referals': [str(r) for r in getattr(result, 'referals', []) or []],
    }


class SamDBRecorder(object):
    """
    Transparent wrapper around SamDBHelper that logs directory calls.

    Attribute access falls through to the wrapped helper for everything
    except the methods in RECORDED_METHODS, so the proxy behaves
    identically whether or not recording is active.
    """

    def __init__(self, helper, record_dir):
        # Bypass our own __getattr__/__setattr__ for these two.
        object.__setattr__(self, '_helper', helper)
        object.__setattr__(self, '_dir', record_dir)
        object.__setattr__(self, '_exchange', 0)

        os.makedirs(record_dir, exist_ok=True)
        object.__setattr__(
            self, '_path', os.path.join(record_dir, 'calls.jsonl'))

        # Truncate on start so each capture session is self-contained.
        with open(self._path, 'w'):
            pass
        log.info('ADWS recording enabled -> %s', record_dir)

    # -- exchange correlation --------------------------------------------

    def set_exchange(self, index):
        """Tag subsequent calls with the SOAP exchange index they serve."""
        object.__setattr__(self, '_exchange', index)

    # -- capture ----------------------------------------------------------

    def _write(self, entry):
        entry['exchange'] = self._exchange
        try:
            with open(self._path, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception:
            # Recording must never take down the proxy. A capture
            # session that loses a line is recoverable; a crashed DC
            # during capture is not.
            log.exception('failed to write recording entry')

    def _record(self, method, args, call):
        try:
            value = call()
        except Exception as exc:
            self._write({
                'method': method, 'args': args,
                'result': None, 'error': repr(exc),
            })
            raise

        if method == 'search':
            encoded = _encode_result(value)
        else:
            encoded = str(value) if value is not None else None

        self._write({
            'method': method, 'args': args,
            'result': encoded, 'error': None,
        })
        return value

    # -- intercepted methods ---------------------------------------------

    def search(self, base=None, scope=None, expression=None,
               attrs=None, controls=None):
        args = {
            'base': str(base) if base is not None else None,
            'scope': scope,
            'expression': expression,
            'attrs': list(attrs) if attrs is not None else None,
            'controls': list(controls) if controls is not None else None,
        }
        return self._record(
            'search', args,
            lambda: self._helper.search(
                base=base, scope=scope, expression=expression,
                attrs=attrs, controls=controls),
        )

    def domain_dn(self):
        return self._record(
            'domain_dn', {}, lambda: self._helper.domain_dn())

    def get_schema_basedn(self):
        return self._record(
            'get_schema_basedn', {},
            lambda: self._helper.get_schema_basedn())

    def get_syntax_oid_from_lDAPDisplayName(self, attr):
        return self._record(
            'get_syntax_oid_from_lDAPDisplayName', {'attr': attr},
            lambda: self._helper.get_syntax_oid_from_lDAPDisplayName(attr),
        )

    # -- transparent passthrough -----------------------------------------

    def __getattr__(self, name):
        # Only reached for attributes not found on the wrapper itself.
        return getattr(object.__getattribute__(self, '_helper'), name)

    def __setattr__(self, name, value):
        setattr(self._helper, name, value)


def record_dir():
    """Return the configured recording directory, or None if disabled."""
    return os.environ.get(ENV_VAR) or None


def maybe_wrap(helper):
    """
    Wrap a SamDBHelper in a recorder if ADWS_RECORD_DIR is set.

    Returns the helper unchanged when recording is disabled, so the
    call site in main.py is a single unconditional line.
    """
    target = record_dir()
    if not target:
        return helper
    try:
        return SamDBRecorder(helper, target)
    except Exception:
        log.exception('could not enable recording; continuing without it')
        return helper


def set_exchange(helper, index):
    """
    Tag the recorder with the current SOAP exchange index, if recording.

    Safe to call with an unwrapped helper -- it is a no-op then, which
    keeps main.py free of recording-related conditionals.
    """
    setter = getattr(helper, 'set_exchange', None)
    if setter is not None and isinstance(helper, SamDBRecorder):
        setter(index)
