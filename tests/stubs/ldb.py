"""
------------------------------------------------------------------------------
Script Name:      tests/stubs/ldb.py
Script Author:    Neal Russell
Script Created:   2026-09-03
Script Version:   1.0.0
Script Purpose:   Drop-in stand-in for Samba's python3-ldb module, so the
                  ADWS render_* code can be imported and exercised on a
                  machine with no Samba installation.

Script Desc:      sambautils.py does `import ldb` at module scope and uses
                  ldb constants, ldb.Message, ldb.Dn and ldb.Result. This
                  module reproduces just enough of that surface for the
                  render_* methods to run against replayed fixture data.

                  DESIGN RULE -- MIRROR REALITY, NOT THE IDEAL
                  --------------------------------------------
                  This stub deliberately reproduces real python3-ldb's
                  quirks, including the constants it does NOT export.
                  A stub that is more capable than the real module would
                  hide bugs rather than surface them. See the comment on
                  the syntax constants below, and tests/test_stub_fidelity.py
                  which asserts (under `pytest -m live`, inside the
                  container) that this table still matches the real thing.
------------------------------------------------------------------------------
Execution Context: Imported only by tests/conftest.py, which installs it
                   into sys.modules under the name 'ldb' before sambautils
                   is imported. Never used in production.
------------------------------------------------------------------------------
"""
from base64 import b64decode, b64encode

# The builtin, captured before the name is shadowed below.
_builtin_bytes = bytes


# ========================================================================== #
# ldb.bytes                                                                  #
# ========================================================================== #
# Samba's python3 bindings do NOT hand back plain bytes for attribute
# values. They hand back a bytes SUBCLASS whose __str__ decodes UTF-8,
# which is what lets production code write both of these against the
# same value:
#
#   isinstance(v, bytes)                 -> True  (LdapAttr relies on this
#                                           for the base64 fallback)
#   str(msg['objectClass'][-1])          -> 'user' (render_pull relies on
#                                           this for the XML tag name)
#
# A stub that returned plain bytes would break the second case --
# str(b'user') is "b'user'", which produces the malformed tag
# <addata:b'user'>. Getting this wrong made eleven render_pull tests
# fail against code that works fine in production, which is a good
# illustration of why test_stub_fidelity.py exists.

class bytes(_builtin_bytes):  # noqa: A001 - deliberately shadows the builtin

    def __str__(self):
        try:
            return self.decode('utf-8')
        except UnicodeDecodeError:
            # Genuinely binary data. Real ldb.bytes raises here too;
            # production code never str()s such values, it goes through
            # LdapAttr's base64 path instead.
            return _builtin_bytes.__str__(self)

    def __repr__(self):
        return 'ldb.bytes(%s)' % _builtin_bytes.__repr__(self)


# ========================================================================== #
# Search Scope Constants                                                     #
# ========================================================================== #
# Values match enum ldb_scope in ldb.h. SCOPE_DEFAULT is -1 in the C
# header; the Python bindings expose it as 0. sambautils only uses
# BASE / ONELEVEL / SUBTREE via SCOPE_ADLQ_TO_LDB.

SCOPE_DEFAULT  = 0
SCOPE_BASE     = 0
SCOPE_ONELEVEL = 1
SCOPE_SUBTREE  = 2


# ========================================================================== #
# LDAP Syntax OID Constants                                                  #
# ========================================================================== #
# IMPORTANT -- read before "fixing" the omissions below.
#
# sambautils.py wraps every one of these in getattr(ldb, NAME, 1) because
# python3-ldb does not export all of them. That polyfill is only
# meaningful if this stub reproduces the same gaps. If we exported all
# nine constants here, the stubbed test run would build a nine-entry
# OID_SCHEMA_SYNTAX_DICT while the real DC builds a smaller one -- and
# the tests would pass on a registry that does not exist in production.
#
# So: SYNTAX_LARGE_INTEGER, SYNTAX_OBJECT_IDENTIFIER and
# SYNTAX_GENERALIZED_TIME are INTENTIONALLY ABSENT. All three fall back
# to the literal 1 in sambautils, collide on the same dict key, and the
# last one defined in SCHEMA_SYNTAX_LIST wins. test_syntax_registry.py
# documents the resulting behaviour.
#
# CONFIRMED against a live container (2026-09-04, Samba/python3-ldb on
# Python 3.13.5): SYNTAX_GENERALIZED_TIME does not exist on the real
# `ldb` module -- test_stub_fidelity.py caught this stub being wrong
# about it. SYNTAX_LARGE_INTEGER and SYNTAX_OBJECT_IDENTIFIER were
# already excluded here and have NOT yet been independently confirmed
# absent (the live run before this fix asserted the wrong set of
# "present" names and never checked them). Both are still treated as
# absent below on the pre-existing reasoning; test_stub_fidelity.py now
# checks all three explicitly on every live run so a wrong guess here
# cannot survive silently again.

SYNTAX_DIRECTORY_STRING  = "1.3.6.1.4.1.1466.115.121.1.15"
SYNTAX_INTEGER           = "1.3.6.1.4.1.1466.115.121.1.27"
SYNTAX_BOOLEAN           = "1.3.6.1.4.1.1466.115.121.1.7"
SYNTAX_OCTET_STRING      = "1.3.6.1.4.1.1466.115.121.1.40"
SYNTAX_DN                = "1.3.6.1.4.1.1466.115.121.1.12"
SYNTAX_UTC_TIME          = "1.3.6.1.4.1.1466.115.121.1.53"

# SYNTAX_GENERALIZED_TIME -- intentionally not defined; CONFIRMED absent
# SYNTAX_LARGE_INTEGER    -- intentionally not defined; NOT yet confirmed
# SYNTAX_OBJECT_IDENTIFIER -- intentionally not defined; NOT yet confirmed


# ========================================================================== #
# Error Codes and Exception                                                  #
# ========================================================================== #
# Only the codes the ADWS paths can actually provoke are listed. Error 32
# (NO_SUCH_OBJECT) is the one behind the empty-BaseObject workaround
# documented in sambautils change log v1.1.4.

ERR_OPERATIONS_ERROR = 1
ERR_NO_SUCH_OBJECT   = 32
ERR_INVALID_DN_SYNTAX = 34


class LdbError(Exception):
    """
    Mirrors ldb.LdbError, which is raised with a (code, message) tuple.
    """

    def __init__(self, code, message=''):
        super().__init__(code, message)
        self.code = code
        self.message = message


# ========================================================================== #
# Dn                                                                         #
# ========================================================================== #
# sambautils.get_rdn() calls get_rdn_name() and get_rdn_value(); several
# render_* methods call str() on a Dn. Real ldb.Dn does full RFC 4514
# parsing including escaping -- this stub does a simple split, which is
# adequate for fixture data but will diverge on DNs containing escaped
# commas or equals signs. Fixtures containing such DNs should be added
# to the live suite rather than relied on here.

class Dn(object):

    def __init__(self, samdb_or_str, dn=None):
        # Real ldb.Dn is constructed as Dn(ldb_context, "CN=...").
        # Accept both that form and a bare string for test convenience.
        self._dn = dn if dn is not None else samdb_or_str
        if not isinstance(self._dn, str):
            self._dn = str(self._dn)

    def _first_component(self):
        # Split on the first unescaped comma. Escaped commas ("\,") are
        # left alone; anything more exotic is out of scope for the stub.
        out, i = [], 0
        while i < len(self._dn):
            ch = self._dn[i]
            if ch == '\\' and i + 1 < len(self._dn):
                out.append(self._dn[i:i + 2])
                i += 2
                continue
            if ch == ',':
                break
            out.append(ch)
            i += 1
        return ''.join(out)

    def get_rdn_name(self):
        comp = self._first_component()
        return comp.split('=', 1)[0].strip() if '=' in comp else ''

    def get_rdn_value(self):
        comp = self._first_component()
        return comp.split('=', 1)[1].strip() if '=' in comp else ''

    def __str__(self):
        return self._dn

    def __repr__(self):
        return 'Dn(%r)' % self._dn

    def __eq__(self, other):
        return str(self).lower() == str(other).lower()

    def __hash__(self):
        return hash(str(self).lower())


# ========================================================================== #
# MessageElement                                                             #
# ========================================================================== #
# Real ldb.MessageElement is a read-only C-level sequence of bytes values.
# LdapAttr.__init__ specifically handles that by converting to a list, so
# this stub must also be iterable and indexable but NOT a plain list --
# otherwise the conversion path in LdapAttr goes untested.

class MessageElement(object):

    def __init__(self, values, name=None):
        if isinstance(values, (str, _builtin_bytes)):
            values = [values]
        # Normalise to ldb.bytes -- see the class comment above for why
        # the subclass matters rather than plain bytes.
        self._vals = [
            bytes(v) if isinstance(v, _builtin_bytes)
            else bytes(str(v).encode('utf-8'))
            for v in values
        ]
        self.name = name

    def __iter__(self):
        return iter(self._vals)

    def __getitem__(self, i):
        return self._vals[i]

    def __len__(self):
        return len(self._vals)

    def __repr__(self):
        return 'MessageElement(%r)' % (self._vals,)


# ========================================================================== #
# Message                                                                    #
# ========================================================================== #
# Dict-like. build_attr_list() calls msg.keys(), msg.get(name), uses
# `name in msg`, and reads msg['dn'] as a Dn. Note that 'dn' appears in
# keys() on real LDB results, which is why build_attr_list explicitly
# removes it.

class Message(object):

    def __init__(self, dn='', attrs=None):
        self.dn = dn if isinstance(dn, Dn) else Dn(dn)
        self._attrs = {}
        for k, v in (attrs or {}).items():
            self._attrs[k] = (
                v if isinstance(v, MessageElement)
                else MessageElement(v, name=k)
            )

    def keys(self):
        # 'dn' is included to match real LDB, which surfaces it as a key.
        return ['dn'] + list(self._attrs.keys())

    def get(self, name, default=None):
        if name == 'dn':
            return self.dn
        return self._attrs.get(name, default)

    def __getitem__(self, name):
        if name == 'dn':
            return self.dn
        return self._attrs[name]

    def __contains__(self, name):
        return name == 'dn' or name in self._attrs

    def __iter__(self):
        return iter(self.keys())

    def __repr__(self):
        return 'Message(%r, %r)' % (str(self.dn), list(self._attrs))


# ========================================================================== #
# Control and Result                                                         #
# ========================================================================== #
# render_pull() inspects result.controls, str()-ing each entry and looking
# for one that starts with 'paged_results'. It also reads result.msgs and
# render_transfer_get() indexes result[0].
#
# result.msgs is READ-ONLY on the real object -- see sambautils change log
# v1.1.8, where assigning to it raised AttributeError. The property below
# reproduces that, so the same mistake cannot be reintroduced silently.

class Control(object):

    def __init__(self, text):
        self._text = text

    def __str__(self):
        return self._text

    def __repr__(self):
        return 'Control(%r)' % self._text


class Result(object):

    def __init__(self, msgs=None, controls=None, referals=None):
        self._msgs = list(msgs or [])
        self.controls = [
            c if isinstance(c, Control) else Control(str(c))
            for c in (controls or [])
        ]
        self.referals = list(referals or [])

    @property
    def msgs(self):
        # Read-only by design; see class comment.
        return self._msgs

    def __getitem__(self, i):
        return self._msgs[i]

    def __iter__(self):
        return iter(self._msgs)

    def __len__(self):
        return len(self._msgs)

    def __bool__(self):
        return bool(self._msgs)

    def __repr__(self):
        return 'Result(%d msgs)' % len(self._msgs)


# ========================================================================== #
# Fixture Serialisation Helpers                                              #
# ========================================================================== #
# LDB attribute values are arbitrary bytes (SIDs, GUIDs, security
# descriptors), so fixtures store every value base64-encoded. These two
# helpers are the single definition of that format, shared by the
# recorder (adws/record.py) and the replayer (tests/replay.py).

def message_to_dict(msg):
    """Serialise an ldb.Message (real or stub) to a JSON-safe dict."""
    attrs = {}
    for key in msg.keys():
        if key == 'dn':
            continue
        vals = msg.get(key)
        if vals is None:
            continue
        encoded = []
        for v in vals:
            if not isinstance(v, _builtin_bytes):
                v = str(v).encode('utf-8')
            encoded.append(b64encode(v).decode('ascii'))
        attrs[key] = encoded
    return {'dn': str(msg.get('dn')), 'attrs': attrs}


def message_from_dict(data):
    """Rebuild a stub Message from the dict produced by message_to_dict."""
    return Message(
        dn=data.get('dn', ''),
        attrs={
            k: [b64decode(v) for v in vals]
            for k, vals in (data.get('attrs') or {}).items()
        },
    )
