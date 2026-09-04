"""
------------------------------------------------------------------------------
Script Name:      debug_cap.py
Script Author:    Neal Russell
Author's Company: N/A (fork of gitlab.com/catalyst-samba/samba-adws)
Script Created:   2026-09-04
Script Version:   1.1.0
Script Purpose:   Temporary bisection tool for the message size ceiling
                  the AD PowerShell client silently enforces on ADWS
                  responses. Truncates the size of a response two
                  independent ways, so a real capture can be repeated
                  at several response sizes without editing code
                  between attempts:

                    ADWS_DEBUG_MAX_ATTR_VALUES
                      caps how many values a single multi-valued
                      attribute renders (shrinks a few huge
                      attributes, e.g. attributeTypes)

                    ADWS_DEBUG_MAX_OBJECTS
                      caps how many objects a Pull response renders
                      (shrinks a response with many small objects,
                      e.g. an attributeSchema enumeration)

Script Desc:      Confirmed live, 2026-09-04: a WS-Transfer Get response
                  around 900KB, two different content sets across two
                  different cmdlets, was rejected by the AD PowerShell
                  client both times, sent successfully and then reset
                  immediately after, with no server side error.
                  ADWS_DEBUG_MAX_ATTR_VALUES=50 shrank that same
                  request to about 31KB and it was accepted cleanly,
                  including the client's own graceful EndRecord close.
                  That confirmed a message size or reader quota
                  rejection for that exchange.

                  The client then proceeded to a second, unrelated
                  schema introspection step, a WS-Enumeration Pull of
                  194 attributeSchema objects with ordinary,
                  single-valued attributes, about 121KB, which was
                  ALSO rejected the same way. Since every attribute in
                  that response is already single-valued,
                  ADWS_DEBUG_MAX_ATTR_VALUES cannot shrink it. The
                  object count is what needs to shrink, hence
                  ADWS_DEBUG_MAX_OBJECTS.

                  Both knobs are independent and may be set together.
                  Neither belongs in the response path once the real
                  threshold, or the real mechanism if it turns out not
                  to be a simple byte threshold, is known.

                  ADWS_DEBUG_MAX_ATTR_VALUES patches
                  sambautils.LdapAttr.__init__. ADWS_DEBUG_MAX_OBJECTS
                  patches sambautils.SamDBHelper.search at the class
                  level, wrapping whatever ldb.Result it returns so
                  that only its first N messages are visible to the
                  caller, everything else (controls, in particular the
                  paged_results cookie render_pull() depends on for
                  paging) passed through unchanged.

                  Patching search() at the CLASS level here, rather
                  than on an instance the way adws/record.py does, is
                  deliberate and required. main.py calls
                  enable_if_configured() once at process start, before
                  any connection or SamDBHelper instance exists.
                  record.maybe_wrap() runs later, once per connection,
                  and captures whatever search() is active on the
                  instance at that moment via getattr(helper,
                  'search') before installing its own instance level
                  patch. Because instance attributes shadow class
                  attributes, that capture sees this module's
                  class-level patch first, wraps it, and installs the
                  combined result on the instance. Recording still
                  observes the capped results, and render_pull() still
                  calls a single self.search(...), unaware that two
                  layers are underneath it. Patching search() on an
                  instance here instead would race the order these two
                  modules happen to be enabled in, which is exactly
                  the kind of fragility this module should not add on
                  top of an already fragile investigation.
------------------------------------------------------------------------------
Execution Context: Imported and enabled once by main.py at startup. A
                   no-op unless one of the two environment variables
                   above is set.
------------------------------------------------------------------------------
Change Log:
  1.0.0 - Initial bisection tool: ADWS_DEBUG_MAX_ATTR_VALUES.
  1.1.0 - Added ADWS_DEBUG_MAX_OBJECTS, for the case where a
            response is large because of object count rather than
            oversized individual attributes.
------------------------------------------------------------------------------
"""
import logging
import os

from adws import sambautils

log = logging.getLogger(__name__)

ATTR_VALUES_ENV_VAR = 'ADWS_DEBUG_MAX_ATTR_VALUES'
OBJECTS_ENV_VAR = 'ADWS_DEBUG_MAX_OBJECTS'

# Set once each patch has been applied, so a second call to
# enable_if_configured() in the same process is a no-op rather than a
# double patch.
_original_ldapattr_init = None
_original_search = None


# ---- _attr_values_limit ----
def _attr_values_limit():
    """Return the configured per-attribute value cap, or None if unset."""
    value = os.environ.get(ATTR_VALUES_ENV_VAR)
    return int(value) if value else None


# ---- _object_limit ----
def _object_limit():
    """Return the configured object count cap, or None if unset."""
    value = os.environ.get(OBJECTS_ENV_VAR)
    return int(value) if value else None


# ---- _capped_ldapattr_init ----
def _capped_ldapattr_init(self, attr, vals, ldap_syntax,
                           xsi_type='xsd:string'):
    """
    Replacement for LdapAttr.__init__ that truncates vals to the
    configured cap before delegating to the real constructor.

    Runs after the real search() call, on values already pulled out
    of whatever ldb returned, so this never touches an ldb.Message or
    ldb.MessageElement directly. A single value (already scalar, not
    yet wrapped in a list) is left alone. The real __init__ still does
    its own bytes handling, base64 fallback, and XML illegal character
    detection on whatever survives the cap.
    """
    limit = _attr_values_limit()
    if limit is not None and hasattr(vals, '__iter__') \
            and not isinstance(vals, (str, bytes)):
        vals = list(vals)[:limit]
    _original_ldapattr_init(self, attr, vals, ldap_syntax, xsi_type)


class _CappedResult(object):
    """
    Presents only the first N messages of a real ldb.Result.

    Wraps rather than copies, since a real ldb.Result is a C
    extension type this module has no business trying to
    reconstruct. controls (in particular the paged_results cookie)
    and referals pass through unchanged, so paging behaviour is
    unaffected by the cap, only how many objects a single page
    renders.
    """

    # ---- __init__ ----
    def __init__(self, real_result, limit):
        self._real = real_result
        self._limit = limit

    @property
    def msgs(self):
        return list(self._real.msgs)[:self._limit]

    @property
    def controls(self):
        return self._real.controls

    @property
    def referals(self):
        return getattr(self._real, 'referals', [])

    def __iter__(self):
        return iter(self.msgs)

    def __len__(self):
        return len(self.msgs)

    def __getitem__(self, index):
        return self.msgs[index]

    def __bool__(self):
        return bool(self.msgs)


# ---- _capped_search ----
def _capped_search(self, *args, **kwargs):
    """
    Replacement for SamDBHelper.search that wraps its result in a
    _CappedResult when ADWS_DEBUG_MAX_OBJECTS is set.

    Declared to take self explicitly, since this patches the class
    rather than an instance. See the module docstring for why that
    matters here.
    """
    result = _original_search(self, *args, **kwargs)
    limit = _object_limit()
    if limit is None:
        return result
    return _CappedResult(result, limit)


# ---- enable_if_configured ----
def enable_if_configured():
    """
    Patch whichever of LdapAttr.__init__ and SamDBHelper.search have
    a configured cap.

    Safe to call every time main.py starts. Does nothing for a knob
    whose environment variable is unset, and patches each one at most
    once per process.
    """
    global _original_ldapattr_init, _original_search

    attr_limit = _attr_values_limit()
    if attr_limit is not None and _original_ldapattr_init is None:
        _original_ldapattr_init = sambautils.LdapAttr.__init__
        sambautils.LdapAttr.__init__ = _capped_ldapattr_init
        log.warning(
            '%s=%s -- every multi-valued attribute is being truncated '
            'for size bisection. This is debug tooling, not a fix. '
            'Unset %s before any real use.',
            ATTR_VALUES_ENV_VAR, attr_limit, ATTR_VALUES_ENV_VAR,
        )

    object_limit = _object_limit()
    if object_limit is not None and _original_search is None:
        _original_search = sambautils.SamDBHelper.search
        sambautils.SamDBHelper.search = _capped_search
        log.warning(
            '%s=%s -- every search() result is being truncated to that '
            'many objects for size bisection. This is debug tooling, '
            'not a fix. Unset %s before any real use.',
            OBJECTS_ENV_VAR, object_limit, OBJECTS_ENV_VAR,
        )
