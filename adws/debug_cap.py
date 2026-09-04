"""
------------------------------------------------------------------------------
Script Name:      debug_cap.py
Script Author:    Neal Russell
Author's Company: N/A (fork of gitlab.com/catalyst-samba/samba-adws)
Script Created:   2026-09-04
Script Version:   1.0.0
Script Purpose:   Temporary bisection tool for the message size ceiling
                  the AD PowerShell client silently enforces on ADWS
                  responses. Truncates every multi-valued attribute to
                  a configured maximum number of values, so a real
                  capture can be repeated at several response sizes
                  without editing code between attempts.

Script Desc:      Confirmed live, 2026-09-04: three response bodies of
                  roughly 900KB, two different content sets across two
                  different cmdlets, were all rejected by the AD
                  PowerShell client in the same way. The proxy sent a
                  complete response every time and the connection was
                  reset immediately after, with no server side error.
                  A response of about 172KB, from the same client
                  session earlier in the investigation, was accepted.
                  This points at a WCF message size or reader quota
                  rejection rather than a content defect, but the real
                  threshold is unknown, and finding it precisely
                  requires testing against the real client, which this
                  module exists to make cheap to repeat.

                  Off unless ADWS_DEBUG_MAX_ATTR_VALUES is set. When
                  set, every attribute value list longer than that
                  count is truncated before rendering, which shrinks
                  large multi-valued attributes such as
                  extendedAttributeInfo and attributeTypes without
                  touching the response shape or any other attribute.

                  This module patches sambautils.LdapAttr.__init__ at
                  the class level, once, the first time
                  enable_if_configured() is called. It is bisection
                  tooling only. It is not a fix, it does not belong in
                  the response path once the real threshold is known,
                  and it must never run with the environment variable
                  unset.
------------------------------------------------------------------------------
Execution Context: Imported and enabled once by main.py at startup. A
                   no-op unless ADWS_DEBUG_MAX_ATTR_VALUES is set in
                   the environment.
------------------------------------------------------------------------------
Change Log:
  1.0.0 - Initial bisection tool.
------------------------------------------------------------------------------
"""
import logging
import os

from adws import sambautils

log = logging.getLogger(__name__)

ENV_VAR = 'ADWS_DEBUG_MAX_ATTR_VALUES'

# Set once enable_if_configured() has patched LdapAttr.__init__, so a
# second call in the same process is a no-op rather than a double
# patch.
_original_init = None


# ---- _limit ----
def _limit():
    """Return the configured value cap, or None if unset."""
    value = os.environ.get(ENV_VAR)
    return int(value) if value else None


# ---- _capped_init ----
def _capped_init(self, attr, vals, ldap_syntax, xsi_type='xsd:string'):
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
    limit = _limit()
    if limit is not None and hasattr(vals, '__iter__') \
            and not isinstance(vals, (str, bytes)):
        vals = list(vals)[:limit]
    _original_init(self, attr, vals, ldap_syntax, xsi_type)


# ---- enable_if_configured ----
def enable_if_configured():
    """
    Patch LdapAttr.__init__ if ADWS_DEBUG_MAX_ATTR_VALUES is set.

    Safe to call every time main.py starts. Does nothing when the
    environment variable is unset, and patches at most once per
    process when it is set.
    """
    global _original_init
    limit = _limit()
    if limit is None:
        return
    if _original_init is not None:
        return
    _original_init = sambautils.LdapAttr.__init__
    sambautils.LdapAttr.__init__ = _capped_init
    log.warning(
        'ADWS_DEBUG_MAX_ATTR_VALUES=%s -- every multi-valued attribute '
        'is being truncated for size bisection. This is debug tooling, '
        'not a fix. Unset %s before any real use.',
        limit, ENV_VAR,
    )
