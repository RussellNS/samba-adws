"""
Stand-in for samba.dsdb.

sambautils.py imports this module but does not currently reference
anything from it. The two flags below are the ones the DC-qualification
logic in render_pull() is reasoning about (see DC_QUAL_ATTRS), and are
provided so that logic can be expressed in terms of named constants
rather than magic numbers when it is next touched.
"""

# userAccountControl bit identifying a domain controller computer account
UF_SERVER_TRUST_ACCOUNT = 0x2000

# Well-known RID of the Domain Controllers group (primaryGroupID)
DOMAIN_RID_DCS = 516
