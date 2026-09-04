# get-adobject-attributeschema-page1

Raw SOAP capture from a live container run, 2026-09-04:

```powershell
Get-ADObject -SearchBase (Get-ADRootDSE -Server dc1.vlab.test:9389).schemaNamingContext `
  -LDAPFilter '(objectClass=attributeSchema)' `
  -Server dc1.vlab.test:9389
```

`0.xml` — WS-Transfer Get, Root DSE lookup.
`1.xml` — WS-Enumeration Pull, 256 `attributeSchema` objects (one page).
`2.xml` — WS-Transfer Get, `msDS-PortLDAP` lookup.

**Not a `replay.Recording` fixture** — `calls.jsonl` came back empty due
to a truncation race in `adws/record.py` (fixed the same day this was
captured; see that file's change log), so there is no LDB-call-level
data to replay through `tests/replay.py`. These are the raw pre-WCF-
encoding SOAP exchanges only, kept as the evidence for the confirmed
bug below rather than as a replayable test fixture. A future capture
with the fix in place would carry `calls.jsonl` and could feed
`replay.Recording.from_dir()` directly.

## What this proves

`1.xml` line 104:

```xml
<addata:objectClass LdapSyntax="1.3.6.1.4.1.1466.115.121.1.15">
```

Every one of the 256 objects in the response has this same malformed
`LdapSyntax` value on `objectClass` — a raw OID string where every
other attribute gets a name (`UnicodeString`, `OctetString`, ...). This
is the confirmed root cause of the `Get-ADObject` call above failing
with `ADServerDownException` on the Windows client: the proxy sent a
well-formed response, but with content the AD PowerShell client's WCF
deserializer didn't recognize, causing it to reject the response,
retry identically on a new connection, and eventually give up.

Fixed in `sambautils.py` v1.1.15 — see `tests/test_syntax_registry.py`
and `tests/test_render_pull.py::test_object_class_is_rendered_with_a_real_syntax_name_when_requested`
for the regression coverage.
