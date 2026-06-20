# Active Directory Web Services (ADWS) Proxy for Samba

> [!NOTE]
> This is a fork of the [Catalyst Samba-ADWS Project on GitLab](https://gitlab.com/catalyst-samba/samba-adws) as referenced on the [AD PowerShell compatibility](https://wiki.samba.org/index.php/ADWS_/_AD_Powershell_compatibility) page on [SambaWiki](https://wiki.samba.org/index.php/Main_Page). The original project (2018) targeted an older Samba release and Python 2.x. The Cayalyst Samba-ADWS Project does not work in 2026. The goal of this fork is to modernize it — Python 3.x, current Samba (4.x), and meaningful compatibility with the AD PowerShell module (RSAT) as shipped with Windows 10/11 and Windows Server 2019/2022/2025.

---

## Background

Active Directory Web Services (ADWS) is the protocol that Windows' **AD PowerShell module** (RSAT) uses to talk to a Domain Controller. It runs on port **9389** over a WCF `net.tcp` binding and wraps LDAP operations in SOAP envelopes encoded in WCF binary XML.

Samba ships with an ADWS stub, but it is not functional for modern PowerShell. This proxy sits
between PowerShell and Samba's LDAP layer, speaking ADWS on port 9389 to the client and
translating requests into LDB queries against the running Samba AD DC.

The intended deployment is alongside the [samba-ad-dc-lab](https://github.com/RussellNS/samba-ad-dc-lab) container — a single Docker image that provides a fully provisioned Samba AD DC plus this ADWS proxy, making the combined stack addressable by standard Windows RSAT tools without any modification to the Windows client.

---

## What Works

The Catalyst Samba-ADWS Project was a proof of concept (POC).  In this POC, it was hard coded to only pull computer objects.  So `Get-ADComputer` worked with minimal functionality (i.e. it might pull some computer properties for a computer object in AD but fail on others, especially those with non-escaped XML characters in the return).

In the first release (v1.0.0) of this repo, the goal, as stated earlier, was just to get the previous repo working with current packages (Python 3.x, Samba 4.x, ect.).  That goal was met.

The work on this project continues with updates in the ‘master’ branch. Currently, the following AD PowerShell cmdlets have been validated as working using this proxy:

| Cmdlet                     | Status | Notes                                              |
|----------------------------|--------|----------------------------------------------------|
| `Get-ADUser`               | ✅      | Filter and Identity forms                          |
| `Get-ADComputer`           | ✅      | Filter and Identity forms, `-Properties *`         |
| `Get-ADGroup`              | ✅      | Filter and Identity forms                          |
| `Get-ADOrganizationalUnit` | ✅      | Filter and Identity forms                          |
| `Get-ADObject`             | ✅      | Filter, Identity (by GUID/DN), explicit properties |
| `Get-ADRootDSE`            | ✅      |                                                    |
| `Get-ADDomainController`   | 🔄     | In progress                                        |
| `Get-ADDomain`             | 🔄     | In progress                                        |
| `Get-ADForest`             | 🔄     | In progress                                        |

Write operations (`New-AD*`, `Set-AD*`, `Remove-AD*`) are not implemented.

---

## Architecture

```
Windows Client (RSAT / AD PowerShell)
        │
        │  net.tcp port 9389  (WCF binary XML over NMF/NNS)
        ▼
┌─────────────────────────┐
│     ADWS Proxy          │  main.py + sambautils.py
│  (this repository)      │  Jinja2 XML templates
└─────────┬───────────────┘
          │  Python-LDB (direct in-process)
          ▼
┌─────────────────────────┐
│   Samba AD DC           │  samba-ad-dc-lab container
│   (LDB / sam.ldb)       │
└─────────────────────────┘
```

The proxy implements three ADWS endpoints:

- `/Windows/Resource` — WS-Transfer Get (single-object lookup by GUID or DN)
- `/Windows/Enumeration` — WS-Enumeration Enumerate + Pull (directory searches)
- `/Windows/TopologyManagement` — CustomActions (DC/domain/forest topology queries)

Authentication is handled via GSSAPI/Kerberos negotiate, delegated to the underlying Samba stack.

---

## Deployment

This proxy is designed to run as a supervised process inside the same container as the Samba AD DC, managed by `supervisord`. The `samba-ad-dc-lab` repository provides the complete Dockerfile and Compose configuration. Standalone deployment is possible but requires a reachable Samba LDB at the standard path (`/var/lib/samba/private/sam.ldb`).

### Standalone (for development)

```bash
git clone https://github.com/RussellNS/samba-adws
cd samba-adws
pip3 install -r requirements.txt
python3 main.py --bind 0.0.0.0 --port 9389
```

Samba must already be provisioned and running. The proxy connects to LDB directly via the `python3-samba` library — no LDAP socket is involved.

### Inside the samba-ad-dc-lab container

The combined container handles startup ordering automatically. ADWS starts after Samba's AD DC enters its running state. No additional configuration is required.

---

## Protocol Notes

### WCF net.tcp / NMF

ADWS uses Microsoft's `net.tcp` transport, which layered the following protocols:

- **MC-NMF** — .NET Message Framing, the binary framing layer on top of TCP
- **MC-NMFTB** — .NET Message Framing TCP Binding, which adds the preamble/handshake
- **MS-NNS** — .NET NegotiateStream, the GSSAPI/Kerberos negotiate wrapper

This proxy uses the WCF library inherited from the upstream catalyst-samba project to handle framing and negotiate, allowing `sambautils.py` to work purely with decoded XML strings.

### SOAP/XML encoding

ADWS encodes SOAP envelopes in **WCF binary XML** — a compact binary representation of XML that uses a dictionary of well-known element/attribute names to reduce wire size. The proxy decodes incoming binary XML to text XML for processing and re-encodes responses before sending. The `wcf/` directory contains the encoder/decoder inherited from the upstream project.

---

## Development Notes

### File layout

```
main.py                     Entry point, request routing, WCF framing
adws/
  sambautils.py             Core backend: LDB queries, response rendering
  xmlutils.py               XML helpers, namespace map, request/response logging
  templates/
    Pull.xml                WS-Enumeration PullResponse
    Enumerate.xml           WS-Enumeration EnumerateResponse
    transfer-Get.xml        WS-Transfer GetResponse (object lookup)
    root-DSE.xml            Root DSE GetResponse
    msDS-PortLDAP.xml       Port capability GetResponse
    GetADDomainController.xml   Topology CustomAction response
    topology-action.xml     Generic topology handshake response
wcf/                        WCF binary XML encoder/decoder (upstream)
nettcp/                     NMF/NNS framing (upstream)
```

### Request/response logging

During development, every request/response pair is written to `/tmp/<n>.xml` inside the container, where `n` increments with each exchange in a session. This makes it straightforward to inspect the raw SOAP XML for any cmdlet:

```bash
docker exec samba-ad-dc cat /tmp/0.xml   # first exchange
docker exec samba-ad-dc cat /tmp/1.xml   # second exchange
# etc.
```

### Adding support for a new cmdlet

Most AD PowerShell cmdlets use standard Enumerate + Pull, so if the LDAP filter and attribute
list are well-formed, they will work without any code changes. The cases that require explicit
handling are:

1. **TopologyManagement CustomActions** — `Get-ADDomainController`, `Get-ADDomain`, `Get-ADForest`. These use a bespoke request/response format defined in `MS-ADCAP` and require a dedicated handler in `render_topology_action()`.
2. **WS-Transfer Get with no AttributeTypeList** — triggered by `-Properties *` on an Identity-based lookup. Handled by `render_transfer_get()` with `fetch_all=True`.
3. **Schema queries** — some cmdlets pre-flight with `attributeSchema`/`classSchema` Enumerate requests to build a local attribute map. These fall through the standard Enumerate/Pull path and work automatically.

---

## License

MIT — see [LICENSE](LICENSE).

The upstream WCF/NMF library (`wcf/`, `nettcp/`) retains its original license from the [catalyst-samba/samba-adws](https://gitlab.com/catalyst-samba/samba-adws) project.
