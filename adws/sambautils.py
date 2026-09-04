"""
------------------------------------------------------------------------------
Script Name:      sambautils.py
Script Author:    Neal Russell
Author's Company: N/A (fork of gitlab.com/catalyst-samba/samba-adws)
Script Created:   2024-Jan-01
Script Modified:  2026-Sep-04
Script Version:   1.1.15
Script Purpose:   Core AD backend for the samba-adws ADWS proxy. Provides
                  attribute models, Jinja2 template rendering, and the
                  SamDBHelper class which connects to the local Samba LDB
                  database and handles all LDAP queries.

Script Desc:      This module is imported by main.py and is never executed
                  directly (except in interactive/debug mode -- see the
                  __main__ block at the bottom of this file).

                  1.  ldb constant polyfill -- getattr() guards against
                      missing OID constants across Samba versions.

                  2.  XML_ILLEGAL_CHARS -- compiled regex that matches
                      characters which are valid UTF-8 but illegal in
                      XML 1.0 (e.g. \x01 SOH). Used by LdapAttr to
                      decide whether a decoded string must be
                      base64-encoded before it is placed into XML.

                  3.  SchemaSyntax / registry -- maps LDAP OIDs to the
                      LdapSyntax names and XSD types that Windows expects
                      in ADWS responses.

                  4.  LdapAttr -- wraps one LDB attribute and its values.
                      Handles bytes-to-string decoding, base64 fallback
                      for binary data, and XML illegal-character detection.
                      Renders itself to XML via LDAP_ATTR_TEMPLATE.

                  5.  SyntheticAttr -- wraps computed attributes that do
                      not exist in LDB but are required by the ADWS
                      protocol (objectReferenceProperty, distinguishedName,
                      etc.). Renders itself to XML via
                      SYNTHETIC_ATTR_TEMPLATE.

                  6.  SamDBHelper -- subclasses SamDB to add ADWS-specific
                      render_*() methods. Each render method handles one
                      ADWS SOAP action: Root DSE lookup, WS-Transfer Get,
                      WS-Enumeration Enumerate, and WS-Enumeration Pull.

------------------------------------------------------------------------------
Execution Context: Imported by main.py. Not a standalone executable.
                   Requires a running Samba AD DC with a readable sam.ldb.
------------------------------------------------------------------------------
Change Log:
  1.0.0  - Python 3.13 compatibility refactor. ldb constant polyfill,
           bytes/binary handling, SamDB subclass pattern.
  1.1.0  - Generic object class fix. render_pull() now passes
           (object_class, attrs) tuples to Pull.xml so that any AD
           object type (user, group, OU, etc.) is wrapped in the
           correct <addata:X> tag instead of <addata:computer>.
           Fixes Get-ADUser, Get-ADGroup, Get-ADOU, Get-ADObject.
  1.1.1  - XML 1.0 illegal character fix. LdapAttr now detects
           control characters (e.g. \x01) that are valid UTF-8 but
           illegal in XML, and base64-encodes those values rather
           than letting lxml raise XMLSyntaxError and crash the
           connection handler. Fixes Get-ADGroup failure.
  1.1.2  - TopologyManagement support. Added render_topology_action()
           to SamDBHelper and topology-action.xml template to handle
           the WS-CustomActions capability handshake that Get-ADDomain,
           Get-ADForest, and Get-ADDomainController send before
           fetching data. Fixes ADServerDownException on those cmdlets.
  1.1.3  - Wildcard attribute fix. PowerShell sends 'ad:all' as the
           last SelectionProperty when the caller uses -Properties *.
           Previously 'all' was passed as a literal LDB attribute name
           which LDB silently ignored, causing sparse results. When
           'ad:all' is detected, render_pull() now passes attrs=None
           to the LDB search (returning all attributes) and passes an
           empty attr_names list to build_attr_list() so all returned
           attributes are rendered in the response. Fixes Get-ADDomain,
           Get-ADForest, and Get-ADDomainController data population.
  1.1.4  - Empty BaseObject fix. Get-ADDomainController sends an empty
           string as the LDAP BaseObject, intending a global subtree
           search of the entire directory. Samba's LDB partition module
           rejects an empty base DN with error 32. render_pull() now
           falls back to self.domain_dn() when BaseObject is empty,
           matching real Windows DC behaviour. Fixes the LdbError crash
           on Get-ADDomainController.
  1.1.5  - GetADDomainController data response. Unlike GetADDomain and
           GetADForest, the GetADDomainController topology action is a
           data request, not a handshake. The request body contains an
           NtdsSettingsDN identifying the DC to look up. Added
           render_get_dc() to SamDBHelper which queries the nTDSDSA
           and server objects from LDB and renders the full DC property
           set into GetADDomainController.xml. render_topology_action()
           now dispatches to render_get_dc() for this action instead
           of returning an empty acknowledgement.
  1.1.6  - ServerObjectGuid GUID source fix. v1.1.5 used the GUID of
           the server topology object (CN=DC1,CN=Servers,...) for
           ServerObjectGuid. PowerShell expects the GUID of the
           computer account object (CN=DC1,OU=Domain Controllers,...)
           to correlate the topology response with the Pull result.
           render_get_dc() now performs a third LDB lookup via the
           serverReference DN to retrieve the correct GUID.
  1.1.7  - Multi-NC search for empty BaseObject. The v1.1.4 fallback
           for an empty BaseObject searched only the domain NC, which
           caused Get-ADDomainController to return only the computer
           object and miss the nTDSDSA and server objects in the
           Configuration NC. render_pull() now searches the domain NC
           and Configuration NC separately when BaseObject is empty
           and merges the results, matching the global directory
           search a real Windows DC performs.
  1.1.8  - Fix ldb.Result.msgs read-only error. v1.1.7 attempted to
           assign to last_result.msgs to carry merged results through
           the existing loop, but ldb.Result.msgs is a read-only C
           attribute. The multi-NC branch now builds the objects list
           directly from all_msgs without using a carrier result
           object, bypassing the paged_results control path entirely
           (multi-NC results are small and do not need paging).
  1.1.9  - Inject DC-qualification attributes into computer Pull
           responses. PowerShell requires userAccountControl and
           primaryGroupID to confirm a computer object is a DC
           account. These attributes are never in the narrow 6-attr
           selection that Get-ADDomainController sends, so PowerShell
           receives the computer object but cannot determine it is a
           DC. render_pull() now injects these two attributes into
           any computer object in a Pull response when they are
           present in LDB but absent from the requested attr list.
  1.1.10 - Fix DC-qualification attribute injection. v1.1.9 checked
           whether userAccountControl and primaryGroupID were present
           in the LDB result msg, but they were never fetched because
           they were not in attrs_to_fetch. The fix always appends
           these two attributes to attrs_to_fetch so LDB returns them,
           and build_attr_list() renders them for computer objects
           regardless of whether the client requested them.
  1.1.11 - Fix InvocationId in GetADDomainControllerResponse. The
           field was populated with the nTDSDSA invocationId attribute
           (a replication GUID), but PowerShell uses the nTDSDSA
           objectGUID to correlate the topology response with the
           nTDSDSA Pull result. Since they differ, PowerShell could
           not match the two responses and threw
           ADIdentityNotFoundException. render_get_dc() now reads
           objectGUID from the nTDSDSA object and decodes it as the
           InvocationId value.
  1.1.12 - Populate OperatingSystem fields in
           GetADDomainControllerResponse. The OS fields were hardcoded
           as nil/empty. render_get_dc() now fetches operatingSystem,
           operatingSystemVersion, operatingSystemHotfix, and
           operatingSystemServicePack from the computer account object
           and includes them in the response body. Empty/absent values
           render as nil per the existing template pattern.
  1.1.13 - Fix ad:all wildcard in render_transfer_get(). When
           PowerShell sends -Properties * on a WS-Transfer Get (e.g.
           Get-ADObject -Identity <GUID> -Properties *), the last
           AttributeType entry is 'ad:all'. render_transfer_get()
           was passing the literal string 'all' to LDB as an attr
           name, causing LDB to return internal fields including
           'controls' which PowerShell rejects with ArgumentException.
           render_transfer_get() now applies the same ad:all wildcard
           detection as render_pull(): strips 'all' from attr_names
           and passes attrs=None to LDB to return all real attributes,
           then passes an empty list to build_attr_list() to render
           everything LDB returned.
  1.1.14 - Fix WS-Transfer Get with no AttributeTypeList. Some Get
           requests (e.g. Get-ADObject -Identity <GUID> -Properties *)
           send only LDAP controls in the body with no AttributeType
           elements. render_transfer_get() was passing attrs=[] to LDB
           which caused it to return all attributes including internal
           LDB fields. The fix treats an empty AttributeType_List the
           same as fetch_all: pass attrs=None to LDB and an empty list
           to build_attr_list() so all real attributes are returned
           but internal fields are filtered out by the schema lookup.
  1.1.15 - Fix LDAP syntax OID registry collision that broke
           Get-ADObject outright. The nine SYNTAX_* constants were
           sourced via getattr(ldb, 'SYNTAX_X', 1); python3-ldb does
           not export SYNTAX_LARGE_INTEGER, SYNTAX_OBJECT_IDENTIFIER or
           SYNTAX_GENERALIZED_TIME (confirmed against a live container,
           2026-09-04), so all three silently collided on the fallback
           value 1 in OID_SCHEMA_SYNTAX_DICT. objectClass's real syntax
           is Object Identifier, and objectClass is in Get-ADObject's
           default property set; a live capture showed every object in
           a Pull response rendering
           <addata:objectClass LdapSyntax="1.3.6.1.4.1.1466.115.121.1.15">
           -- the unknown-attribute fallback's literal OID string,
           reached because the real syntax was unregistered. The AD
           PowerShell client silently rejected every response, retried
           identically, and reported ADServerDownException. Fixed by
           hardcoding all nine syntax OIDs as literals (they are RFC
           4517 / MS-ADTS protocol constants, not Samba version
           details, so there was never a good reason to source them
           from the `ldb` module) and by changing the unknown-attribute
           fallback to emit the name 'UnicodeString' instead of an OID
           string, matching every other registry entry.
------------------------------------------------------------------------------
To Do List:
  *  Implement WS-Transfer Put (Set-AD* cmdlets).
  *  Implement WS-Transfer Create / Delete (New-AD* / Remove-AD*).
  *  Implement MS-ADCAP custom operations (password change, unlock, etc.).
------------------------------------------------------------------------------
"""
from __future__ import print_function, absolute_import
import ldb
import re
import samba
from samba.samdb import SamDB
from samba.param import LoadParm
from samba.auth import system_session
from samba import dsdb
from os.path import abspath, dirname, join
import jinja2
from jinja2 import Environment, FileSystemLoader, select_autoescape
from base64 import b64encode



# ========================================================================== #
# LDAP Syntax OID Constants                                                  #
# ========================================================================== #
# These are RFC 4517 standard syntax OIDs (SYNTAX_LARGE_INTEGER is the
# one Microsoft-specific exception -- AD's Integer8/LargeInteger syntax,
# MS-ADTS 3.1.1.2.3). They are protocol constants, not Samba
# implementation details, so they are hardcoded here directly rather
# than sourced from the `ldb` module.
#
# CHANGE LOG NOTE (formerly a getattr(ldb, NAME, 1) polyfill):
# This used to read these values off the `ldb` module via
# getattr(ldb, 'SYNTAX_X', 1), on the theory that python3-ldb might not
# expose every constant on every Samba version. In practice python3-ldb
# does not expose SYNTAX_LARGE_INTEGER, SYNTAX_OBJECT_IDENTIFIER or
# SYNTAX_GENERALIZED_TIME AT ALL (confirmed live, 2026-09-04, against
# Samba/python3-ldb on Python 3.13.5) -- so all three silently fell back
# to the same placeholder value of 1 and collided in
# OID_SCHEMA_SYNTAX_DICT, which is keyed by this value. Only the last
# of the three defined in SCHEMA_SYNTAX_LIST was ever reachable.
#
# objectClass's real LDAP syntax IS Object Identifier, and objectClass
# is in the default property set of Get-ADObject, so this collision put
# an unresolvable syntax on the single most fundamental AD attribute.
# build_attr_list()'s fallback for an unresolvable syntax renders the
# literal fallback OID string as the LdapSyntax value instead of a name
# -- confirmed via a live capture to render
# <addata:objectClass LdapSyntax="1.3.6.1.4.1.1466.115.121.1.15">
# on every object in a Pull response, which is not a well-known token
# the AD PowerShell client's WCF deserializer recognises. That is the
# confirmed cause of Get-ADObject returning ADServerDownException
# against a live DC: the proxy sent a response every time, but the
# client rejected it, retried identically, and gave up.

SYNTAX_INTEGER           = '1.3.6.1.4.1.1466.115.121.1.27'
SYNTAX_LARGE_INTEGER     = '1.2.840.113556.1.4.906'
SYNTAX_BOOLEAN           = '1.3.6.1.4.1.1466.115.121.1.7'
SYNTAX_DIRECTORY_STRING  = '1.3.6.1.4.1.1466.115.121.1.15'
SYNTAX_OCTET_STRING      = '1.3.6.1.4.1.1466.115.121.1.40'
SYNTAX_DN                = '1.3.6.1.4.1.1466.115.121.1.12'
SYNTAX_UTC_TIME          = '1.3.6.1.4.1.1466.115.121.1.53'
SYNTAX_GENERALIZED_TIME  = '1.3.6.1.4.1.1466.115.121.1.24'
SYNTAX_OBJECT_IDENTIFIER = '1.3.6.1.4.1.1466.115.121.1.38'



# ========================================================================== #
# XML 1.0 Illegal Character Pattern                                          #
# ========================================================================== #
# XML 1.0 prohibits certain control characters even when the string is
# otherwise valid UTF-8. A value containing \x01 (SOH), \x02, \x03,
# etc. will cause lxml to raise XMLSyntaxError when it tries to parse
# the rendered XML, crashing the connection handler before a response
# can be sent to PowerShell. The pattern below matches any character
# that is illegal in XML 1.0.
#
# Legal character ranges per https://www.w3.org/TR/xml/#charsets :
#   #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] |
#   [#x10000-#x10FFFF]
#
# Any character NOT in those ranges must be base64-encoded to keep
# the generated XML well-formed. Used in LdapAttr.__init__().

XML_ILLEGAL_CHARS = re.compile(
    r'[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]'
)



# ========================================================================== #
# Jinja2 Template Engine Setup                                               #
# ========================================================================== #
# Templates live in the adws/templates/ directory alongside this file.
# autoescape is enabled for XML to prevent injection through AD attribute
# values that contain characters like <, >, or &. The |safe filter in
# templates is used deliberately only for pre-rendered XML fragments
# that we have already escaped ourselves (LdapAttr.to_xml() /
# SyntheticAttr.to_xml()).

HERE      = dirname(abspath(__file__))
TEMPLATES = join(HERE, 'templates')

ENV = Environment(
    loader=FileSystemLoader(TEMPLATES),
    autoescape=select_autoescape(['xml']),
)



# ========================================================================== #
# LDAP Scope Mapping                                                         #
# ========================================================================== #
# PowerShell AD cmdlets express search scope using ADWS/LDAP dialect
# strings ('base', 'onelevel', 'subtree'). This dict maps them to the
# integer constants that python-ldb expects on search() calls.
# Reference: https://msdn.microsoft.com/en-us/library/dd340513.aspx

SCOPE_ADLQ_TO_LDB = {
    'base':     ldb.SCOPE_BASE,
    'onelevel': ldb.SCOPE_ONELEVEL,
    'subtree':  ldb.SCOPE_SUBTREE,
}



# ========================================================================== #
# DC Qualification Attributes                                                #
# ========================================================================== #
# These attributes are required for PowerShell to identify a computer
# object as a domain controller rather than a workstation. They are
# always fetched from LDB and injected into Pull responses for computer
# objects even when the client did not explicitly request them.
#   userAccountControl - must have UF_SERVER_TRUST_ACCOUNT (0x1000)
#   primaryGroupID     - must be 516 (Domain Controllers group)

DC_QUAL_ATTRS = ['userAccountControl', 'primaryGroupID']



# ========================================================================== #
# Root DSE Sentinel GUID                                                     #
# ========================================================================== #
# The Root DSE is the top-level entry of an LDAP directory (like the
# "/" of a filesystem). It has no real GUID in AD; Windows uses this
# well-known fake GUID as a handle to request it. We match on this to
# decide whether a Get request is asking for the Root DSE or a real
# object.

ROOT_DSE_GUID = '11111111-1111-1111-1111-111111111111'



# ========================================================================== #
# Schema Syntax Registry                                                     #
# ========================================================================== #
# SchemaSyntax encapsulates the relationship between an LDAP OID, the
# human-readable LdapSyntax name Windows expects in responses (e.g.
# 'UnicodeString'), and the XSD type used in the SOAP envelope (e.g.
# 'xsd:string' or 'xsd:base64Binary'). Every LDAP attribute type has
# one of these.
#
# SCHEMA_SYNTAX_LIST contains one entry per syntax that appears in a
# standard Samba AD schema. OID_SCHEMA_SYNTAX_DICT is keyed by OID for
# O(1) lookup during attribute serialisation.
#
# ROOT_DSE_ATTRS maps Root DSE attribute names to their syntax OIDs.
# The Root DSE is a virtual pseudo-entry with no schema record in LDB,
# so its syntaxes are defined statically here per the ADWS spec
# (MS-ADDM Appendix A <4>).
# Reference: https://msdn.microsoft.com/en-us/library/dd340513.aspx

class SchemaSyntax(object):

    def __init__(self, oid, ldap_syntax, xsi_type='xsd:string'):
        # OID that uniquely identifies this LDAP syntax in the schema
        self.oid         = oid
        # Human-readable name sent in the LdapSyntax XML attribute
        self.ldap_syntax = ldap_syntax
        # XSD type sent in the xsi:type XML attribute for each value
        self.xsi_type    = xsi_type

    def render(self):
        return 'xml'



SCHEMA_SYNTAX_LIST = [
    SchemaSyntax(SYNTAX_INTEGER,           'Integer'),
    SchemaSyntax(SYNTAX_LARGE_INTEGER,     'LargeInteger'),
    SchemaSyntax(SYNTAX_BOOLEAN,           'Boolean'),
    SchemaSyntax(SYNTAX_DIRECTORY_STRING,  'UnicodeString'),
    SchemaSyntax(SYNTAX_OCTET_STRING,      'OctetString',
                 xsi_type='xsd:base64Binary'),
    SchemaSyntax(SYNTAX_DN,                'DSDNString'),
    SchemaSyntax(SYNTAX_UTC_TIME,          'UTCTimeString'),
    SchemaSyntax(SYNTAX_GENERALIZED_TIME,  'GeneralizedTimeString'),
    SchemaSyntax(SYNTAX_OBJECT_IDENTIFIER, 'ObjectIdentifier'),
]

OID_SCHEMA_SYNTAX_DICT = {obj.oid: obj for obj in SCHEMA_SYNTAX_LIST}

ROOT_DSE_ATTRS = {
    'configurationNamingContext':    SYNTAX_DN,
    'currentTime':                   SYNTAX_GENERALIZED_TIME,
    'defaultNamingContext':          SYNTAX_DN,
    'dnsHostName':                   SYNTAX_DIRECTORY_STRING,
    'domainControllerFunctionality': SYNTAX_INTEGER,
    'domainFunctionality':           SYNTAX_INTEGER,
    'dsServiceName':                 SYNTAX_DN,
    'forestFunctionality':           SYNTAX_INTEGER,
    'highestCommittedUSN':           SYNTAX_LARGE_INTEGER,
    'isGlobalCatalogReady':          SYNTAX_BOOLEAN,
    'isSynchronized':                SYNTAX_BOOLEAN,
    'ldapServiceName':               SYNTAX_DIRECTORY_STRING,
    'namingContexts':                SYNTAX_DN,
    'rootDomainNamingContext':       SYNTAX_DN,
    'schemaNamingContext':           SYNTAX_DN,
    'serverName':                    SYNTAX_DN,
    'subschemaSubentry':             SYNTAX_DN,
    'supportedCapabilities':         SYNTAX_OBJECT_IDENTIFIER,
    'supportedControl':              SYNTAX_OBJECT_IDENTIFIER,
    'supportedLDAPVersion':          SYNTAX_INTEGER,
    # vendorName is Samba-only and intentionally omitted from ADWS
    # responses because it is not part of the Windows AD schema and
    # confuses clients.
}



# ========================================================================== #
# LdapAttr                                                                   #
# ========================================================================== #
# Wraps one LDAP attribute and its values, ready to be serialised into
# the ADWS XML response format. LDAP_ATTR_TEMPLATE is the inline Jinja2
# template used by LdapAttr.to_xml(). It renders the attribute with its
# LdapSyntax annotation and one <ad:value> element per value. The
# 'addata:' namespace prefix marks this as a real LDAP attribute (vs.
# 'ad:' which is used for synthetic attributes).
#
# Bytes handling (LdapAttr.__init__):
#   LDB returns all attribute values as bytes objects. We attempt UTF-8
#   decode first (covers the vast majority of string attributes).
#
#   If the decoded string contains XML 1.0 illegal characters (e.g.
#   \x01 SOH, which appears in some Samba group attributes), lxml will
#   raise XMLSyntaxError when it tries to parse the rendered XML,
#   crashing the connection handler before any response is sent. We
#   detect this with XML_ILLEGAL_CHARS and base64-encode those values.
#
#   If UTF-8 decode fails entirely (SIDs, GUIDs, certificate blobs,
#   nTSecurityDescriptor, etc.), we base64-encode the raw bytes. In
#   both base64 cases xsi_type is updated to 'xsd:base64Binary' so
#   Windows knows to decode the value on its end.

LDAP_ATTR_TEMPLATE = jinja2.Template("""
<addata:{{obj.attr}} LdapSyntax="{{obj.ldap_syntax}}">
   {%- for val in obj.vals %}
   <ad:value xsi:type="{{obj.xsi_type}}">{{val}}</ad:value>
   {%- endfor %}
</addata:{{obj.attr}}>""".strip())



class LdapAttr(object):

    def __init__(self, attr, vals, ldap_syntax, xsi_type='xsd:string'):
        # LDAP display name of the attribute, e.g. 'sAMAccountName'
        self.attr        = attr
        self.ldap_syntax = ldap_syntax

        # xsi_type must be namespace-qualified (e.g. 'xsd:string')
        assert ':' in xsi_type
        self.xsi_type = xsi_type

        # ldb.MessageElement is a read-only C-level iterable. Convert
        # to a plain Python list so we can index and modify freely.
        if hasattr(vals, '__iter__') and not isinstance(vals, (str, bytes)):
            self.vals = list(vals)
        else:
            self.vals = [vals]

        # Walk every value and handle bytes objects.
        for i, v in enumerate(self.vals):
            if isinstance(v, bytes):
                try:
                    decoded = v.decode('utf-8')

                    # Even valid UTF-8 may contain control characters
                    # illegal in XML 1.0 (e.g. \x01 SOH). Detect them
                    # with XML_ILLEGAL_CHARS and base64-encode if found.
                    if XML_ILLEGAL_CHARS.search(decoded):
                        self.vals[i] = b64encode(v).decode('ascii')
                        self.xsi_type = 'xsd:base64Binary'
                    else:
                        self.vals[i] = decoded

                except UnicodeDecodeError:
                    # Truly binary data that cannot be decoded as UTF-8.
                    # b64encode() returns bytes; decode to ASCII str so
                    # Jinja2 can render it without type errors.
                    self.vals[i] = b64encode(v).decode('ascii')

                    # CRITICAL: update xsi_type so Windows knows to
                    # base64-decode this value. If left as 'xsd:string'
                    # Windows interprets the base64 as literal text,
                    # causing attribute parsing failures on the client.
                    self.xsi_type = 'xsd:base64Binary'

    def to_xml(self):
        """Render this attribute as an XML fragment string."""
        return LDAP_ATTR_TEMPLATE.render({'obj': self})



# ========================================================================== #
# SyntheticAttr                                                              #
# ========================================================================== #
# Wraps computed attributes that do not exist in LDB but are required
# by the ADWS protocol. They are injected into responses by the render_*
# methods of SamDBHelper. They use the 'ad:' namespace prefix rather
# than 'addata:'.
# Reference: https://msdn.microsoft.com/en-us/library/dd340577.aspx
#
#   objectReferenceProperty    - The GUID used as the ADWS object handle
#   container-hierarchy-parent - GUID of the parent container
#   distinguishedName          - Full LDAP DN string
#   relativeDistinguishedName  - RDN component only (e.g. 'CN=MyPC')
#
# The assertion in __init__ enforces that only known synthetic attribute
# names are used, catching typos and protocol violations early rather
# than producing silently malformed XML responses.

SYNTHETIC_ATTRS = {
    'objectReferenceProperty',
    'container-hierarchy-parent',
    'distinguishedName',
    'relativeDistinguishedName',
}

SYNTHETIC_ATTR_TEMPLATE = jinja2.Template("""
<ad:{{obj.attr}}>
   {%- for val in obj.vals %}
   <ad:value xsi:type="{{obj.xsi_type}}">{{val}}</ad:value>
   {%- endfor %}
</ad:{{obj.attr}}>""".strip())



class SyntheticAttr(object):

    def __init__(self, attr, vals, xsi_type='xsd:string'):
        assert attr in SYNTHETIC_ATTRS, \
            f"'{attr}' is not a known synthetic attribute"
        self.attr     = attr
        self.xsi_type = xsi_type

        # Normalise to list regardless of input type
        if not isinstance(vals, list):
            vals = [vals]
        self.vals = list(vals)

        # Apply the same bytes-handling logic as LdapAttr
        for i, v in enumerate(self.vals):
            if isinstance(v, bytes):
                try:
                    self.vals[i] = v.decode('utf-8')
                except UnicodeDecodeError:
                    self.vals[i] = b64encode(v).decode('ascii')
                    self.xsi_type = 'xsd:base64Binary'

    def to_xml(self):
        """Render this synthetic attribute as an XML fragment string."""
        return SYNTHETIC_ATTR_TEMPLATE.render({'obj': self})



# ========================================================================== #
# Helper Functions                                                           #
# ========================================================================== #

def render_template(template_name, **kwargs):
    """
    Load and render a Jinja2 template from the templates/ directory.

    All keyword arguments are passed directly into the template context,
    making them available as variables inside the XML template files.
    """
    template = ENV.get_template(template_name)
    return template.render(**kwargs)



def is_rootDSE(guid):
    """
    Return True if the given GUID string is the sentinel Root DSE GUID.
    """
    return guid.strip() == ROOT_DSE_GUID



def get_rdn(dn):
    """
    Extract the Relative Distinguished Name from an ldb.Dn object.

    For example, given 'CN=MyComputer,OU=Servers,DC=corp,DC=local' this
    returns 'CN=MyComputer'. Returns an empty string if either component
    is missing (e.g. for the Root DSE which has no RDN).
    """
    rdn_name  = dn.get_rdn_name()
    rdn_value = dn.get_rdn_value()
    if rdn_name and rdn_value:
        return '%s=%s' % (rdn_name, rdn_value)
    return ''



# ========================================================================== #
# SamDBHelper                                                                #
# ========================================================================== #
# Subclasses SamDB (the Samba Python binding to the LDB directory
# database) to add ADWS-specific query helpers and XML rendering methods.
#
# By subclassing rather than wrapping, we get direct access to all SamDB
# methods (search, add, delete, modify, etc.) without delegation
# boilerplate, while still being able to add our own methods alongside.
#
# SamDB connects to the local sam.ldb file using a system session
# (root-level Kerberos credentials), which is why main.py must be run
# as root/sudo.

class SamDBHelper(SamDB):

    def __init__(self):
        # LoadParm reads smb.conf to find the path to sam.ldb and
        # domain info. load_default() picks up the system smb.conf.
        lp = LoadParm()
        lp.load_default()
        # system_session() provides root-equivalent LDB credentials so
        # we can read all attributes including privileged ones (password
        # hashes, security descriptors, etc.).
        SamDB.__init__(self, lp=lp, session_info=system_session())



    def search_scope_base(self, *args, **kwargs):
        """
        Search for exactly one object by DN (LDAP base scope).

        Thin wrapper that injects ldb.SCOPE_BASE so call sites do not
        need to import or reference ldb.SCOPE_* directly.
        """
        kwargs['scope'] = ldb.SCOPE_BASE
        return self.search(*args, **kwargs)



    def search_scope_onelevel(self, *args, **kwargs):
        """
        Search immediate children of a container (LDAP one-level scope).

        Thin wrapper that injects ldb.SCOPE_ONELEVEL so call sites do
        not need to import or reference ldb.SCOPE_* directly.
        """
        kwargs['scope'] = ldb.SCOPE_ONELEVEL
        return self.search(*args, **kwargs)



    def search_scope_subtree(self, *args, **kwargs):
        """
        Search a container and all its descendants (LDAP subtree scope).

        Thin wrapper that injects ldb.SCOPE_SUBTREE so call sites do
        not need to import or reference ldb.SCOPE_* directly.
        """
        kwargs['scope'] = ldb.SCOPE_SUBTREE
        return self.search(*args, **kwargs)



    def get_rootdse_attr_schema_syntax(self, attr):
        """
        Look up the SchemaSyntax for a Root DSE attribute by name.

        Uses the static ROOT_DSE_ATTRS dict rather than the live schema
        because the Root DSE is a virtual entry with no schema record.
        Returns None if the attribute is unknown.
        """
        oid = ROOT_DSE_ATTRS.get(attr)
        return oid and OID_SCHEMA_SYNTAX_DICT.get(oid) or None



    def get_attr_schema_syntax(self, attr, is_root_dse=False):
        """
        Look up the SchemaSyntax for any attribute by LDAP display name.

        For Root DSE attributes, uses the static ROOT_DSE_ATTRS dict.
        For all other attributes, queries the live Samba schema via
        get_syntax_oid_from_lDAPDisplayName() and looks up the result
        in OID_SCHEMA_SYNTAX_DICT.

        Returns None if the attribute is not found in either source,
        which triggers the fallback in build_attr_list().
        """
        if is_root_dse:
            oid = ROOT_DSE_ATTRS.get(attr)
        else:
            oid = self.get_syntax_oid_from_lDAPDisplayName(attr)
        return oid and OID_SCHEMA_SYNTAX_DICT.get(oid) or None



    def build_attr_list(self, msg, is_root_dse=False, attr_names=[]):
        """
        Convert an ldb.Message into a list of LdapAttr / SyntheticAttr
        objects ready to be passed to a Jinja2 template for rendering.

        Parameters
        ----------
        msg         : ldb.Message returned by self.search()
        is_root_dse : True when processing the Root DSE pseudo-entry
        attr_names  : Ordered list of attribute names to include. If
                      empty, all attributes present in msg are used
                      (minus 'dn' and 'vendorName' which are internal
                      or Samba-only fields).

        The ordering of attr_names is preserved in the output list,
        which matters because Windows is sensitive to attribute order
        in some response types.
        """
        # If the caller did not specify which attributes to return,
        # derive the list from what LDB actually returned, excluding
        # internal fields not part of the ADWS response schema.
        if not attr_names:
            attr_names = list(msg.keys())
            if 'dn'         in attr_names: attr_names.remove('dn')
            if 'vendorName' in attr_names: attr_names.remove('vendorName')

        attrs = []
        for attr_name in attr_names:
            attr_obj = None
            vals     = msg.get(attr_name, None)

            if vals is not None:
                if attr_name in SYNTHETIC_ATTRS:
                    # Synthetic attributes use the 'ad:' namespace and
                    # have no LdapSyntax annotation in the schema.
                    attr_obj = SyntheticAttr(attr_name, vals)
                else:
                    # Look up the LDAP syntax for this attribute so we
                    # can annotate the XML with the correct type info.
                    syntax = self.get_attr_schema_syntax(
                        attr_name, is_root_dse=is_root_dse)

                    # Fallback for attributes whose syntax OID is not in
                    # our registry (e.g. schema extensions or
                    # Samba-specific attrs). Treat as plain Unicode
                    # strings, which is correct for most unknown attrs.
                    #
                    # ldap_syntax must be the NAME ('UnicodeString'), not
                    # the OID -- this field is confirmed (via a live
                    # capture, 2026-09-04) to reach the AD PowerShell
                    # client's WCF deserializer verbatim as the
                    # LdapSyntax XML attribute. A prior version of this
                    # fallback used the OID string here by mistake,
                    # which is what made objectClass unrenderable before
                    # SYNTAX_OBJECT_IDENTIFIER was registered above.
                    if not syntax:
                        syntax = type('Syntax', (), {
                            'ldap_syntax': 'UnicodeString',
                            'xsi_type':    'xsd:string'
                        })

                    attr_obj = LdapAttr(
                        attr_name, vals,
                        syntax.ldap_syntax, syntax.xsi_type)

            else:
                # The attribute was requested but not present on this
                # object. relativeDistinguishedName is the only synthetic
                # attribute that can be computed from context when absent
                # -- it is derived from the object's DN.
                if attr_name == 'relativeDistinguishedName':
                    attr_obj = SyntheticAttr(
                        attr_name, [get_rdn(msg['dn'])])

            if attr_obj:
                attrs.append(attr_obj)

        return attrs



    def render_root_dse_xml(self, **context):
        """
        Handle a WS-Transfer Get request for the Root DSE.

        The Root DSE is queried with an empty base DN and SCOPE_BASE.
        Synthetic attributes are injected in the specific order required
        by the ADWS protocol: objectReferenceProperty first, then
        container-hierarchy-parent, relativeDistinguishedName, and
        distinguishedName last.
        """
        result = self.search(base='', scope=ldb.SCOPE_BASE)
        msg    = result[0]

        attrs = self.build_attr_list(msg, is_root_dse=True)

        # objectReferenceProperty must appear first in the response
        attrs.insert(0, SyntheticAttr('objectReferenceProperty',
                                      [ROOT_DSE_GUID]))

        # These three positional attributes must appear last, in order
        attrs.append(SyntheticAttr('container-hierarchy-parent',
                                   [ROOT_DSE_GUID]))
        attrs.append(SyntheticAttr('relativeDistinguishedName', ['']))
        attrs.append(SyntheticAttr('distinguishedName',         ['']))

        context['attrs'] = attrs
        return render_template('root-DSE.xml', **context)



    def render_msds_portldap(self, **context):
        """
        Handle a WS-Transfer Get request for msDS-PortLDAP.

        PowerShell queries this attribute early in the connection to
        discover which LDAP port the DC is listening on. We return a
        static response from a template rather than querying LDB since
        the port is fixed.
        """
        return render_template('msDS-PortLDAP.xml', **context)



    def render_transfer_get(self, **context):
        """
        Handle a WS-Transfer Get for a specific AD object by GUID.

        The objectReferenceProperty in the request header contains the
        GUID of the object to retrieve. Samba accepts GUIDs as LDB
        search base DNs in the format '<GUID=...>', so we pass it
        directly to self.search().
        """
        AttributeType_List = context['AttributeType_List']

        # Strip namespace prefix from each attribute name.
        # e.g. 'addata:sAMAccountName' -> 'sAMAccountName'
        attr_names = [attr.split(':')[-1] for attr in AttributeType_List]

        # Wildcard / empty-list detection.
        #
        # Case 1 -- 'ad:all' wildcard: PowerShell sends 'ad:all' as the
        # last AttributeType when the caller uses -Properties *. After
        # stripping the namespace prefix it becomes the literal 'all',
        # which is not a valid LDB attribute name.
        #
        # Case 2 -- empty AttributeType_List: some Get requests (e.g.
        # Get-ADObject -Identity <GUID> -Properties *) place LDAP
        # controls in the body but no AttributeType elements at all.
        # Passing attrs=[] to LDB returns all attributes including
        # internal fields such as 'controls', which PowerShell rejects
        # with "Encountered attribute 'controls'".
        #
        # In both cases the correct behaviour is to pass attrs=None to
        # LDB (returning all real schema attributes) and an empty list
        # to build_attr_list() so it derives the rendered set from
        # msg.keys(), which excludes internal LDB fields via the schema
        # syntax lookup in get_attr_schema_syntax().
        fetch_all = (not attr_names) or ('all' in attr_names)
        if fetch_all:
            ldb_attrs   = None
            build_names = []
        else:
            ldb_attrs   = attr_names
            build_names = attr_names

        result = self.search(
            base=context['objectReferenceProperty'],
            attrs=ldb_attrs,
            controls=[])

        msg   = result[0]
        attrs = self.build_attr_list(msg, attr_names=build_names)

        context['attrs'] = attrs
        return render_template('transfer-Get.xml', **context)



    def render_enumerate(self, **context):
        """
        Handle a WS-Enumeration Enumerate request.

        This is the first half of a two-phase search. The client sends
        an LDAP filter and attribute selection; we store them in a
        server-side context dict keyed by EnumerationContext UUID and
        return an acknowledgement. The actual LDB query happens in
        render_pull() when the client sends the matching Pull request.
        """
        return render_template('Enumerate.xml', **context)



    def render_pull(self, **context):
        """
        Handle a WS-Enumeration Pull request.

        This is the second half of the two-phase search started by
        render_enumerate(). We execute the LDAP query stored in the
        EnumerationContext, page the results using the LDB paged_results
        control, and return the matching objects wrapped in the correct
        object-class XML tags.

        Generic object class fix (v1.1.0)
        ----------------------------------
        Previously Pull.xml hardcoded <addata:computer> for every
        result object, which meant only Get-ADComputer worked.

        The fix has two parts:

        1.  We always request objectClass from LDB in addition to
            whatever attributes the client asked for. objectClass is
            multi-valued; its last value is the most-derived class
            (e.g. 'user', 'group', 'computer', 'organizationalUnit').
            This is the value Windows uses as the XML element name in
            ADWS responses.

        2.  We pass a list of (object_class, attrs) tuples to Pull.xml
            instead of a flat list of attrs. The template uses the
            object_class from each tuple to emit the correct
            <addata:X> / </addata:X> tags, making the response valid
            for any AD object type without per-type template files.

        If objectClass was not in the client's original attribute
        request, we build the attr list using only attr_names so that
        objectClass does not appear as a spurious attribute in the
        response payload.
        """
        SelectionProperty_List = context['SelectionProperty_List']
        enumeration_context    = context['EnumerationContext']
        cookie                 = enumeration_context.get('cookie', '')

        # Strip namespace prefix from attribute names the client wants.
        # e.g. 'addata:sAMAccountName' -> 'sAMAccountName'
        attr_names = [attr.split(':')[-1] for attr in SelectionProperty_List]

        LdapQuery   = context['LdapQuery']
        MaxElements = context['MaxElements']

        scope = SCOPE_ADLQ_TO_LDB[LdapQuery['Scope'].lower()]

        # Wildcard detection (v1.1.3)
        # PowerShell sends 'ad:all' as the final SelectionProperty when
        # the caller uses -Properties *. After stripping the namespace
        # prefix it becomes the literal string 'all', which is not a
        # valid LDB attribute name. LDB silently ignores it and returns
        # only the other named attributes, producing sparse results that
        # cause cmdlets like Get-ADDomain to report object-not-found.
        #
        # When 'all' is present we remove it from attr_names and pass
        # attrs=None to the LDB search, which tells Samba to return
        # every attribute on the object. We also set
        # client_requested_objectclass=True so objectClass is always
        # included in the result (LDB returns it regardless when
        # attrs=None, and we need it for the XML tag rewrite).
        fetch_all = 'all' in attr_names
        if fetch_all:
            attr_names = [a for a in attr_names if a != 'all']
            attrs_to_fetch               = None
            client_requested_objectclass = True
        else:
            # Always include objectClass in the LDB query so we can
            # determine the correct XML wrapper tag for each result.
            # Track whether the client asked for it so we can strip it
            # from the rendered attr list if they did not.
            client_requested_objectclass = 'objectClass' in attr_names
            base_fetch = (
                attr_names
                if client_requested_objectclass
                else attr_names + ['objectClass']
            )
            # Always fetch DC-qualification attributes from LDB so
            # they are available for injection into computer object
            # responses. If already in the list they are not duplicated.
            for _dc_attr in DC_QUAL_ATTRS:
                if _dc_attr not in base_fetch:
                    base_fetch = base_fetch + [_dc_attr]
            attrs_to_fetch = base_fetch

        # An empty BaseObject means 'search the entire directory'.
        # Samba's LDB partition module rejects a literal empty base DN
        # with error 32. A real Windows DC performs a global catalog
        # search across all NCs; we approximate this by searching the
        # domain NC and Configuration NC separately and merging the
        # results. This is necessary for cmdlets like
        # Get-ADDomainController whose filter spans both NCs
        # (computer objects in the domain NC and nTDSDSA/server
        # objects in the Configuration NC).
        #
        # When BaseObject is non-empty we use it directly as before.
        if LdapQuery['BaseObject']:
            # Standard single-base search with paged results support.
            result = self.search(
                base=LdapQuery['BaseObject'],
                scope=scope,
                expression=LdapQuery['Filter'],
                attrs=attrs_to_fetch,
                controls=['paged_results:1:%s%s' % (MaxElements, cookie)]
            )

            # Check the paged_results control to determine whether more
            # pages remain. If absent or cookie is empty this is the
            # last (or only) page.
            ctrls = [
                str(c) for c in result.controls
                if str(c).startswith('paged_results')
            ]
            if ctrls:
                spl = ctrls[0].rsplit(':', 3)
                if len(spl) == 3:
                    # Non-empty cookie -- more results waiting.
                    new_cookie = ':' + spl[-1]
                    enumeration_context['cookie'] = new_cookie
                    context['is_end'] = False
                else:
                    context['is_end'] = True
            else:
                context['is_end'] = True

            msgs_to_render = list(result.msgs)

        else:
            # Empty BaseObject means 'search the entire directory'.
            # Samba rejects a literal empty base DN (error 32). We
            # approximate a global search by querying the domain NC
            # and Configuration NC separately and merging the msgs.
            # These are small DC-discovery result sets so paging is
            # not needed; we treat the merged set as the final page.
            domain_base = str(self.domain_dn())
            config_base = 'CN=Configuration,' + domain_base
            msgs_to_render = []
            for search_base in [domain_base, config_base]:
                try:
                    r = self.search(
                        base=search_base,
                        scope=ldb.SCOPE_SUBTREE,
                        expression=LdapQuery['Filter'],
                        attrs=attrs_to_fetch,
                        controls=[
                            'paged_results:1:%s' % MaxElements
                        ]
                    )
                    msgs_to_render.extend(list(r.msgs))
                except Exception:
                    pass
            # Multi-NC results are returned as a single complete page.
            context['is_end'] = True

        # Build (object_class, attrs) tuples for every result object.
        #
        # objectClass is multi-valued and ordered from least- to
        # most-derived. The last value is what we want: e.g. for a user
        # the list is ['top', 'person', 'organizationalPerson', 'user']
        # and we use 'user' as the XML element name.
        objects = []
        for msg in msgs_to_render:
            object_class = (
                str(msg['objectClass'][-1])
                if 'objectClass' in msg
                else 'top'  # safe fallback; should not occur in practice
            )

            # When fetch_all is True, pass an empty attr_names list
            # so build_attr_list() derives the list from msg.keys()
            # and renders every attribute LDB returned. When False,
            # pass attr_names so only the requested attrs are rendered
            # and objectClass is excluded unless the client asked for it.
            effective_attr_names = [] if fetch_all else attr_names

            # For computer objects, inject DC-qualification attributes
            # if they are present in the LDB result but not in the
            # client's selection list. This allows PowerShell to
            # identify the object as a DC account without a separate
            # lookup. We only inject when the LDB result actually
            # contains the attribute so we never fabricate data.
            if object_class == 'computer' and not fetch_all:
                extra = [
                    a for a in DC_QUAL_ATTRS
                    if a not in attr_names and a in msg
                ]
                if extra:
                    effective_attr_names = list(attr_names) + extra

            attrs = self.build_attr_list(
                msg,
                attr_names=effective_attr_names
            )

            objects.append((object_class, attrs))

        context['objects'] = objects
        return render_template('Pull.xml', **context)



    def render_get_dc(self, **context):
        """
        Handle the GetADDomainController TopologyManagement action.

        Unlike GetADDomain and GetADForest (which are pure handshakes
        with empty request bodies), GetADDomainController is a DATA
        request. The request body contains an NtdsSettingsDN element
        identifying which DC to look up. PowerShell uses the response
        body to construct the ADDomainController object directly and
        does not make a follow-up Enumerate/Pull.

        We query two LDB objects to build the response:
          1. The nTDSDSA object (NtdsSettingsDN from the request) for
             invocationId, hasMasterNCs, msDS-Behavior-Version, and
             options (bit 0 set = Global Catalog).
          2. The server object (parent DN of the nTDSDSA) for
             dNSHostName, serverReference, and objectGUID.

        FSMO role ownership is determined by comparing the
        fSMORoleOwner attributes of well-known objects against the
        NtdsSettingsDN. The five standard FSMO roles checked are:
          - PDC Emulator     (domainDNS object)
          - RID Master       (RID Manager$ object)
          - Infrastructure   (Infrastructure object)
          - Schema Master    (schema NC head)
          - Domain Naming    (partitions container)
        """
        xmlhelper = context['xmlhelper']

        # Extract NtdsSettingsDN from the request body.
        # Namespace: b = serialization arrays namespace used by ADWS.
        ntds_dn = xmlhelper.get_elem_text(
            './/s:Body//b:string',
        )
        if not ntds_dn:
            # Fall back to generic handshake if DN is missing
            context['action_name'] = 'GetADDomainController'
            return render_template('topology-action.xml', **context)

        # Query the nTDSDSA object
        ntds_result = self.search(
            base=ntds_dn,
            scope=ldb.SCOPE_BASE,
            expression='(objectClass=*)',
            attrs=['invocationId', 'hasMasterNCs', 'options',
                   'objectGUID', 'msDS-Behavior-Version']
        )
        ntds_msg = ntds_result[0]

        # The server object is the direct parent of the nTDSDSA object.
        # Strip the first component of the DN to get the parent.
        # e.g. 'CN=NTDS Settings,CN=DC1,...' -> 'CN=DC1,...'
        server_dn = ','.join(ntds_dn.split(',')[1:])

        server_result = self.search(
            base=server_dn,
            scope=ldb.SCOPE_BASE,
            expression='(objectClass=*)',
            attrs=['dNSHostName', 'serverReference',
                   'objectGUID', 'cn']
        )
        server_msg = server_result[0]

        # Extract site name from the server DN.
        # DN structure: CN=<dc>,CN=Servers,CN=<site>,CN=Sites,...
        # Split gives: ['CN=<dc>', 'CN=Servers', 'CN=<site>', ...]
        dn_parts   = server_dn.split(',')
        if len(dn_parts) > 2:
            site_name = dn_parts[2].split('=')[1]
        else:
            site_name = ''

        # Build the list of NC partitions mastered by this DC
        partitions = []
        if 'hasMasterNCs' in ntds_msg:
            partitions = [
                str(v) for v in ntds_msg['hasMasterNCs']
            ]

        # Determine Global Catalog status.
        # options bit 0 (value 1) set means this is a GC.
        if 'options' in ntds_msg:
            options = int(str(ntds_msg['options'][0]))
        else:
            options = 0
        is_gc = 'true' if (options & 1) else 'false'

        # Resolve FSMO roles held by this DC by comparing the
        # fSMORoleOwner attribute of each role object against
        # ntds_dn (case-insensitive).
        fsmo_checks = {
            'PDCEmulator':       self.domain_dn(),
            'RIDMaster':         'CN=RID Manager$,CN=System,'
                                 + str(self.domain_dn()),
            'InfrastructureMaster': 'CN=Infrastructure,'
                                    + str(self.domain_dn()),
            'SchemaMaster':      str(self.get_schema_basedn()),
            'DomainNamingMaster':'CN=Partitions,CN=Configuration,'
                                 + str(self.domain_dn()),
        }
        roles = []
        for role_name, role_base in fsmo_checks.items():
            try:
                r = self.search(
                    base=role_base,
                    scope=ldb.SCOPE_BASE,
                    expression='(objectClass=*)',
                    attrs=['fSMORoleOwner']
                )
                if r and 'fSMORoleOwner' in r[0]:
                    owner = str(r[0]['fSMORoleOwner'][0])
                    if owner.lower() == ntds_dn.lower():
                        roles.append(role_name)
            except Exception:
                pass

        # Resolve domain DNS name from the default naming context.
        # e.g. DC=vlab,DC=test -> vlab.test
        domain_dn  = str(self.domain_dn())
        domain_dns = '.'.join(
            p.split('=')[1]
            for p in domain_dn.split(',')
            if p.upper().startswith('DC=')
        )

        # objectGUID from server object - decode bytes to GUID string
        # ServerObjectGuid must be the GUID of the computer account
        # object (CN=DC1,OU=Domain Controllers,...), not the server
        # topology object (CN=DC1,CN=Servers,...). PowerShell uses
        # this GUID to correlate the topology response with the
        # computer object it received from the Enumerate/Pull phase.
        # We retrieve it by following the serverReference DN from the
        # server object, which points directly to the computer account.
        if 'serverReference' in server_msg:
            computer_dn = str(server_msg['serverReference'][0])
        else:
            computer_dn = ''
        computer_guid_raw = b''
        if computer_dn:
            try:
                comp_result = self.search(
                    base=computer_dn,
                    scope=ldb.SCOPE_BASE,
                    expression='(objectClass=*)',
                    attrs=['objectGUID', 'operatingSystem',
                           'operatingSystemVersion',
                           'operatingSystemHotfix',
                           'operatingSystemServicePack']
                )
                if comp_result and 'objectGUID' in comp_result[0]:
                    computer_guid_raw = bytes(
                        comp_result[0]['objectGUID'][0]
                    )
            except Exception:
                pass

        import struct
        if len(computer_guid_raw) == 16:
            p = struct.unpack('<IHH8B', computer_guid_raw)
            server_guid = (
                '%08x-%04x-%04x-%02x%02x-'
                '%02x%02x%02x%02x%02x%02x'
            ) % (p[0], p[1], p[2], p[3], p[4],
                 p[5], p[6], p[7], p[8], p[9], p[10])
        else:
            server_guid = ''

        # InvocationId in the ADWS response must be the objectGUID of
        # the nTDSDSA object, not the invocationId attribute. PowerShell
        # uses this value to correlate the topology response with the
        # nTDSDSA object returned by the follow-up Enumerate/Pull.
        # The nTDSDSA objectGUID is already in ntds_msg; we decode it
        # using the same little-endian struct pattern as server_guid.
        if 'objectGUID' in ntds_msg:
            ntds_guid_raw = bytes(ntds_msg['objectGUID'][0])
        else:
            ntds_guid_raw = b''
        if len(ntds_guid_raw) == 16:
            p3 = struct.unpack('<IHH8B', ntds_guid_raw)
            inv_id = (
                '%08x-%04x-%04x-%02x%02x-'
                '%02x%02x%02x%02x%02x%02x'
            ) % (p3[0], p3[1], p3[2], p3[3], p3[4],
                 p3[5], p3[6], p3[7], p3[8], p3[9], p3[10])
        else:
            inv_id = ''

        # Extract OS fields from the computer account object.
        # These are stored on the computer object in the domain NC.
        # comp_result may be empty if the computer DN was not found.
        comp_msg = comp_result[0] if comp_result else None

        def _comp_str(attr):
            # Return string value of attr from comp_msg, or None.
            if comp_msg and attr in comp_msg:
                return str(comp_msg[attr][0])
            return None

        context.update({
            'NtdsSettingsDN':   ntds_dn,
            'ServerObjectDN':   server_dn,
            'ServerObjectGuid': server_guid,
            'ComputerObjectDN': str(server_msg['serverReference'][0])
                                if 'serverReference' in server_msg
                                else '',
            'HostName':         str(server_msg['dNSHostName'][0])
                                if 'dNSHostName' in server_msg else '',
            'Name':             str(server_msg['cn'][0])
                                if 'cn' in server_msg else '',
            'Site':             site_name,
            'Domain':           domain_dns,
            'Forest':           domain_dns,
            'DefaultPartition': domain_dn,
            'Partitions':       partitions,
            'InvocationId':     inv_id,
            'IsGlobalCatalog':  is_gc,
            'IsReadOnly':       'false',
            'LdapPort':         '389',
            'SslPort':          '636',
            'Enabled':          'true',
            'OperationMasterRoles':       roles,
            'OperatingSystem':            _comp_str('operatingSystem'),
            'OperatingSystemVersion':     _comp_str('operatingSystemVersion'),
            'OperatingSystemHotfix':      _comp_str('operatingSystemHotfix'),
            'OperatingSystemServicePack': _comp_str(
                                    'operatingSystemServicePack'),
        })
        return render_template('GetADDomainController.xml', **context)



    def render_topology_action(self, **context):
        """
        Handle a WS-CustomActions TopologyManagement request.

        Most topology actions (GetADDomain, GetADForest) are pure
        capability handshakes -- the request body is empty and
        PowerShell only checks that the response is well-formed before
        going on to fetch data via Enumerate/Pull.

        GetADDomainController is the exception: its request body
        contains an NtdsSettingsDN and PowerShell constructs the
        ADDomainController object directly from the response body
        without a follow-up Enumerate/Pull. It is dispatched to
        render_get_dc() which performs the necessary LDB queries.

        The Action URI follows the pattern:
          .../CustomActions/TopologyManagement/<ActionName>

        We extract the local action name (e.g. 'GetADDomain') from
        the tail of the URI. Handshake actions use topology-action.xml
        (empty body). Data actions use their own dedicated template.
        """
        action = context.get('Action', '')

        # Extract the local action name from the tail of the URI.
        # e.g. '.../TopologyManagement/GetADDomain' -> 'GetADDomain'
        action_name = action.split('/')[-1] if action else 'Unknown'

        # Dispatch data actions to their dedicated render methods.
        if action_name == 'GetADDomainController':
            return self.render_get_dc(**context)

        # All other topology actions are pure handshakes.
        context['action_name'] = action_name
        return render_template('topology-action.xml', **context)



# ========================================================================== #
# Interactive Shell Entry Point                                              #
# ========================================================================== #
# Running this file directly drops into an IPython shell with a live
# SamDB connection, useful for inspecting LDB data and testing queries
# interactively without going through the full ADWS proxy stack.

if __name__ == '__main__':
    from IPython import embed
    embed(header='Samba Python Shell')
