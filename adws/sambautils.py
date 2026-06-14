"""
------------------------------------------------------------------------------
Script Name:      sambautils.py
Script Author:    Neal Russell
Author's Company: N/A (fork of gitlab.com/catalyst-samba/samba-adws)
Script Created:   2024-Jan-01
Script Modified:  2026-Jun-14
Script Version:   1.1.3
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
# ldb Constant Polyfill                                                      #
# ========================================================================== #
# The python3-ldb package does not consistently expose OID constants
# across all Samba versions. getattr() with a fallback prevents
# AttributeErrors at import time on systems where a constant is missing.
# The fallback value of 1 is a placeholder; if a constant is genuinely
# absent it means the installed Samba version does not support that
# syntax, which will surface as a missing syntax lookup rather than a
# hard crash.

SYNTAX_INTEGER           = getattr(ldb, 'SYNTAX_INTEGER',           1)
SYNTAX_LARGE_INTEGER     = getattr(ldb, 'SYNTAX_LARGE_INTEGER',     1)
SYNTAX_BOOLEAN           = getattr(ldb, 'SYNTAX_BOOLEAN',           1)
SYNTAX_DIRECTORY_STRING  = getattr(ldb, 'SYNTAX_DIRECTORY_STRING',  1)
SYNTAX_OCTET_STRING      = getattr(ldb, 'SYNTAX_OCTET_STRING',      1)
SYNTAX_DN                = getattr(ldb, 'SYNTAX_DN',                1)
SYNTAX_UTC_TIME          = getattr(ldb, 'SYNTAX_UTC_TIME',          1)
SYNTAX_GENERALIZED_TIME  = getattr(ldb, 'SYNTAX_GENERALIZED_TIME',  1)
SYNTAX_OBJECT_IDENTIFIER = getattr(ldb, 'SYNTAX_OBJECT_IDENTIFIER', 1)


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
                    if not syntax:
                        syntax = type('Syntax', (), {
                            'ldap_syntax': '1.3.6.1.4.1.1466.115.121.1.15',
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

        result = self.search(
            base=context['objectReferenceProperty'],
            attrs=attr_names,
            controls=[])

        msg   = result[0]
        attrs = self.build_attr_list(msg, attr_names=attr_names)

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
            attrs_to_fetch          = None
            client_requested_objectclass = True
        else:
            # Always include objectClass in the LDB query so we can
            # determine the correct XML wrapper tag for each result.
            # Track whether the client asked for it so we can strip it
            # from the rendered attr list if they did not.
            client_requested_objectclass = 'objectClass' in attr_names
            attrs_to_fetch = (
                attr_names
                if client_requested_objectclass
                else attr_names + ['objectClass']
            )

        result = self.search(
            base=LdapQuery['BaseObject'],
            scope=scope,
            expression=LdapQuery['Filter'],
            attrs=attrs_to_fetch,
            controls=['paged_results:1:%s%s' % (MaxElements, cookie)]
        )

        # Check the paged_results control in the response to determine
        # whether more pages remain. If absent or the cookie is empty,
        # this is the last (or only) page of results.
        ctrls = [
            str(c) for c in result.controls
            if str(c).startswith('paged_results')
        ]

        if ctrls:
            spl = ctrls[0].rsplit(':', 3)
            if len(spl) == 3:
                # Non-empty cookie -- more results waiting. Store it so
                # the next Pull request picks up where this one left off.
                new_cookie = ':' + spl[-1]
                enumeration_context['cookie'] = new_cookie
                context['is_end'] = False
            else:
                # Empty cookie -- this is the final page.
                context['is_end'] = True
        else:
            # No paged_results control at all -- treat as final page.
            context['is_end'] = True

        # Build (object_class, attrs) tuples for every result object.
        #
        # objectClass is multi-valued and ordered from least- to
        # most-derived. The last value is what we want: e.g. for a user
        # the list is ['top', 'person', 'organizationalPerson', 'user']
        # and we use 'user' as the XML element name.
        objects = []
        for msg in result.msgs:
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
            attrs = self.build_attr_list(
                msg,
                attr_names=[] if fetch_all else attr_names
            )

            objects.append((object_class, attrs))

        context['objects'] = objects
        return render_template('Pull.xml', **context)


    def render_topology_action(self, **context):
        """
        Handle a WS-CustomActions TopologyManagement request.

        PowerShell cmdlets Get-ADDomain, Get-ADForest, and
        Get-ADDomainController open a connection to the separate
        TopologyManagement endpoint and send a CustomAction request
        before retrieving any data. The request body is always empty
        -- it is a capability handshake, not a data request.

        PowerShell uses the response only to confirm the server speaks
        the TopologyManagement protocol. If the response is missing or
        malformed it raises ADServerDownException and aborts. After
        receiving a valid acknowledgement here, PowerShell fetches the
        actual data through the standard Enumerate/Pull path using its
        own LDAP filters (e.g. objectClass=domainDNS).

        The Action URI follows the pattern:
          .../CustomActions/TopologyManagement/<ActionName>

        We extract the local action name (e.g. 'GetADDomain') from the
        tail of the URI and pass it to the template, which uses it to
        build the matching response element and Action URI.
        """
        action = context.get('Action', '')

        # Extract the local action name from the tail of the URI.
        # e.g. '.../TopologyManagement/GetADDomain' -> 'GetADDomain'
        action_name = action.split('/')[-1] if action else 'Unknown'

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
