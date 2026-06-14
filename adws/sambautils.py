#!/usr/bin/env python3
# ============================================================================
# Script Name  : sambautils.py
# Author       : RussellNS
# Forked From  : Catalyst Samba-ADWS Project on GitLab
# Original URL : https://gitlab.com/catalyst-samba/samba-adws
# Purpose      : Core AD backend for the ADWS proxy. Provides the
#                SamDBHelper class which connects to the local Samba LDB
#                database and handles all LDAP queries. Also defines the
#                attribute model (LdapAttr, SyntheticAttr) and Jinja2
#                template rendering used to produce SOAP/XML responses
#                for every ADWS action.
# ============================================================================
# Change Log  :
#   v1.0.0  - Python 3.13 compatibility refactor. ldb constant polyfill,
#               bytes/binary handling, SamDB subclass pattern.
#   v1.1.0  - Generic object class fix. render_pull() now passes
#               (object_class, attrs) tuples to Pull.xml so that any
#               AD object type (user, group, OU, etc.) is wrapped in
#               the correct <addata:X> tag instead of the hardcoded
#               <addata:computer>.
# ============================================================================
from __future__ import print_function, absolute_import
import ldb
import samba
from samba.samdb import SamDB
from samba.param import LoadParm
from samba.auth import system_session
from samba import dsdb
from os.path import abspath, dirname, join
import jinja2
from jinja2 import Environment, FileSystemLoader, select_autoescape
from base64 import b64encode



# ============================================================================
# ldb Constant Polyfill
# ============================================================================
# The python3-ldb package does not consistently expose OID constants
# across all Samba versions. getattr() with a fallback prevents
# AttributeErrors at import time on systems where a constant is missing.
# The fallback value of 1 is a placeholder; if a constant is genuinely
# absent it means the installed Samba version does not support that
# syntax, which will surface as a missing syntax lookup rather than a
# hard crash.
# ============================================================================
SYNTAX_INTEGER          = getattr(ldb, 'SYNTAX_INTEGER',          1)
SYNTAX_LARGE_INTEGER    = getattr(ldb, 'SYNTAX_LARGE_INTEGER',    1)
SYNTAX_BOOLEAN          = getattr(ldb, 'SYNTAX_BOOLEAN',          1)
SYNTAX_DIRECTORY_STRING = getattr(ldb, 'SYNTAX_DIRECTORY_STRING', 1)
SYNTAX_OCTET_STRING     = getattr(ldb, 'SYNTAX_OCTET_STRING',     1)
SYNTAX_DN               = getattr(ldb, 'SYNTAX_DN',               1)
SYNTAX_UTC_TIME         = getattr(ldb, 'SYNTAX_UTC_TIME',         1)
SYNTAX_GENERALIZED_TIME = getattr(ldb, 'SYNTAX_GENERALIZED_TIME', 1)
SYNTAX_OBJECT_IDENTIFIER= getattr(ldb, 'SYNTAX_OBJECT_IDENTIFIER',1)

# ============================================================================
# Jinja2 Template Engine Setup
# ============================================================================
# Templates live in the adws/templates/ directory alongside this file.
# autoescape is enabled for XML to prevent injection through AD attribute
# values that contain characters like <, >, or &. The |safe filter in
# templates is used deliberately only for pre-rendered XML fragments
# that we have already escaped ourselves (LdapAttr.to_xml /
# SyntheticAttr.to_xml).
# ============================================================================
HERE      = dirname(abspath(__file__))
TEMPLATES = join(HERE, 'templates')

ENV = Environment(
    loader=FileSystemLoader(TEMPLATES),
    autoescape=select_autoescape(['xml']),
)

# ============================================================================
# LDAP Scope Mapping
# ============================================================================
# PowerShell AD cmdlets express search scope using ADWS/LDAP dialect
# strings ('base', 'onelevel', 'subtree'). This dict maps them to the
# integer constants that python-ldb expects on search() calls.
# Reference: https://msdn.microsoft.com/en-us/library/dd340513.aspx
# =============================================================================
SCOPE_ADLQ_TO_LDB = {
    'base':     ldb.SCOPE_BASE,
    'onelevel': ldb.SCOPE_ONELEVEL,
    'subtree':  ldb.SCOPE_SUBTREE,
}



def render_template(template_name, **kwargs):
    """
    Load and render a Jinja2 template from the templates/ directory.

    All keyword arguments are passed directly into the template context,
    making them available as variables inside the XML template files.
    """
    template = ENV.get_template(template_name)
    return template.render(**kwargs)



# ============================================================================
# SchemaSyntax
# ============================================================================
# Encapsulates the relationship between an LDAP OID, the human-readable
# LdapSyntax name Windows expects in responses (e.g. 'UnicodeString'),
# and the XSD type used in the SOAP envelope (e.g. 'xsd:string' or
# 'xsd:base64Binary'). Every LDAP attribute type has one of these.
# ============================================================================
class SchemaSyntax(object):
    def __init__(self, oid, ldap_syntax, xsi_type='xsd:string'):
        # OID string that uniquely identifies this LDAP syntax in the schema
        self.oid         = oid
        # Human-readable name sent in the LdapSyntax XML attribute
        self.ldap_syntax = ldap_syntax
        # XSD type sent in the xsi:type XML attribute for each value
        self.xsi_type    = xsi_type

    def render(self):
        return 'xml'



# ============================================================================
# Root DSE Sentinel GUID
# ============================================================================
# The Root DSE is the top-level entry of an LDAP directory (like the
# "/" of a filesystem). It has no real GUID in AD; Windows uses this
# well-known fake GUID as a handle to request it. We match on this to
# decide whether a Get request is asking for the Root DSE or a real
# object.
# ============================================================================
ROOT_DSE_GUID = '11111111-1111-1111-1111-111111111111'



def is_rootDSE(guid):
    """Return True if the given GUID string is the sentinel Root DSE GUID."""
    return guid.strip() == ROOT_DSE_GUID



# ============================================================================
# Schema Syntax Registry
# ============================================================================
# Maps LDAP OIDs to SchemaSyntax instances. When we retrieve an
# attribute from LDB, we look up its OID via
# get_syntax_oid_from_lDAPDisplayName() and use this dict to find the
# correct ldap_syntax and xsi_type for the XML response. Only the
# syntaxes that appear in a standard Samba AD schema are listed here.
# ============================================================================
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

# Keyed by OID for O(1) lookup during attribute serialisation
OID_SCHEMA_SYNTAX_DICT = {obj.oid: obj for obj in SCHEMA_SYNTAX_LIST}

# ============================================================================
# Root DSE Attribute Syntax Map
# ============================================================================
# The Root DSE is a special pseudo-entry that does not have schema
# entries in the usual place. Its attribute syntaxes are defined by the
# ADWS spec (MS-ADDM Appendix A <4>) rather than looked up dynamically,
# so we maintain a static dict here. Attributes not listed here will be
# skipped during Root DSE serialisation.
# Reference: https://msdn.microsoft.com/en-us/library/dd340513.aspx
# ============================================================================
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

# ============================================================================
# LdapAttr Jinja2 Template
# ============================================================================
# Inline Jinja2 template used by LdapAttr.to_xml(). Renders one LDAP
# attribute as an XML fragment with its LdapSyntax annotation and one
# <ad:value> element per value. The namespace prefix 'addata:' marks
# this as a real LDAP attribute (vs. 'ad:' which is used for synthetic
# attributes).
# ============================================================================
LDAP_ATTR_TEMPLATE = jinja2.Template("""
<addata:{{obj.attr}} LdapSyntax="{{obj.ldap_syntax}}">
   {%- for val in obj.vals %}
   <ad:value xsi:type="{{obj.xsi_type}}">{{val}}</ad:value>
   {%- endfor %}
</addata:{{obj.attr}}>""".strip())



class LdapAttr(object):
    """
    Represents one LDAP attribute retrieved from LDB, ready to be
    serialised into the ADWS XML response format.

    Handles the Python 3 bytes/str boundary: LDB returns attribute
    values as bytes objects. We attempt UTF-8 decode first (covers the
    vast majority of string attributes). If that fails (SIDs, GUIDs,
    certificate blobs, etc.) we base64-encode the value and switch
    xsi_type to 'xsd:base64Binary' so Windows knows to decode it on
    the other end.
    """

    def __init__(self, attr, vals, ldap_syntax, xsi_type='xsd:string'):
        # LDAP display name of the attribute, e.g. 'sAMAccountName'
        self.attr        = attr
        self.ldap_syntax = ldap_syntax

        # xsi_type must be namespace-qualified (e.g. 'xsd:string')
        assert ':' in xsi_type
        self.xsi_type = xsi_type

        # ldb.MessageElement is a read-only C-level iterable. Convert to
        # a plain Python list so we can index, modify, and iterate freely.
        if hasattr(vals, '__iter__') and not isinstance(vals, (str, bytes)):
            self.vals = list(vals)
        else:
            self.vals = [vals]

        # Walk every value and handle bytes objects.
        for i, v in enumerate(self.vals):
            if isinstance(v, bytes):
                try:
                    # Most LDAP string attributes are valid UTF-8.
                    self.vals[i] = v.decode('utf-8')
                except UnicodeDecodeError:
                    # Binary attributes (objectSid, objectGUID,
                    # nTSecurityDescriptor, userCertificate, etc.)
                    # cannot be decoded as text. Base64-encode them so
                    # they survive XML serialisation intact.
                    # b64encode() returns bytes in Python 3; decode to
                    # ASCII str so Jinja2 can render it without errors.
                    self.vals[i] = b64encode(v).decode('ascii')

                    # CRITICAL: update xsi_type so Windows knows to
                    # base64-decode this value. If left as 'xsd:string'
                    # Windows interprets the base64 text as a literal
                    # string value, causing attribute parsing failures
                    # on the client side.
                    self.xsi_type = 'xsd:base64Binary'

    def to_xml(self):
        """Render this attribute as an XML fragment string."""
        return LDAP_ATTR_TEMPLATE.render({'obj': self})



# ============================================================================
# Synthetic Attributes
# ============================================================================
# These attributes do not exist directly in the LDB schema but are
# required by the ADWS protocol. They are computed by the proxy and
# injected into responses. They use the 'ad:' namespace prefix rather
# than 'addata:'.
# Reference: https://msdn.microsoft.com/en-us/library/dd340577.aspx
#
#   objectReferenceProperty    - The GUID used as the ADWS object handle
#   container-hierarchy-parent - GUID of the parent container
#   distinguishedName          - Full LDAP DN string
#   relativeDistinguishedName  - RDN component only (e.g. 'CN=MyPC')
# ============================================================================
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
    """
    Represents a computed/synthetic ADWS attribute that does not exist
    in LDB.

    The assertion enforces that only known synthetic attribute names are
    used, catching typos and protocol violations early rather than
    producing silently malformed XML responses.
    """

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



def get_rdn(dn):
    """
    Extract the Relative Distinguished Name from an ldb.Dn object.

    For example, given the DN 'CN=MyComputer,OU=Servers,DC=corp,DC=local'
    this returns the string 'CN=MyComputer'. Returns an empty string if
    either component is missing (e.g. for the Root DSE which has no RDN).
    """
    rdn_name  = dn.get_rdn_name()
    rdn_value = dn.get_rdn_value()
    if rdn_name and rdn_value:
        return '%s=%s' % (rdn_name, rdn_value)
    return ''



# ============================================================================
# SamDBHelper
# ============================================================================
# Subclasses SamDB (the Samba Python binding to the LDB directory
# database) to add ADWS-specific query helpers and XML rendering
# methods.
#
# By subclassing rather than wrapping, we get direct access to all
# SamDB methods (search, add, delete, modify, etc.) without delegation
# boilerplate, while still being able to add our own methods alongside
# them.
#
# SamDB connects to the local sam.ldb file using a system session
# (root-level Kerberos credentials), which is why main.py must be run
# as root/sudo.
# ============================================================================
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

    # ------------------------------------------------------------------------
    # Convenience scope wrappers
    # These are thin wrappers that inject the scope constant so call
    # sites don't have to import or reference ldb.SCOPE_* directly.
    # ------------------------------------------------------------------------

    def search_scope_base(self, *args, **kwargs):
        """Search for exactly one object by DN (LDAP base scope)."""
        kwargs['scope'] = ldb.SCOPE_BASE
        return self.search(*args, **kwargs)

    def search_scope_onelevel(self, *args, **kwargs):
        """Search immediate children of a container (one-level scope)."""
        kwargs['scope'] = ldb.SCOPE_ONELEVEL
        return self.search(*args, **kwargs)

    def search_scope_subtree(self, *args, **kwargs):
        """Search a container and all descendants (subtree scope)."""
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

        For Root DSE attributes, falls back to the static ROOT_DSE_ATTRS
        dict. For all other attributes, queries the live Samba schema via
        get_syntax_oid_from_lDAPDisplayName() and looks up the result in
        OID_SCHEMA_SYNTAX_DICT.

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
            vals = msg.get(attr_name, None)

            if vals is not None:
                if attr_name in SYNTHETIC_ATTRS:
                    # Synthetic attributes use the 'ad:' namespace and
                    # have no LdapSyntax annotation in the schema.
                    attr_obj = SyntheticAttr(attr_name, vals)
                else:
                    # Look up the LDAP syntax for this attribute so we
                    # can annotate the XML with the correct type metadata.
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
                # object. The only synthetic attribute that can be
                # computed from context when absent from msg is
                # relativeDistinguishedName, derived from the object DN.
                if attr_name == 'relativeDistinguishedName':
                    attr_obj = SyntheticAttr(
                        attr_name, [get_rdn(msg['dn'])])

            if attr_obj:
                attrs.append(attr_obj)

        return attrs

    # ========================================================================
    # XML Rendering Methods
    # Each method handles one ADWS SOAP action, performs the necessary
    # LDB query, builds the attribute list, and delegates to a Jinja2
    # template.
    # ========================================================================

    def render_root_dse_xml(self, **context):
        """
        Handle a WS-Transfer Get request for the Root DSE.

        The Root DSE is queried with an empty base DN and SCOPE_BASE.
        Three synthetic attributes are injected in a specific order
        required by the ADWS protocol: objectReferenceProperty first,
        then container-hierarchy-parent, relativeDistinguishedName, and
        distinguishedName at the end.
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
        static response from a template rather than querying LDB, since
        the port is fixed.
        """
        return render_template('msDS-PortLDAP.xml', **context)

    def render_transfer_get(self, **context):
        """
        Handle a WS-Transfer Get request for a specific AD object by GUID.

        The objectReferenceProperty in the request header contains the
        GUID of the object to retrieve. We search LDB by GUID (Samba
        accepts GUIDs as search base DNs in the format '<GUID=...>')
        and return the requested attributes via transfer-Get.xml.
        """
        AttributeType_List = context['AttributeType_List']

        # Strip the namespace prefix from each attribute name.
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
        render_pull() when the client sends a Pull request referencing
        this EnumerationContext.
        """
        return render_template('Enumerate.xml', **context)

    def render_pull(self, **context):
        """
        Handle a WS-Enumeration Pull request.

        This is the second half of the two-phase search started by
        Enumerate. We execute the LDAP query stored in the
        EnumerationContext, page the results using the LDB
        paged_results control, and return the matching objects wrapped
        in the correct object-class XML tags.

        Generic object class fix (v1.1.0)
        ----------------------------------
        Previously the Pull.xml template hardcoded <addata:computer>
        for every result object, which meant only Get-ADComputer worked
        correctly.

        The fix has two parts:

        1. We always request objectClass from LDB in addition to
           whatever attributes the client asked for. objectClass is
           multi-valued; its last value is the most-derived class
           (e.g. 'user', 'group', 'computer', 'organizationalUnit').
           This is the value Windows uses as the XML element name in
           ADWS responses.

        2. We pass a list of (object_class, attrs) tuples to Pull.xml
           instead of a flat list of attrs. The template uses the
           object_class from each tuple to emit the correct
           <addata:X> / </addata:X> tags, making the response valid
           for any AD object type.

        If objectClass was not in the client's original attribute
        request, we strip it from the rendered attr list so it does
        not appear as a spurious attribute in the response payload.
        """
        SelectionProperty_List = context['SelectionProperty_List']
        enumeration_context    = context['EnumerationContext']
        cookie                 = enumeration_context.get('cookie', '')

        # Strip namespace prefixes from the attribute names the client
        # wants. e.g. 'addata:sAMAccountName' -> 'sAMAccountName'
        attr_names = [attr.split(':')[-1] for attr in SelectionProperty_List]

        LdapQuery   = context['LdapQuery']
        MaxElements = context['MaxElements']

        scope = SCOPE_ADLQ_TO_LDB[LdapQuery['Scope'].lower()]

        # --- Generic object class fix, part 1 ---
        # Always include objectClass in the LDB query so we can
        # determine the correct XML wrapper tag for each result object.
        # If the client did not ask for it we will strip it from the
        # attribute list before rendering.
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
        # whether there are more pages. If the control is absent or the
        # cookie is empty, this is the last (or only) page of results.
        ctrls = [
            str(c) for c in result.controls
            if str(c).startswith('paged_results')
        ]

        if ctrls:
            spl = ctrls[0].rsplit(':', 3)
            if len(spl) == 3:
                # A non-empty cookie means the server has more results.
                # Store it so the next Pull request picks up where this
                # one left off.
                new_cookie = ':' + spl[-1]
                enumeration_context['cookie'] = new_cookie
                context['is_end'] = False
            else:
                # Cookie is empty -- this is the final page.
                context['is_end'] = True
        else:
            # No paged_results control at all -- treat as final page.
            context['is_end'] = True

        # --- Generic object class fix, part 2 ---
        # Build (object_class, attrs) tuples for every result object.
        #
        # objectClass is multi-valued and ordered from least- to
        # most-derived. The last value is what we want: e.g. for a
        # user object the values are ['top', 'person',
        # 'organizationalPerson', 'user'] and we use 'user' as the
        # XML element name to match Windows AD behaviour.
        #
        # If the client did not originally request objectClass, we
        # build the attr list using only attr_names (excluding
        # objectClass) so it does not appear as an extra attribute in
        # the XML response.
        objects = []
        for msg in result.msgs:
            object_class = (
                str(msg['objectClass'][-1])
                if 'objectClass' in msg
                else 'top'  # safe fallback; should not occur in practice
            )

            # Build the attribute list using only what the client asked
            # for. objectClass is excluded here unless the client
            # explicitly requested it, keeping the response clean.
            attrs = self.build_attr_list(
                msg,
                attr_names=attr_names
            )

            objects.append((object_class, attrs))

        context['objects'] = objects
        return render_template('Pull.xml', **context)



# ============================================================================
# Interactive Shell Entry Point
# ============================================================================
# Running this file directly drops into an IPython shell with a live
# SamDB connection, useful for inspecting LDB data and testing queries
# interactively without going through the full ADWS proxy stack.
# ============================================================================
if __name__ == '__main__':
    from IPython import embed
    embed(header='Samba Python Shell')
