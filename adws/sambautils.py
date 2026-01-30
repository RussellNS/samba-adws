#!/usr/bin/env python3
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

# --- Polyfill for missing ldb constants ---
# Some versions of python3-ldb do not expose these constants directly.
# We define them safely here to prevent AttributeErrors.
SYNTAX_INTEGER = getattr(ldb, 'SYNTAX_INTEGER', 1)
SYNTAX_LARGE_INTEGER = getattr(ldb, 'SYNTAX_LARGE_INTEGER', 1)
SYNTAX_BOOLEAN = getattr(ldb, 'SYNTAX_BOOLEAN', 1)
SYNTAX_DIRECTORY_STRING = getattr(ldb, 'SYNTAX_DIRECTORY_STRING', 1)
SYNTAX_OCTET_STRING = getattr(ldb, 'SYNTAX_OCTET_STRING', 1)
SYNTAX_DN = getattr(ldb, 'SYNTAX_DN', 1)
SYNTAX_UTC_TIME = getattr(ldb, 'SYNTAX_UTC_TIME', 1)
SYNTAX_GENERALIZED_TIME = getattr(ldb, 'SYNTAX_GENERALIZED_TIME', 1)
SYNTAX_OBJECT_IDENTIFIER = getattr(ldb, 'SYNTAX_OBJECT_IDENTIFIER', 1)

HERE = dirname(abspath(__file__))
TEMPLATES = join(HERE, 'templates')

ENV = Environment(
    loader=FileSystemLoader(TEMPLATES),
    autoescape=select_autoescape(['xml']),
)

# https://msdn.microsoft.com/en-us/library/dd340513.aspx
SCOPE_ADLQ_TO_LDB = {
    'base': ldb.SCOPE_BASE,
    'onelevel': ldb.SCOPE_ONELEVEL,
    'subtree': ldb.SCOPE_SUBTREE,
}

def render_template(template_name, **kwargs):
    template = ENV.get_template(template_name)
    return template.render(**kwargs)

class SchemaSyntax(object):
    def __init__(self, oid, ldap_syntax, xsi_type='xsd:string'):
        self.oid = oid
        self.ldap_syntax = ldap_syntax
        self.xsi_type = xsi_type

    def render(self):
        return 'xml'

ROOT_DSE_GUID = '11111111-1111-1111-1111-111111111111'

def is_rootDSE(guid):
    return guid.strip() == ROOT_DSE_GUID

SCHEMA_SYNTAX_LIST = [
    SchemaSyntax(SYNTAX_INTEGER, 'Integer'),
    SchemaSyntax(SYNTAX_LARGE_INTEGER, 'LargeInteger'),
    SchemaSyntax(SYNTAX_BOOLEAN, 'Boolean'),
    SchemaSyntax(SYNTAX_DIRECTORY_STRING, 'UnicodeString'),
    SchemaSyntax(SYNTAX_OCTET_STRING, 'OctetString', xsi_type='xsd:base64Binary'),
    SchemaSyntax(SYNTAX_DN, 'DSDNString'),
    SchemaSyntax(SYNTAX_UTC_TIME, 'UTCTimeString'),
    SchemaSyntax(SYNTAX_GENERALIZED_TIME, 'GeneralizedTimeString'),
    SchemaSyntax(SYNTAX_OBJECT_IDENTIFIER, 'ObjectIdentifier'),
]

OID_SCHEMA_SYNTAX_DICT = {obj.oid: obj for obj in SCHEMA_SYNTAX_LIST}

ROOT_DSE_ATTRS = {
    'configurationNamingContext': SYNTAX_DN,
    'currentTime': SYNTAX_GENERALIZED_TIME,
    'defaultNamingContext': SYNTAX_DN,
    'dnsHostName': SYNTAX_DIRECTORY_STRING,
    'domainControllerFunctionality': SYNTAX_INTEGER,
    'domainFunctionality': SYNTAX_INTEGER,
    'dsServiceName': SYNTAX_DN,
    'forestFunctionality': SYNTAX_INTEGER,
    'highestCommittedUSN': SYNTAX_LARGE_INTEGER,
    'isGlobalCatalogReady': SYNTAX_BOOLEAN,
    'isSynchronized': SYNTAX_BOOLEAN,
    'ldapServiceName': SYNTAX_DIRECTORY_STRING,
    'namingContexts': SYNTAX_DN,
    'rootDomainNamingContext': SYNTAX_DN,
    'schemaNamingContext': SYNTAX_DN,
    'serverName': SYNTAX_DN,
    'subschemaSubentry': SYNTAX_DN,
    'supportedCapabilities': SYNTAX_OBJECT_IDENTIFIER,
    'supportedControl': SYNTAX_OBJECT_IDENTIFIER,
    'supportedLDAPVersion': SYNTAX_INTEGER,
    # 'verdorName': 'not exist',
}

LDAP_ATTR_TEMPLATE = jinja2.Template("""
<addata:{{obj.attr}} LdapSyntax="{{obj.ldap_syntax}}">
   {%- for val in obj.vals %}
   <ad:value xsi:type="{{obj.xsi_type}}">{{val}}</ad:value>
   {%- endfor %}
</addata:{{obj.attr}}>""".strip())


class LdapAttr(object):
    def __init__(self, attr, vals, ldap_syntax, xsi_type='xsd:string'):
        self.attr = attr  # e.g., sAMAccountName
        self.ldap_syntax = ldap_syntax
        #assert ':' in xsi_type
        self.xsi_type = xsi_type

        # Convert ldb.MessageElement or other iterables to a standard python list
        # This is critical because MessageElements are read-only views in C
        if hasattr(vals, '__iter__') and not isinstance(vals, (str, bytes)):
             self.vals = list(vals)
        else:
             self.vals = [vals]

        # Scan values for binary data
        for i, v in enumerate(self.vals):
            if isinstance(v, bytes):
                try:
                    # Attempt standard UTF-8 decode
                    self.vals[i] = v.decode('utf-8')
                except UnicodeDecodeError:
                    # Fallback for binary data (SIDs, GUIDs, etc.)
                    # 1. Encode to Base64 (returns bytes in Py3)
                    # 2. Decode to ASCII string so Jinja can render it
                    self.vals[i] = b64encode(v).decode('ascii')
                    
                    # CRITICAL FIX: If we base64 encoded it, we MUST tell Windows
                    # that the type is binary, otherwise it sees a string and crashes.
                    self.xsi_type = 'xsd:base64Binary'

    def to_xml(self):
        return LDAP_ATTR_TEMPLATE.render({'obj': self})


# https://msdn.microsoft.com/en-us/library/dd340577.aspx
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
        assert attr in SYNTHETIC_ATTRS
        self.attr = attr
        self.xsi_type = xsi_type

        # Ensure iterable list
        if not isinstance(vals, list):
            vals = [vals]
        
        self.vals = list(vals)

        # Handle binary encoding if necessary
        for i, v in enumerate(self.vals):
            if isinstance(v, bytes):
                try:
                    self.vals[i] = v.decode('utf-8')
                except UnicodeDecodeError:
                    self.vals[i] = b64encode(v).decode('ascii')
                    self.xsi_type = 'xsd:base64Binary'

    def to_xml(self):
        return SYNTHETIC_ATTR_TEMPLATE.render({'obj': self})

def get_rdn(dn):
    rdn_name = dn.get_rdn_name()
    rdn_value = dn.get_rdn_value()
    if rdn_name and rdn_value:
        return f'{rdn_name}={rdn_value}'
    return ''

class SamDBHelper(SamDB):

    def __init__(self):
        lp = LoadParm()
        lp.load_default()
        SamDB.__init__(self, lp=lp, session_info=system_session())

    def search_scope_base(self, *args, **kwargs):
        kwargs['scope'] = ldb.SCOPE_BASE
        return self.search(*args, **kwargs)

    def search_scope_onelevel(self, *args, **kwargs):
        kwargs['scope'] = ldb.SCOPE_ONELEVEL
        return self.search(*args, **kwargs)

    def search_scope_subtree(self, *args, **kwargs):
        kwargs['scope'] = ldb.SCOPE_SUBTREE
        return self.search(*args, **kwargs)

    def get_rootdse_attr_schema_syntax(self, attr):
        oid = ROOT_DSE_ATTRS.get(attr)
        return oid and OID_SCHEMA_SYNTAX_DICT.get(oid) or None

    def get_attr_schema_syntax(self, attr, is_root_dse=False):
        if is_root_dse:
            oid = ROOT_DSE_ATTRS.get(attr)
        else:
            oid = self.get_syntax_oid_from_lDAPDisplayName(attr)
        return oid and OID_SCHEMA_SYNTAX_DICT.get(oid) or None

    def build_attr_list(self, msg, is_root_dse=False, attr_names=[]):
        if not attr_names:
            attr_names = list(msg.keys())
            if 'dn' in attr_names: attr_names.remove('dn')
            if 'vendorName' in attr_names: attr_names.remove('vendorName')

        attrs = []
        for attr_name in attr_names:
            attr_obj = None
            vals = msg.get(attr_name, None)
            if vals is not None:
                if attr_name in SYNTHETIC_ATTRS:
                    attr_obj = SyntheticAttr(attr_name, vals)
                else:
                    syntax = self.get_attr_schema_syntax(
                        attr_name, is_root_dse=is_root_dse)
                    
                    # FIX: Fallback for missing syntax definitions (Mock Object)
                    if not syntax:
                        syntax = type('Syntax', (), {
                            'ldap_syntax': '1.3.6.1.4.1.1466.115.121.1.15', 
                            'xsi_type': 'xsd:string'
                        })

                    if syntax:
                        attr_obj = LdapAttr(
                            attr_name, vals,
                            syntax.ldap_syntax, syntax.xsi_type)
            else:
                if attr_name == 'relativeDistinguishedName':
                    attr_obj = SyntheticAttr(attr_name, [get_rdn(msg['dn'])])
            if attr_obj:
                attrs.append(attr_obj)

        return attrs


    def render_root_dse_xml(self, **context):
        # ldb.Result
        result = self.search(base='', scope=ldb.SCOPE_BASE)
        # ldb.MessageElement
        msg = result[0]

        attrs = self.build_attr_list(msg, is_root_dse=True)
        # this one appears first
        attrs.insert(0, SyntheticAttr('objectReferenceProperty', [ROOT_DSE_GUID]))
        # these 3 appear at last
        attrs.append(SyntheticAttr('container-hierarchy-parent', [ROOT_DSE_GUID]))
        attrs.append(SyntheticAttr('relativeDistinguishedName', ['']))
        attrs.append(SyntheticAttr('distinguishedName', ['']))
        context['attrs'] = attrs
        return render_template('root-DSE.xml', **context)


    def render_msds_portldap(self, **context):
        # return a fixed xml for now
        return render_template('msDS-PortLDAP.xml', **context)

    # def render_get(identifier, attrs, controls, **kwargs):
    def render_transfer_get(self, **context):
        # the attrs client is asking for, e.g: addata:msDS-PortLDAP
        AttributeType_List = context['AttributeType_List']
        # attrs without ns prefix, keep the order which matters
        attr_names = [attr.split(':')[-1] for attr in AttributeType_List]

        result = self.search(
            base=context['objectReferenceProperty'],
            attrs=attr_names,
            controls=[])

        msg = result[0]

        attrs = self.build_attr_list(msg, attr_names=attr_names)
        # attrs.append(SyntheticAttr('distinguishedName', [str(msg.dn)]))
        # attrs.append(SyntheticAttr('relativeDistinguishedName', ['TODO']))
        context['attrs'] = attrs

        return render_template('transfer-Get.xml', **context)

    def render_enumerate(self, **context):
        return render_template('Enumerate.xml', **context)

    def render_pull(self, **context):
        SelectionProperty_List = context['SelectionProperty_List']
        enumeration_context = context['EnumerationContext']
        cookie = enumeration_context.get('cookie', '')

        attr_names = [attr.split(':')[-1] for attr in SelectionProperty_List]
        LdapQuery = context['LdapQuery']
        MaxElements = context['MaxElements']

        scope = SCOPE_ADLQ_TO_LDB[LdapQuery['Scope'].lower()]
        result = self.search(
            base=LdapQuery['BaseObject'],
            scope=scope,
            expression=LdapQuery['Filter'],
            attrs=attr_names,
            controls=['paged_results:1:%s%s' % (MaxElements, cookie)]
        )

        ctrls = [str(c) for c in result.controls if
                 str(c).startswith("paged_results")]
        
        # Safety check for controls
        if ctrls:
            spl = ctrls[0].rsplit(':', 3)
            if len(spl) == 3:
                new_cookie = ':' + spl[-1]
                enumeration_context['cookie'] = new_cookie
                context['is_end'] = False
            else:
                context['is_end'] = True
        else:
             context['is_end'] = True

        objects = [
            self.build_attr_list(msg, attr_names=attr_names)
            for msg in result.msgs
        ]
        context['objects'] = objects

        return render_template('Pull.xml', **context)

    def render_topology_action(self, **context):
        """Responds to various Topology Management requests."""
        action = context.get('Action', '')
        message_id = context.get('MessageID')
        
        # Fetch basic domain info from RootDSE
        res = self.search(base="", scope=ldb.SCOPE_BASE, attrs=["dnsHostName", "defaultNamingContext"])
        dns_hostname = str(res[0].get("dnsHostName", "samba.vlab.test"))
        distinguished_name = str(res[0].get("defaultNamingContext", "DC=vlab,DC=test"))
        netbios_name = dns_hostname.split('.')[0].upper()

        # CASE 1: Get-ADDomainController
        if 'GetADDomainController' in action:
            response_action = "http://schemas.microsoft.com/2008/1/ActiveDirectory/Topology/GetADDomainControllerResponse"
            body_content = (
                f'<GetADDomainControllerResponse xmlns="http://schemas.microsoft.com/2008/1/ActiveDirectory/Topology">'
                f'<GetADDomainControllerResult>'
                f'<DestinationServer>{dns_hostname}</DestinationServer>'
                f'<HostName>{dns_hostname}</HostName>'
                f'<NetbiosName>{netbios_name}</NetbiosName>'
                f'<Site>Default-First-Site-Name</Site>'
                f'</GetADDomainControllerResult>'
                f'</GetADDomainControllerResponse>'
            )

        # CASE 2: Get-ADDomain
        elif 'GetADDomain' in action:
            response_action = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/TopologyManagement/GetADDomainResponse"
            # Note: The result often needs to be explicitly namespaced or contain the identity
            body_content = (
                f'<GetADDomainResponse xmlns="http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/TopologyManagement">'
                f'<GetADDomainResult xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory">'
                f'<ad:DistinguishedName>{distinguished_name}</ad:DistinguishedName>'
                f'<ad:DNSRoot>{dns_hostname}</ad:DNSRoot>'
                f'<ad:NetBIOSName>{netbios_name}</ad:NetBIOSName>'
                f'</GetADDomainResult>'
                f'</GetADDomainResponse>'
            )
        else:
            return None

        # Return the envelope with NO leading whitespace in the body
        return (f'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">'
                f'<s:Header>'
                f'<a:Action s:mustUnderstand="1">{response_action}</a:Action>'
                f'<a:RelatesTo>{message_id}</a:RelatesTo>'
                f'</s:Header>'
                f'<s:Body>{body_content}</s:Body>'
                f'</s:Envelope>')

if __name__ == '__main__':
    from IPython import embed
    embed(header='Samba Python Shell')
