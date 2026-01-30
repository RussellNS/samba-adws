#!/usr/bin/env python3
# encoding: utf-8
# Refactored for Python 3.13 compatibility
# Original Copyright 2016 Timo Schmid

import logging
from logging.config import dictConfig
import socketserver as SocketServer # Python 3 renamed SocketServer to socketserver

# ADWS and WCF Specific Imports
from helperlib import print_hexdump
from nettcp import nmf
from nettcp.stream.socket import SocketStream
from nettcp.stream.gssapi import GSSAPIStream, GENSECStream
from wcf.xml2records import XMLParser
from wcf.records import dump_records
from adws import sambautils
from adws import xmlutils

# --- Logging Configuration ---
LOG_FORMAT = ('%(levelname)-10s %(asctime)s pid:%(process)d '
              '%(name)s %(pathname)s #%(lineno)d: %(message)s')

LOG_CONFIG = {
    'version': 1,
    'incremental': False,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {'format': LOG_FORMAT},
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
            'level': logging.DEBUG,
        },
    },
    'root': {
        'handlers': ['console'],
        'level': logging.DEBUG,
    },
    'loggers': {
        'wcf': {'level': logging.WARN},
        'nettcp': {'level': logging.WARN},
        'adws': {'level': logging.DEBUG},
    },
}

dictConfig(LOG_CONFIG)
log = logging.getLogger(__name__)

# must be after dictConfig, otherwise log in these packages
# will not be configed as expected
import sys
import uuid
import binascii
import argparse

"""
# Omitting the following code
# Retaining in comment to document that it existed before

try:
    import SocketServer
except ImportError:
    import socketserver as SocketServer

from helperlib import print_hexdump

from nettcp import nmf
from nettcp.stream.socket import SocketStream
from nettcp.stream.gssapi import GSSAPIStream, GENSECStream

from wcf.xml2records import XMLParser
from wcf.records import dump_records

from adws import sambautils
from adws import xmlutils
"""

def print_data(msg, data):
    """
    Functionality: Prints hexdump of data to stderr if DEBUG is enabled.
    Refactor: Ensured 'data' is treated as bytes for hexdump.
    """
    if log.isEnabledFor(logging.DEBUG):
        print(msg, file=sys.stderr)
        # In Python 3, hexdump requires bytes/bytearray
        if isinstance(data, str):
            data = data.encode('utf-8', errors='replace')
        print_hexdump(data, colored=True, file=sys.stderr)


class NETTCPProxy(SocketServer.BaseRequestHandler):
    """
    Class: NETTCPProxy
    Property: self.stream (Initialized in handle)
    Property: self.request (TCP Socket provided by SocketServer)
    """

    def send_record(self, record):
        """
        Method: send_record
        Functionality: Converts a WCF record to bytes and writes to the stream.
        Modification: record.to_bytes() must return a 'bytes' object in Python 3.
        """
        log.debug(f'<<<<Server record: {record}')
        self.stream.write(record.to_bytes())

    def handle(self):
        """
        Method: handle
        Functionality: Main loop for the ADWS Proxy. Handles GSSAPI negotiation,
        XML parsing of SOAP requests, and database rendering via SambaUtils.

        this func is called in __init__ of base class
        """
        log.info('start handle request')

        # Dictionary to store search contexts between Enumerate and Pull requests
        EnumerationContext_Dict = {}
        
        # Wrapping the raw socket in a SocketStream for .read()/.write() support
        self.stream = SocketStream(self.request)
        negotiated = False
        request_index = 0

        # Samba helper to interact with the local AD database (LDB)
        samdbhelper = sambautils.SamDBHelper()

        while True:
            log.debug('\n\nstart parsing stream...')
            
            # Reads from the stream and interprets the .NET Message Framing (nmf)
            obj = nmf.Record.parse_stream(self.stream)
            if not obj:
                break
            log.info(f'>>>>Client record: {obj}')

            # data = obj.to_bytes()

            # self.log_data('c>s', data)

            # print_data('Got Data from client:', data)

            # self.stream.write(data)

            # --- Record Type Handling ---
            if obj.code == nmf.KnownEncodingRecord.code:
                # if self.negotiate:
                #     upgr = UpgradeRequestRecord(UpgradeProtocolLength=21,
                #                                 UpgradeProtocol='application/negotiate').to_bytes()
                #    s.sendall(upgr)
                #     resp = Record.parse_stream(SocketStream(s))
                #     assert resp.code == UpgradeResponseRecord.code, resp
                    # self.stream = GSSAPIStream(self.stream, self.server_name)
                # start receive thread
                # t.start()
                pass
            
            elif obj.code == nmf.UpgradeRequestRecord.code:
                # Handle .NET Framing protocol upgrade (usually to GSSAPI/GENSEC)
                self.send_record(nmf.UpgradeResponseRecord())
                if not negotiated:
                    log.info('negotiate started')
                    self.stream = GENSECStream(self.stream)
                    self.stream.negotiate_server()
                    negotiated = True
                    log.info('negotiate finished')
                else:
                    log.info('negotiate skipped')
                    
            elif obj.code == nmf.PreambleEndRecord.code:
                # Acknowledge the end of the .NET framing preamble
                self.send_record(nmf.PreambleAckRecord())
                
            elif obj.code == nmf.SizedEnvelopedMessageRecord.code:
                # This is a SOAP/XML Message
                # payload_to_xml() must return a STR in Python 3
                xml = obj.payload_to_xml()

                # Log XML to file/console for debugging
                xmlutils.print_xml(xml, request_index, mode='w+')

                # Initialize XML helper for XPath queries
                xmlhelper = xmlutils.XMLHelper(xml)

                # Extract LDAP attributes requested by the client
                # could be LDAP attrs or
                # synthetic attrs with namespace prefix
                AttributeType_List = xmlhelper.get_elem_list(
                    './/s:Body/da:BaseObjectSearchRequest/da:AttributeType',
                    as_text=True)

                # Build context mapping for the AD backend
                context = {
                    'MessageID': xmlhelper.get_elem_text('.//a:MessageID'),
                    'objectReferenceProperty': xmlhelper.get_elem_text('.//ad:objectReferenceProperty'),
                    'Action': xmlhelper.get_elem_text('.//a:Action'),
                    'To': xmlhelper.get_elem_text('.//a:To'),
                    'AttributeType_List': AttributeType_List,
                }

                ack_xml = None

                # --- SOAP Action Routing ---
                
                # Action: Get (Object Read)
                if context['Action'] == 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Get':
                    if sambautils.is_rootDSE(context['objectReferenceProperty']):
                        # search rootDSE
                        if not AttributeType_List:
                            ack_xml = samdbhelper.render_root_dse_xml(**context)
                        elif AttributeType_List == ['addata:msDS-PortLDAP']:
                            ack_xml = samdbhelper.render_msds_portldap(**context)
                    else:
                        # search object
                        ack_xml = samdbhelper.render_transfer_get(**context)
                
                # Action: Enumerate (Start Search)
                elif context['Action'] == 'http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate':
                    enumeration_context = {}
                    ldapquery_elem = xmlhelper.get_elem('.//adlq:LdapQuery')
                    adlq_len = len(xmlutils.NAMESPACES['adlq']) + 2
                    # tag: '{http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery}Filter'

                    # Use dictionary comprehension to map LDAP filters
                    enumeration_context['LdapQuery'] = {
                        child.tag[adlq_len:]: (child.text or "").strip()
                        for child in ldapquery_elem
                    }
                    enumeration_context['SelectionProperty_List'] = xmlhelper.get_elem_list(
                        './/ad:SelectionProperty', as_text=True)

                    # Generate a unique handle for the client to reference this search
                    EnumerationContext = str(uuid.uuid1())
                    EnumerationContext_Dict[EnumerationContext] = enumeration_context

                    context['EnumerationContext'] = EnumerationContext
                    ack_xml = samdbhelper.render_enumerate(**context)

                # Action: Pull (Fetch Search Results)
                elif context['Action'] == 'http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull':
                    context['MaxElements'] = xmlhelper.get_elem_text('.//wsen:MaxElements')
                    EnumerationContext = xmlhelper.get_elem_text('.//wsen:EnumerationContext')

                    # Retrieve saved search context
                    if EnumerationContext in EnumerationContext_Dict:
                        enumeration_context = EnumerationContext_Dict[EnumerationContext]
                        context['EnumerationContext'] = enumeration_context
                        context.update(enumeration_context)
                        ack_xml = samdbhelper.render_pull(**context)

                # Action: Topology (New)
                elif context['Action'] and 'Topology' in context['Action']:
                    log.info(f"Handling Topology Action: {context['Action']}")
                    ack_xml = samdbhelper.render_topology_action(**context)

                # --- Response Construction ---
                if not ack_xml:
                    log.error(f"Unhandled SOAP Action or missing response XML for Action: {context['Action']}")
                    break

                xmlutils.print_xml(ack_xml, request_index, mode='a')
                request_index += 1

                # XMLParser.parse (from MyHTMLParser.py) now handles bytes/str
                # Here we encode to bytes to be safe with the WCF binary encoder
                records = XMLParser.parse(ack_xml.encode('utf-8'))
                payload = dump_records(records)

                # WCF Envelope overhead (+1 byte for the record type marker)
                size = len(payload) + 1
                log.debug(f'output payload size: {size}')
                
                # Create the WCF binary message record
                ack = nmf.SizedEnvelopedMessageRecord(
                    Payload=b'\x00' + payload,
                    Size=size
                )
                
                self.send_record(ack)
                
            elif obj.code == nmf.EndRecord.code:
                break

    def finish(self):
        """
        Method: finish
        Functionality: Clean up the stream on connection close.
        """
        if hasattr(self, 'stream'):
            self.stream.close()
        log.info('close stream and exit handle')


def main():
    """
    Function: main
    Functionality: Entry point. Parses CLI args and starts the Forking TCP Server.
    Modification: Updated to use Python 3 socketserver.
    """
    parser = argparse.ArgumentParser(description="ADWS Proxy Refactored for Python 3")
    parser.add_argument('-b', '--bind', default='localhost')
    parser.add_argument('-p', '--port', type=int, default=9389)
    args = parser.parse_args()

    # Initialize the NMF record type registry
    nmf.register_types()

    # ForkingTCPServer handles each connection in a new process (Unix/Linux)
    server = SocketServer.ForkingTCPServer((args.bind, args.port), NETTCPProxy)
    log.info(f"Serving ADWS on {args.bind}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
