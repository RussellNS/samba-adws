#!/usr/bin/env python3
# encoding: utf-8
# Refactored for Python 3.13 compatibility
# Original Copyright 2016 Timo Schmid

import sys
import argparse
import logging
import ldb
import socketserver
from samba.auth import system_session
from samba.samdb import SamDB
from samba.param import LoadParm
from jinja2 import Environment, FileSystemLoader

# Internal WCF/ADWS modules
from wcf.records import *
from wcf.xml2records import XMLParser
from wcf.records2xml import RecordParser
from sambautils import SamDBHelper

# --- Logging Configuration ---
logging.basicConfig(level=logging.DEBUG, format='%(levelname)-10s %(asctime)s pid:%(process)d %(filename)s #%(lineno)d: %(message)s')

# Setup Jinja2
env = Environment(loader=FileSystemLoader('/opt/samba-adws/templates'))

def render_template(template_name, **context):
    template = env.get_template(template_name)
    return template.render(**context)

class ADWSProxyHandler(socketserver.StreamRequestHandler):
    """
    Blends the original binary record handling with new SOAP routing.
    """
    def handle(self):
        logging.info(f"Start handle request from {self.client_address}")
        lp = LoadParm()
        lp.load_default()
        self.samdb = SamDB(url="/var/lib/samba/private/sam.db", session_info=system_session(), lp=lp)
        self.samdb_helper = SamDBHelper(self.samdb)
        
        try:
            # 1. Handle WCF Preamble (Simplified representation of the handshake)
            while True:
                data = self.rfile.read(1)
                if not data: break
                record_type = data[0]

                # If it's a SizedEnvelopedMessage (Standard SOAP wrapper)
                if record_type == 0x0b: 
                    size = self.read_vint()
                    payload = self.rfile.read(size)
                    xml_content = RecordParser.parse(payload)
                    
                    # Route the XML content
                    response_xml = self.process_soap_routing(xml_content)
                    
                    if response_xml:
                        self.send_wcf_message(response_xml)
                
                # Handling Preamble Records (Version, Mode, etc.)
                elif record_type in [0x00, 0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x09]:
                    # These are standard WCF Handshake records
                    # Original logic handled these as a pass-through
                    pass 
        except Exception as e:
            logging.error(f"Error in handler: {e}", exc_info=True)

    def read_vint(self):
        """Reads a WCF Variable Integer."""
        n = 0
        s = 0
        while True:
            b = self.rfile.read(1)[0]
            n |= (b & 0x7f) << s
            s += 7
            if not (b & 0x80): break
        return n

    def process_soap_routing(self, xml_string):
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_string)
        ns = {
            's': 'http://www.w3.org/2003/05/soap-envelope',
            'a': 'http://www.w3.org/2005/08/addressing'
        }
        
        action_node = root.find('.//a:Action', ns)
        if action_node is None: return None
        
        action = action_node.text
        message_id = root.find('.//a:MessageID', ns).text
        context = {'MessageID': message_id, 'Action': action}

        logging.info(f">>>> Incoming SOAP Action: {action}")

        # --- ROUTE TO SPECIFIC HANDLERS ---
        if "enumeration/Enumerate" in action:
            return self.samdb_helper.render_enumerate(root=root, **context)
        
        elif "enumeration/Pull" in action:
            # Now uses the dynamic 'render_pull' we modified earlier
            return self.samdb_helper.render_pull(root=root, **context)

        elif "TopologyManagement/GetAD" in action:
            return self.handle_topology(action, context)

        # ADAC uses WS-Transfer GET to fetch specific object details
        elif "transfer/Get" in action:
            return self.handle_transfer_get(root, context)

        return None

    def handle_topology(self, action, context):
        """Generic handler for Domain/Forest discovery."""
        is_forest = "GetADForest" in action
        base_dn = str(self.samdb.get_root_basedn() if is_forest else self.samdb.get_default_basedn())
        
        context['ResponseTag'] = action.split('/')[-1] + "Response"
        context['Namespace'] = "http://schemas.microsoft.com/2008/1/ActiveDirectory/CustomActions/TopologyManagement"
        
        # Simple fetch of the root object
        res = self.samdb.search(base=base_dn, scope=ldb.SCOPE_BASE)
        objects = [{'type': 'forest' if is_forest else 'domain', 
                    'attrs': self.samdb_helper.build_attr_list(res[0])}]
        
        context['objects'] = objects
        return render_template('GetADObject.xml', **context)

    def send_wcf_message(self, xml_string):
        """Converts XML back to binary and sends over the wire."""
        records = XMLParser.parse(xml_string.encode('utf-8'))
        payload = b''.join([r.to_bytes() for r in records])
        
        # Sized Envelope Record Header (0x0b) + VInt Size
        self.wfile.write(b'\x0b')
        size = len(payload)
        while size > 0x7f:
            self.wfile.write(bytes([(size & 0x7f) | 0x80]))
            size >>= 7
        self.wfile.write(bytes([size]))
        self.wfile.write(payload)

def main():
    parser = argparse.ArgumentParser(description='Samba ADWS Proxy')
    parser.add_argument('--host', default='0.0.0.0', help='Listen host')
    parser.add_argument('--port', type=int, default=9389, help='Listen port')
    args = parser.parse_args()

    # Register WCF Record Types (Similar to your original registry)
    # The record classes should already be imported from wcf.records
    
    logging.info(f"Starting ADWS Proxy on {args.host}:{args.port}")
    server = socketserver.ThreadingTCPServer((args.host, args.port), ADWSProxyHandler)
    server.lp = LoadParm()
    server.lp.load_default()
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == '__main__':
    main()
