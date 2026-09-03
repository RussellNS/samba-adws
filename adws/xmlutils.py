#!/usr/bin/env python
# coding: utf8
import os
import re

from lxml import etree

NAMESPACES = {
    "a": "http://www.w3.org/2005/08/addressing",
    "ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
    "addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
    "adlq": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery",
    "b": "http://schemas.microsoft.com/2003/10/Serialization/Arrays",
    "da": "http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess",
    "s": "http://www.w3.org/2003/05/soap-envelope",
    "wsen": "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
    "xsd": "http://www.w3.org/2001/XMLSchema",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
}


def elem_get_text(elem):
    if elem is not None:
        text = elem.text
        if text is not None:
            return text.strip()
    return ''


def elem_is_empty(elem):
    # no text, no children, then empty
    return len(elem) == 0 and elem_get_text(elem) == ''


def elem_tostring(elem, pretty_print=True, encoding='unicode'):
    """pretty and unicode by default"""
    return etree.tostring(
        elem, pretty_print=pretty_print, encoding=encoding)



def print_xml(xml, sn=0, mode='w+'):
    """
    Validate an XML string and dump it for inspection.

    The parse is not incidental -- it is what catches malformed
    responses before they are encoded and sent, so it stays even when
    the dump target changes.

    Destination is the ADWS_RECORD_DIR directory when recording is
    enabled (so the SOAP exchange sits alongside the LDB calls it
    provoked), otherwise the historical /tmp/<n>.xml location. Each
    file holds the request followed by the response for that exchange.
    """
    # parse to validate
    root = etree.fromstring(xml)

    # Imported lazily to keep this module importable without the rest
    # of the adws package (tests import xmlutils on its own).
    from adws.record import record_dir

    target_dir = record_dir() or '/tmp'
    try:
        os.makedirs(target_dir, exist_ok=True)
    except OSError:
        target_dir = '/tmp'

    with open(os.path.join(target_dir, '%s.xml' % sn), mode) as f:
        f.write(xml + '\n\n\n')


def rm_whitespaces(text):
    """rm any whitespaces from text"""
    return re.sub(r'\s+', '', text, flags=re.UNICODE)


def compare_xml(xml1, xml2):
    return rm_whitespaces(xml1) == rm_whitespaces(xml2)


class XMLHelper(object):
    """
    A class helps to extract data from xml.
    """

    def __init__(self, xml):
        self.xml = xml
        self.root = etree.fromstring(xml)
        self.nsmap = self.root.nsmap
        # root ns + common ns
        self.nsmap.update(NAMESPACES)

        self.header = self.get_elem('s:Header')
        self.body = self.get_elem('s:Body')

    def get_elem(self, xpath, as_text=False):
        elem = self.root.find(xpath, namespaces=self.nsmap)
        return elem_get_text(elem) if as_text else elem

    def get_elem_text(self, xpath):
        return self.get_elem(xpath, as_text=True)

    def get_elem_list(self, xpath, as_text=False):
        elems = self.root.findall(xpath, namespaces=self.nsmap)
        return [elem.text.strip() for elem in elems] if as_text else elems

    def is_elem_empty(self, xpath):
        """
        A empty element has no text and children

        e.g.: <s:Body></s:Body>
        """
        elem = self.root.find(xpath, self.nsmap)
        return elem_is_empty(elem)

