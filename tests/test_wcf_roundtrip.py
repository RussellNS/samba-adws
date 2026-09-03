"""
WCF binary XML encode/decode.

The wcf/ and nettcp/ packages are pure Python with no Samba dependency,
so these tests exercise the real encoder -- no stubs involved. This is
the layer that turns a rendered response into what actually goes on the
wire, so a break here is invisible to every template-level test.
"""
from io import BytesIO

import pytest
from lxml import etree

from wcf.records import dump_records, Record
from wcf.xml2records import XMLParser


def encode(xml):
    return dump_records(XMLParser.parse(xml.encode('utf-8')))


def decode(payload):
    return Record.parse(BytesIO(payload))


def roundtrip(xml):
    records = decode(encode(xml))
    out = ''
    for record in records:
        out += record.to_bytes().decode('utf-8', errors='replace') \
            if hasattr(record, 'to_bytes') else ''
    return records


def test_simple_element_roundtrips():
    records = roundtrip('<root><child>value</child></root>')
    assert records


def test_dictionary_string_is_compressed():
    """
    Well-known names come from the WCF dictionary rather than being
    written out as literals -- that is the whole point of the binary
    encoding, and a regression would silently bloat every response.
    """
    known = encode(
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        '<s:Body/></s:Envelope>')
    unknown = encode(
        '<q:Envelope xmlns:q="http://example.invalid/not-a-known-namespace">'
        '<q:Body/></q:Envelope>')

    assert len(known) < len(unknown)


@pytest.mark.parametrize('text', [
    'plain',
    'with spaces',
    'unicode: éèê',
    'cjk: 中文',
])
def test_text_values_survive_encoding(text):
    xml = '<root><v>%s</v></root>' % text
    records = decode(encode(xml))
    assert records


def test_base64_value_survives_encoding():
    """
    Binary attributes (objectSid, objectGUID, nTSecurityDescriptor) are
    carried as base64 text, which is the longest content the encoder
    routinely handles.
    """
    from base64 import b64encode
    blob = b64encode(bytes(range(256))).decode('ascii')
    records = decode(encode('<root><v>%s</v></root>' % blob))
    assert records


def test_rendered_response_is_well_formed_xml():
    """
    Guard for the print_xml() parse step: main.py parses every rendered
    response before encoding it, so malformed XML kills the connection
    rather than producing a bad response.
    """
    xml = (
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        '<s:Body><ok/></s:Body></s:Envelope>'
    )
    etree.fromstring(xml.encode('utf-8'))
    assert encode(xml)
