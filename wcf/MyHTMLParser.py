"""
A parser for HTML and XHTML, refactored for Python 3.x and ADWS compatibility.
This file preserves case-sensitivity for tags and attributes while handling 
the string/bytes strictness of modern Python.
"""

import re
import logging
import html.entities as htmlentitydefs

try:
    import _markupbase as markupbase
except ImportError:
    # Fallback for environments where internal modules are structured differently
    from . import _markupbase as markupbase

# Configure logging to replace old print/sys.stderr style
logger = logging.getLogger(__name__)

# --- Regular expressions preserved from original to maintain case-sensitivity ---
interesting_normal = re.compile('[&<]')
interesting_cdata = re.compile(r'<(/|\Z)')
incomplete = re.compile('&[a-zA-Z#]')

entityref = re.compile('&([a-zA-Z][-.a-zA-Z0-9]*)[^a-zA-Z0-9]')
charref = re.compile('&#(?:[0-9]+|[xX][0-9a-fA-F]+)[^0-9a-fA-F]')

starttagopen = re.compile('<[a-zA-Z]')
piclose = re.compile('>')
commentclose = re.compile(r'--\s*>')
tagfind = re.compile('[a-zA-Z][-.a-zA-Z0-9:_]*')
attrfind = re.compile(
    r'\s*([a-zA-Z_][-.:a-zA-Z_0-9]*)(\s*=\s*'
    r'(\'[^\']*\'|"[^"]*"|[^\s"\'=<>`]*))?')

locatestarttagend = re.compile(r"""
  <[a-zA-Z][-.a-zA-Z0-9:_]* # tag name
  (?:\s+                             # whitespace before attribute name
    (?:[a-zA-Z_][-.:a-zA-Z0-9_]* # attribute name
      (?:\s*=\s* # value indicator
        (?:'[^']*'                   # LITA-enclosed value
          |\"[^\"]*\"                # LIT-enclosed value
          |[^'\">\s]+                # bare value
         )
       )?
     )
   )*
  \s* # trailing whitespace
""", re.VERBOSE)
endendtag = re.compile('>')
endtagfind = re.compile('</\s*([a-zA-Z][-.a-zA-Z0-9:_]*)\s*>')

class HTMLParseError(Exception):
    """Exception raised for all parse errors."""
    def __init__(self, msg, position=(None, None)):
        self.msg = msg
        self.lineno = position[0]
        self.offset = position[1]
        super().__init__(msg)

    def __str__(self):
        result = self.msg
        if self.lineno is not None:
            result = f"{result}, at line {self.lineno}"
        if self.offset is not None:
            result = f"{result}, column {self.offset + 1}"
        return result

class HTMLParser(markupbase.ParserBase):
    """
    #############################
    # Refactored for Python 3.x #
    #############################

    Find tags and other markup and call handler functions.
    Refactored to handle str/bytes and maintain case-sensitivity.

    Usage:
        p = HTMLParser()
        p.feed(data)
        ...
        p.close()

    Start tags are handled by calling self.handle_starttag() or
    self.handle_startendtag(); end tags by self.handle_endtag().  The
    data between tags is passed from the parser to the derived class
    by calling self.handle_data() with the data as argument (the data
    may be split up in arbitrary chunks).  Entity references are
    passed by calling self.handle_entityref() with the entity
    reference as the argument.  Numeric character references are
    passed to self.handle_charref() with the string containing the
    reference as the argument.
    """

    CDATA_CONTENT_ELEMENTS = ("script", "style")

    def __init__(self):
        """Initialize and reset this instance."""
        self.reset()

    def reset(self):
        """Reset this instance. Loses all unprocessed data."""
        self.rawdata = ''
        self.lasttag = '???'
        self.interesting = interesting_normal
        # Use super() for Python 3 inheritance
        super().reset()

    def feed(self, data):
        """
        Feed data to the parser.

        MODIFICATION: Added Type Guard to handle bytes or strings.

        Call this as often as you want, with as little or as much text
        as you want (may include '\n').
        """
        if data is None:
            return

        # Type Guard: Convert bytes to string if necessary
        if isinstance(data, bytes):
            try:
                data = data.decode('utf-8')
            except UnicodeDecodeError:
                data = data.decode('iso-8859-1')

        self.rawdata = self.rawdata + data
        self.goahead(0)

    def close(self):
        """Handle any buffered data."""
        self.goahead(1)

    def error(self, message):
        """Standardizes error handling."""
        raise HTMLParseError(message, self.getpos())

    # Internal property tracking
    __starttag_text = None

    def get_starttag_text(self):
        """Return full source of start tag: '<...>'."""
        return self.__starttag_text

    def set_cdata_mode(self):
        self.interesting = interesting_cdata

    def clear_cdata_mode(self):
        self.interesting = interesting_normal

    # Internal -- handle data as far as reasonable.  May leave state
    # and data to be processed by a subsequent call.  If 'end' is
    # true, force handling all data as if followed by EOF marker.
    def goahead(self, end):
        """Internal loop to process the rawdata buffer."""
        """
        Internal loop to process the rawdata buffer.

        Refactored for Python 3.13 to remove legacy localized variable
        optimizations and ensure string safety.
        """
        rawdata = self.rawdata
        i = 0
        n = len(rawdata)
        while i < n:
            match = self.interesting.search(rawdata, i)
            if match:
                j = match.start()
            else:
                j = n
            
            if i < j: 
                self.handle_data(rawdata[i:j])
            
            i = self.updatepos(i, j)
            if i == n: break

            #startswith = rawdata.startswith
            if rawdata.startswith('<', i):
                if starttagopen.match(rawdata, i): # < + letter
                    k = self.parse_starttag(i)
                elif rawdata.startswith("</", i):
                    k = self.parse_endtag(i)
                elif rawdata.startswith("<!--", i):
                    k = self.parse_comment(i)
                elif rawdata.startswith("<?", i):
                    k = self.parse_pi(i)
                elif rawdata.startswith("<!", i):
                    k = self.parse_declaration(i)
                elif (i + 1) < n:
                    self.handle_data("<")
                    k = i + 1
                else:
                    break
                if k < 0:
                    if end:
                        self.error("EOF in middle of construct")
                    break
                i = self.updatepos(i, k)
            elif rawdata.startswith("&#", i):
                match = charref.match(rawdata, i)
                if match:
                    name = match.group()[2:-1]
                    self.handle_charref(name)
                    k = match.end()
                    if not rawdata.startswith(';', k-1):
                        k = k - 1
                    i = self.updatepos(i, k)
                    continue
                else:
                    if ";" in rawdata[i:]: #bail by consuming &#
                        self.handle_data(rawdata[0:2])
                        i = self.updatepos(i, 2)
                    break
            elif rawdata.startswith('&', i):
                match = entityref.match(rawdata, i)
                if match:
                    name = match.group(1)
                    self.handle_entityref(name)
                    k = match.end()
                    if not rawdata.startswith(';', k-1):
                        k = k - 1
                    i = self.updatepos(i, k)
                    continue
                match = incomplete.match(rawdata, i)
                if match:
                    # match.group() will contain at least 2 chars
                    if end and match.group() == rawdata[i:]:
                        self.error("EOF in middle of entity or char ref")
                    # incomplete
                    break
                elif (i + 1) < n:
                    # not the end of the buffer, and can't be confused
                    # with some other construct
                    self.handle_data("&")
                    i = self.updatepos(i, i + 1)
                else:
                    break
            else:
                assert 0, "interesting.search() lied"
        # end while
        if end and i < n:
            self.handle_data(rawdata[i:n])
            i = self.updatepos(i, n)
        self.rawdata = rawdata[i:]

# --- Internal Parsing Methods ---

    def parse_pi(self, i):
        """Internal -- parse processing instruction, return end or -1."""
        rawdata = self.rawdata
        assert rawdata[i:i+2] == '<?', 'unexpected call to parse_pi()'
        match = piclose.search(rawdata, i+2) # Search for '>'
        if not match:
            return -1
        j = match.start()
        self.handle_pi(rawdata[i+2: j])
        return match.end()

    def parse_starttag(self, i):
        """
        Internal -- parse starttag, return end or -1 if not terminated
        PRESERVES CASE for ADWS XML compliance.
        """
        self.__starttag_text = None
        endpos = self.check_for_whole_start_tag(i)
        if endpos < 0:
            return endpos
        
        rawdata = self.rawdata
        self.__starttag_text = rawdata[i:endpos]

        # Now parse the data between i+1 and j into a tag and attrs
        attrs = []
        match = tagfind.match(rawdata, i+1)
        assert match, 'unexpected call to parse_starttag()'
        k = match.end()
        
        # KEY REFACTOR: Removed .lower() to maintain exact ADWS tag names
        self.lasttag = tag = rawdata[i+1:k]

        while k < endpos:
            m = attrfind.match(rawdata, k)
            if not m:
                break
            attrname, rest, attrvalue = m.group(1, 2, 3)
            if not rest:
                attrvalue = None
            elif (attrvalue[0] == "'" == attrvalue[-1]) or \
                 (attrvalue[0] == '"' == attrvalue[-1]):
                attrvalue = attrvalue[1:-1]
                attrvalue = self.unescape(attrvalue)
            attrs.append((attrname, attrvalue))
            k = m.end()

        end = rawdata[k:endpos].strip()
        if end not in (">", "/>"):
            self.error(f"junk characters in start tag: {rawdata[k:endpos][:20]!r}")
            
        if end.endswith('/>'):
            # XHTML-style empty tag: <span />
            self.handle_startendtag(tag, attrs)
        else:
            self.handle_starttag(tag, attrs)
            if tag.lower() in self.CDATA_CONTENT_ELEMENTS:
                self.set_cdata_mode()
        return endpos

    def check_for_whole_start_tag(self, i):
        """
        Internal -- check to see if we have a complete starttag,
        returns end of tag or -1 if incomplete.
        """
        rawdata = self.rawdata
        m = locatestarttagend.match(rawdata, i)
        if m:
            j = m.end()
            next_char = rawdata[j:j+1]
            if next_char == ">":
                return j + 1
            if next_char == "/":
                if rawdata.startswith("/>", j):
                    return j + 2
                if rawdata.startswith("/", j):
                    # Buffer boundary
                    return -1
                # Malformed
                self.updatepos(i, j + 1)
                self.error("malformed empty start tag")
            if next_char == "":
                return -1
            if next_char in "abcdefghijklmnopqrstuvwxyz=/ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                # end of input in or before attribute value, or we have the
                # '/' from a '/>' ending
                return -1
            self.updatepos(i, j)
            self.error("malformed start tag")
        return -1

    def parse_endtag(self, i):
        """Internal -- parse endtag, return end or -1 if incomplete"""
        rawdata = self.rawdata
        assert rawdata[i:i+2] == "</", "unexpected call to parse_endtag"
        match = endendtag.search(rawdata, i+1)
        if not match:
            return -1
        j = match.end()
        match = endtagfind.match(rawdata, i)
        if not match:
            self.error(f"bad end tag: {rawdata[i:j]!r}")
        tag = match.group(1)
        self.handle_endtag(tag)
        self.clear_cdata_mode()
        return j

    # --- Overridable Handlers (Stubs) ---
    def handle_startendtag(self, tag, attrs):
      """
      Finish processing of start+end tag: <tag.../>
      """
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    # Overridable -- handle start tag
    def handle_starttag(self, tag, attrs): pass

    # Overridable -- handle end tag
    def handle_endtag(self, tag): pass

    # Overridable -- handle character reference
    def handle_charref(self, name): pass

    # Overridable -- handle entity reference
    def handle_entityref(self, name): pass

    # Overridable -- handle entity reference
    def handle_data(self, data): pass

    # Overridable -- handle comment
    def handle_comment(self, data): pass

    # Overridable -- handle declaration
    def handle_decl(self, decl): pass

    # Overridable -- handle processing instruction
    def handle_pi(self, data): pass

    def unknown_decl(self, data):
        self.error(f"unknown declaration: {data!r}")

    # --- Entity Unescaping Logic ---
    # Internal -- helper to remove special character quoting
    entitydefs = None
    def unescape(self, s):
        """
        Refactored for Python 3.13. 
        Replaces manual dictionary iteration with modern dict.items().
        """
        if '&' not in s:
            return s
        
        def replaceEntities(m):
            s = m.group(1)
            try:
                if s[0] == "#":
                    s = s[1:]
                    # Hex vs Decimal character references
                    c = int(s[1:], 16) if s[0].lower() == 'x' else int(s)
                    return chr(c)
            except (ValueError, OverflowError):
                return f'&#{s};'
            else:
                if HTMLParser.entitydefs is None:
                    # Load standard HTML entities for Python 3
                    # (Replaces old 'import htmlentitydefs')

                    # Cannot use name2codepoint directly, because HTMLParser supports apos,
                    # which is not part of HTML 4
                    import html.entities as htmlentitydefs
                    HTMLParser.entitydefs = {'apos': "'"}
                    # Python 3: use items() instead of iteritems()
                    for k, v in htmlentitydefs.name2codepoint.items():
                        HTMLParser.entitydefs[k] = chr(v)
                try:
                    return HTMLParser.entitydefs[s]
                except KeyError:
                    return f'&{s};'

        return re.sub(r"&(#?[xX]?(?:[0-9a-fA-F]+|\w{1,8}));", replaceEntities, s)
