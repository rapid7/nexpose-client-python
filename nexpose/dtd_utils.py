# Future Imports for py2 backwards compatibility
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from lxml import etree
from StringIO import StringIO


# see also: http://www.validome.org/grammar/validate/
def parse_dtd(dtd):
    return etree.DTD(StringIO(dtd[dtd.find(' [') + 2:-2].replace('\n', '')))
