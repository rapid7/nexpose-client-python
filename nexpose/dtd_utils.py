# Future Imports for py2/3 backwards compat.
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from lxml import etree
from io import StringIO
from future import standard_library
standard_library.install_aliases()


# see also: http://www.validome.org/grammar/validate/
def parse_dtd(dtd):
    return etree.DTD(StringIO(dtd[dtd.find(' [') + 2:-2].replace('\n', '')))
