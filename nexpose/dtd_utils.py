from lxml import etree
from StringIO import StringIO

# see also: http://www.validome.org/grammar/validate/
def parse_dtd(dtd):
	return etree.DTD(StringIO(dtd[dtd.find(' [')+2:-2].replace('\n','')))