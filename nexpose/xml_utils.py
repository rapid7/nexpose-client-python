from lxml import etree
from StringIO import StringIO

def create_element(tag, optional_attributes=None):
	request = etree.Element(tag)
	if optional_attributes:
		for tag, value in optional_attributes.iteritems():
			request.attrib[tag] = "{0}".format(value)
	return request

def get_attribute(xml_data, attribute_name, default_value=None):
	if xml_data is None:
		return default_value
	return xml_data.attrib.get(attribute_name, default_value)

def get_children_of(xml_data, element_name):
	element = get_element(xml_data, element_name, default_value=None)
	return element.getchildren() if element is not None else ()

def get_element(xml_data, element_name, default_value=None):
	if xml_data is None:
		return default_value
	return xml_data.find(element_name)

def get_content_of(xml_data, element_name, default_value=None):
	if xml_data is None:
		return default_value
	element = xml_data.find(element_name)
	if element is None:
		return default_value
	if element.text is None:
		return default_value
	return element.text

def as_string(xml_data):
	return etree.tostring(xml_data)

def from_large_string(s):
	parser = etree.XMLParser(huge_tree=True)
	return etree.parse(StringIO(s), parser).getroot()

# TODO: when downloading reports we shouldn't use XML, the from_large_string should only be needed in rare cases
#       this is actually a problem of GenerateScanReport as it shouldn't be using Execute_APIv1d1
def as_xml(s):
	# Note:
	# There is a bug in the StartUpdateResponse, in case of a failure (no internet connection),
	# two StartUpdateResponse XML objects are returned, one indicating failure, one indicating success.
	# We handle this bug here (wrong place?!), by embedding the returned XML in a single object
	# and returning the first element after conversion.
	if s.startswith('<?'):
		return from_large_string(s)
	s = '<_>' + s + '</_>'
	return from_large_string(s).getchildren()[0]
