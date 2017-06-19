from xml_utils import get_attribute, create_element
from urlparse import urlparse

class DiscoveryConnectionProtocol:
	HTTP = 'http'
	HTTPS = 'https'


class _DiscoveryConnectionBase:
	def InitalizeFromXML(self, xml_data):
		self.id = int(get_attribute(xml_data, 'id', self.id))
		self.name = get_attribute(xml_data, 'name', self.name)
		self.host = get_attribute(xml_data, 'address', self.host)
		self.port = int(get_attribute(xml_data, 'port', self.port))
		self.protocol = get_attribute(xml_data, 'protocol', self.protocol).lower()
		self.username = get_attribute(xml_data, 'user-name', self.username)
		self.password = get_attribute(xml_data, 'password', self.password)
		# TODO: according to the manual a : is added, I doubt that, untested yet
		if self.protocol.endswith(':'):
			self.protocol = self.protocol[:-1]

	def __init__(self):
		self.id = 0
		self.name = ''
		self.host = ''
		self.port = 0
		self.protocol = ''
		self.username = ''
		self.password = ''


class DiscoveryConnectionSummary(_DiscoveryConnectionBase):
	@staticmethod
	def CreateFromXML(xml_data):
		summary = DiscoveryConnectionSummary()
		summary.InitalizeFromXML(xml_data)
		return summary

	def __init__(self):
		_DiscoveryConnectionBase.__init__(self)


class DiscoveryConnectionConfiguration(DiscoveryConnectionSummary):
	@staticmethod
	def CreateFromXML(xml_data):
		config = DiscoveryConnectionConfiguration()
		config.InitalizeFromXML(xml_data)
		return config
	
	@staticmethod
	def Create():
		config = DiscoveryConnectionConfiguration()
		config.id = -1
		return config

	@staticmethod
	def CreateNamed(name):
		config = DiscoveryConnectionConfiguration.Create()
		config.name = name
		return config

	@staticmethod
	def CreateNamedFromURL(name, url, username=None, password=None):
		parsed_url = urlparse(url)
		host, _, port = parsed_url.netloc.rpartition(':')
		if host == '':
			host = port
			port = '80' if parsed_url.scheme == 'http' else '443'
		config = DiscoveryConnectionConfiguration.CreateNamed(name)
		config.protocol = parsed_url.scheme.upper()
		config.host = host
		config.port = port
		config.username = '' if username is None else username
		config.password = '' if password is None else password
		return config

	def __init__(self):
		_DiscoveryConnectionBase.__init__(self)
	
	def AsXML(self, exclude_id):
		attributes = {}
		if not exclude_id: attributes['id'] = self.id
		attributes['name'] = self.name
		attributes['address'] = self.host
		attributes['port'] = self.port
		attributes['protocol'] = self.protocol
		attributes['user-name'] = self.username
		attributes['password'] = self.password
		xml_data = create_element('DiscoveryConnection', attributes)
		return xml_data
