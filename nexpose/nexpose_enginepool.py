from xml_utils import get_attribute, create_element


class EnginePoolBase:
	def InitalizeFromXML(self, xml_data):
		self.id = int(get_attribute(xml_data, 'id', self.id))
		self.name = get_attribute(xml_data, 'name', self.name)
		self.host = get_attribute(xml_data, 'address', self.host)
		self.port = int(get_attribute(xml_data, 'port', self.port))
		self.scope = get_attribute(xml_data, 'scope', self.scope)

	def __init__(self):
		self.id = 0
		self.name = ''
		self.host = ''
		self.port = 40814
		self.scope = 'silo'


class EnginePoolSummary(EnginePoolBase):
	@staticmethod
	def CreateFromXML(xml_data):
		summary = EnginePoolSummary()
		summary.InitalizeFromXML(xml_data)
		summary.status = get_attribute(xml_data, 'status', summary.status)
		return summary

	def __init__(self):
		EnginePoolBase.__init__(self)
		self.status = EnginePoolStatus.Unknown


class EnginePoolConfiguration(EnginePoolBase):
	@staticmethod
	def CreateFromXML(xml_data):
		config = EnginePoolConfiguration()
		config.InitalizeFromXML(xml_data)
		config.priority = get_attribute(xml_data, 'priority', config.priority)
		config.assigned_sites = [(int(get_attribute(xml_site, 'id', 0)), get_attribute(xml_data, 'name', '')) for xml_site in xml_data.getchildren() if xml_site.tag == 'Site']
		return config
	
	@staticmethod
	def Create():
		config = EnginePoolConfiguration()
		config.id = -1
		return config

	@staticmethod
	def CreateNamed(name):
		config = EnginePoolConfiguration.Create()
		config.name = name
		return config

	def __init__(self):
		EnginePoolBase.__init__(self)
		self.priority = EnginePoolPriority.Normal
		self.assigned_sites = []
	
	def AsXML(self, exclude_id):
		attributes = {}
		if not exclude_id: attributes['id'] = self.id
		attributes['name'] = self.name
		attributes['address'] = self.host
		attributes['port'] = self.port
		attributes['scope'] = self.scope
		attributes['priority'] = self.priority
		xml_data = create_element('EnginePoolConfig', attributes)
		return xml_data
