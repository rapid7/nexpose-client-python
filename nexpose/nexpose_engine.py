from xml_utils import get_attribute, create_element

class EnginePriority:
	VeryLow = 'very-low'
	Low = 'low'
	Normal = 'normal'
	High = 'high'
	VeryHigh = 'very high'


class EngineStatus:
	Active = 'active'
	PendingAuthorization = 'pending-authorization'
	Incompatible = 'incompatible'
	NotResponding = 'not-responding'
	Unknown = 'unknown'


class EngineBase:
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


class EngineSummary(EngineBase):
	@staticmethod
	def CreateFromXML(xml_data):
		summary = EngineSummary()
		summary.InitalizeFromXML(xml_data)
		summary.status = get_attribute(xml_data, 'status', summary.status)
		return summary

	def __init__(self):
		EngineBase.__init__(self)
		self.status = EngineStatus.Unknown


class EngineConfiguration(EngineBase):
	@staticmethod
	def CreateFromXML(xml_data):
		config = EngineConfiguration()
		config.InitalizeFromXML(xml_data)
		config.priority = get_attribute(xml_data, 'priority', config.priority)
		config.assigned_sites = [(int(get_attribute(xml_site, 'id', 0)), get_attribute(xml_site, 'name', '')) for xml_site in xml_data.getchildren() if xml_site.tag == 'Site']
		return config
	
	@staticmethod
	def Create():
		config = EngineConfiguration()
		config.id = -1
		return config

	@staticmethod
	def CreateNamed(name):
		config = EngineConfiguration.Create()
		config.name = name
		return config

	def __init__(self):
		EngineBase.__init__(self)
		self.priority = EnginePriority.Normal
		self.assigned_sites = []
	
	def AsXML(self, exclude_id):
		attributes = {}
		if not exclude_id: attributes['id'] = self.id
		attributes['name'] = self.name
		attributes['address'] = self.host
		attributes['port'] = self.port
		attributes['scope'] = self.scope
		attributes['priority'] = self.priority
		xml_data = create_element('EngineConfig', attributes)
		return xml_data
