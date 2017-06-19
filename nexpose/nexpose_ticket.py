from xml_utils import get_attribute, get_element, get_content_of, create_element


class TicketState:
	OPEN = 'O'
	ASSIGNED = 'A'
	MODIFIED = 'M'
	FIXED = 'X'
	PARTIAL = 'P'
	REJECTED_FIX = 'R'
	PRIORITIZED = 'Z'
	NOT_REPRODUCIBLE = 'F'
	NOT_ISSUE = 'I'
	CLOSED = 'C'
	UNKNOWN = 'U'


class TicketPriority:
	LOW = 'low'
	MODERATE = 'moderate'
	NORMAL = 'normal'
	HIGH = 'high'
	CRITICAL = 'critical'


class TicketEvent:
	@staticmethod
	def CreateFromXML(xml_data):
		xml_event = get_element(xml_data, 'Event')
		event = TicketEvent()
		event.title = xml_event.text
		event.author = get_attribute(xml_data, 'author', event.author)
		event.created_on = get_attribute(xml_data, 'created-on', event.created_on) # TODO: datetime object!
		event.state = get_attribute(xml_event, 'state', TicketState.UNKNOWN)
		event.comment = get_content_of(xml_data, 'Comment', event.comment)
		return event
	
	def __init__(self):
		self.title = ''
		self.author = ''
		self.created_on = '' # TODO: datetime object!
		self.state = TicketState.UNKNOWN
		self.comment = ''


class _TicketBase:
	def InitalizeFromXML(self, xml_data):
		self.name = get_attribute(xml_data, 'name', self.name)
		self.asset_id = int(get_attribute(xml_data, 'device-id', self.asset_id))
		self.assigned_to = get_attribute(xml_data, 'assigned-to', self.assigned_to)
		self.priority = get_attribute(xml_data, 'priority', self.priority)

	def __init__(self):
		self.name = ''
		self.asset_id = 0
		self.assigned_to = ''
		self.priority = TicketPriority.NORMAL


class _TicketDetailsBase:
	def _InitializeFromXML(self, xml_data):
		self.vulnerabilities_ids = [get_attribute(xml_vulnerability, 'id') for xml_vulnerability in xml_data.findall('Vulnerabilities/Vulnerability')]
	
	def _VulnerabilitiesAsXML(self):
		xml_data = create_element('Vulnerabilities')
		for vulnerability_id in self.vulnerabilities_ids:
			xml_vulnerability = create_element('Vulnerability', {'id': vulnerability_id})
			xml_data.append(xml_vulnerability)
		return xml_data
	
	def __init__(self):
		self.vulnerabilities_ids = []


class NewTicket(_TicketBase, _TicketDetailsBase):
	@staticmethod
	def Create():
		return NewTicket()
	
	@staticmethod
	def CreatedNamed(name):
		ticket = NewTicket.Create()
		ticket.name = name
		return ticket

	def __init__(self):
		_TicketBase.__init__(self)
		_TicketDetailsBase.__init__(self)
		
	def AsXML(self):
		attributes = {}
		attributes['name'] = self.name
		attributes['device-id'] = self.asset_id
		attributes['assigned-to'] = self.assigned_to
		attributes['priority'] = self.priority
		xml_data = create_element("TicketCreate", attributes)
		xml_data.append(self._VulnerabilitiesAsXML())
		return xml_data


class TicketSummary(_TicketBase):
	def InitalizeFromXML(self, xml_data):
		_TicketBase.InitalizeFromXML(self, xml_data)
		self.id = int(get_attribute(xml_data, 'id', self.id))
		self.author = get_attribute(xml_data, 'author', self.author)
		self.created_on = get_attribute(xml_data, 'created-on', self.created_on) # TODO: datetime object!
		self.state = get_attribute(xml_data, 'state', self.state)
	
	@staticmethod
	def CreateFromXML(xml_data):
		summary = TicketSummary()
		summary.InitalizeFromXML(xml_data)
		return summary

	def __init__(self):
		_TicketBase.__init__(self)
		self.id = 0
		self.author = ''
		self.created_on = '' # TODO: datetime object!
		self.state = TicketState.OPEN


class TicketDetails(TicketSummary, _TicketDetailsBase):
	@staticmethod
	def CreateFromXML(xml_data):
		config = TicketDetails()
		config.InitalizeFromXML(xml_data)
		_TicketDetailsBase._InitializeFromXML(config, xml_data)
		config.events = [TicketEvent.CreateFromXML(xml_event) for xml_event in xml_data.findall('TicketHistory/Entry')]
		return config

	def __init__(self):
		TicketSummary.__init__(self)
		_TicketDetailsBase.__init__(self)
		self.events = []
