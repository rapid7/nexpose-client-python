from xml_utils import get_attribute

class ReportStatus:
	STARTED   = 'Started'
	GENERATED = 'Generated'
	FAILED    = 'Failed'
	ABORTED   = 'Aborted'
	UNKNOWN   = 'Unknown'

class ReportTemplate:
	pass

# TODO: test the difference between global and silo scoped reports
#       and refactor accordingly
class _ReportBase:
	def _InitalizeFromXML(self, xml_data, name_of_id_field):
		self.id = int(get_attribute(xml_data, name_of_id_field, self.id))
		self.status = get_attribute(xml_data, 'status', self.status)
		self.generated_on = get_attribute(xml_data, 'generated-on', self.generated_on) # TODO: parse this as a date
		self.URI = get_attribute(xml_data, 'report-URI', self.URI)
		self.scope = get_attribute(xml_data, 'scope', self.scope)

	def __init__(self):
		self.id = 0
		self.status = ReportStatus.UNKNOWN
		self.generated_on = '' # TODO: default date?
		self.URI = ''
		self.scope = 'silo'

# TODO: test the difference between global and silo scoped reports
#       and refactor accordingly
class _ReportConfigurationBase:
	def _InitalizeFromXML(self, xml_data):
		self.template_id = get_attribute(xml_data, 'template-id', self.template_id)
		self.name = get_attribute(xml_data, 'name', self.name)

	def __init__(self):
		self.template_id = ''
		self.name = ''

class ReportSummary(_ReportBase):
	@staticmethod
	def CreateFromXML(xml_data):
		summary = ReportSummary()
		_ReportBase._InitalizeFromXML(summary, xml_data, 'id')
		summary.configuration_id = int(get_attribute(xml_data, 'cfg-id', summary.configuration_id))
		return summary

	def __init__(self):
		_ReportBase.__init__(self)
		self.configuration_id = 0

class ReportConfigurationSummary(_ReportBase, _ReportConfigurationBase):
	@staticmethod
	def CreateFromXML(xml_data):
		config = ReportConfigurationSummary()
		_ReportBase._InitalizeFromXML(config, xml_data, 'cfg-id')
		_ReportConfigurationBase._InitalizeFromXML(config, xml_data)
		return config

	def __init__(self):
		_ReportBase.__init__(self)
		_ReportConfigurationBase.__init__(self)

class ReportConfiguration(_ReportConfigurationBase):
	@staticmethod
	def CreateFromXML(xml_data):
		config = ReportConfiguration()
		_ReportConfigurationBase._InitalizeFromXML(config, xml_data)
		return config

	def __init__(self):
		_ReportConfigurationBase.__init__(self)
		self.format = ''
		self.owner = ''
		self.timezone = ''
		self.description = ''
		self.filters = []
		self.baseline = '' # TODO: default date?
		self.users = []
		self.generate = None
		self.delivery = ''
		self.dbexport = ''
		self.credentials = ''
		self.parameter_name = '' # TODO: ??