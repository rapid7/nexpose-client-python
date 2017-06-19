from xml_utils import get_attribute, get_element, as_string
from nexpose_asset import AssetSummary

class _AssetGroupBase:
	def InitializeFromXML(self, xml_data):
		self.id = int(get_attribute(xml_data, 'id', self.id))
		self.name = get_attribute(xml_data, 'name', self.name)
		self.short_description = get_attribute(xml_data, 'description', self.short_description)

	def __init__(self):
		self.id = 0
		self.name = 0
		self.short_description = '' # API 1.1 removes newlines that were added through the UI

class AssetGroupSummary(_AssetGroupBase):
	@staticmethod
	def CreateFromXML(xml_data):
		asset_group = AssetGroupSummary()
		asset_group.InitializeFromXML(xml_data)
		asset_group.risk_score = float(get_attribute(xml_data, 'riskscore', asset_group.risk_score))
		return asset_group

	def __init__(self):
		_AssetGroupBase.__init__(self)
		self.risk_score  = 0.0

class AssetGroupConfiguration(_AssetGroupBase):
	@staticmethod
	def CreateFromXML(xml_data):
		xml_devices = get_element(xml_data, 'Devices', None)
		print as_string(xml_data)
		config = AssetGroupConfiguration()
		config.InitializeFromXML(xml_data)
		config.description = config.short_description
		if xml_devices is not None:
			config.asset_summaries = [AssetSummary.CreateFromXML(xml_device) for xml_device in xml_devices.getchildren() if xml_device.tag == 'device']
		return config

	@staticmethod
	def Create():
		config = AssetGroupConfiguration()
		config.id = -1
		return config
	
	def __init__(self):
		_AssetGroupBase.__init__(self)
		self.description = None
		self.asset_summaries = []