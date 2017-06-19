from json_utils import get_id as _get_id, HasID, JSON

DEFAULT_SOURCENAME = "DavinsiLabs-Nexpose-Python"
DEFAULT_TAGCOLOR = "#f6f6f6"

class TagColors:
	DEFAULT = DEFAULT_TAGCOLOR
	BLUE   = "#496a77"
	GREEN  = "#7d8a58"
	ORANGE = "#de7200"
	RED    = "#a0392e"
	PURPLE = "#844f7d"

class TagAttribute(JSON, HasID):
	@staticmethod
	def CreateFromJSON(json_dict):
		name  = json_dict["tag_attribute_name"]
		value = json_dict["tag_attribute_value"]

		attribute = TagAttribute(name, value)
		attribute.id = json_dict.get("tag_attribute_id", 0)
		return attribute

	@staticmethod
	def Create(name, value=None):
		attribute = TagAttribute(name, value)
		return attribute

	def __init__(self, name, value):
		self.id = 0
		self.name = name
		self.value = value

	def as_json(self):
		json_dict = {}
		if self.id: json_dict["tag_attribute_id"] = self.id
		json_dict["tag_attribute_name"] = self.name
		json_dict["tag_attribute_value"] = self.value
		return json_dict

class TagConfiguration(JSON):
	@staticmethod
	def CreateFromJSON(json_dict):
		config = TagConfiguration()
		config.assetgroup_ids = json_dict["asset_group_ids"]
		config.site_ids = json_dict["site_ids"]
		config.associated_asset_ids = json_dict["tag_associated_asset_ids"]
		config.search_criteria = json_dict["search_criteria"]
		return config

	@staticmethod
	def Create():
		return TagConfiguration()

	def __init__(self):
		self.assetgroup_ids = []
		self.site_ids = []
		self.associated_asset_ids = []
		self.search_criteria = None

	def as_json(self):
		json_dict = {}
		json_dict["asset_group_ids"] = self.assetgroup_ids
		json_dict["site_ids"] = self.site_ids
		json_dict["tag_associated_asset_ids"] = self.associated_asset_ids
		json_dict["search_criteria"] = self.search_criteria
		return json_dict

class Tag(JSON, HasID):
	@staticmethod
	def GetID(tag):
		return _get_id(tag, "tag_id")

	@staticmethod
	def CreateFromJSON(json_dict):
		name = json_dict["tag_name"]
		type = json_dict["tag_type"]
		config = json_dict.get("tag_config", None)

		tag = Tag(name, type)
		tag.id = json_dict["tag_id"]
		tag.config = TagConfiguration.CreateFromJSON(config) if config else None
		tag.asset_ids = json_dict["asset_ids"]
		tag.attributes = []
		if json_dict.get("attributes"):
			for attr in json_dict["attributes"]:
				tag.attributes.append(TagAttribute.CreateFromJSON(attr))
		return tag

	@staticmethod
	def Create(name, type, source_name=None):
		if source_name == None: source_name = DEFAULT_SOURCENAME

		tag = Tag(name, type)
		tag.config = TagConfiguration.Create()
		tag.asset_ids = []
		tag.attributes = [TagAttribute("SOURCE", source_name)]
		return tag

	@staticmethod
	def CreateCustom(name, color=None, source_name=None):
		if color == None: color = DEFAULT_TAGCOLOR

		tag = Tag.Create(name, "CUSTOM", source_name)
		tag.attributes.append(TagAttribute("COLOR", color))
		return tag

	def __init__(self, name, type):
		self.id = 0
		self.name = name
		self.type = type
		self.config = None
		self.asset_ids = None
		self.attributes = None

	def as_json(self):
		json_dict = {}
		if self.id: json_dict["tag_id"] = self.id
		json_dict["tag_name"] = self.name
		json_dict["tag_type"] = self.type
		json_dict["asset_ids"] = self.asset_ids
		json_dict["tag_config"] = self.config.as_json() if self.config else None
		if self.attributes: json_dict["attributes"] = [attr.as_json() for attr in self.attributes]
		return json_dict