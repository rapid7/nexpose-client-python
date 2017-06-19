from copy import deepcopy
from xml_utils import create_element, get_attribute, get_content_of, get_children_of

class RoleScope:
	Global = 'global'
	Silo = 'silo'

class _RoleBase:
	def InitalizeFromXML(self, xml_data, description_fieldname, description_getter):
		self.id = int(get_attribute(xml_data, 'id', self.id))
		self.name = get_attribute(xml_data, 'name', self.name)
		self.fullname = get_attribute(xml_data, 'full-name', self.fullname)
		self.description = description_getter(xml_data, description_fieldname, self.description)
		self.is_enabled = get_attribute(xml_data, 'enabled', self.is_enabled) in ['true', '1', True]
		self.scope = get_attribute(xml_data, 'scope', self.scope)

	def __init__(self):
		self.id = 0
		self.name = ''
		self.fullname = ''
		self.description = ''
		self.is_enabled = True
		self.scope = RoleScope.Silo


class RoleSummary(_RoleBase):
	@staticmethod
	def CreateFromXML(xml_data):
		summary = RoleSummary()
		summary.InitalizeFromXML(xml_data, 'description', get_attribute)
		return summary

	def __init__(self):
		_RoleBase.__init__(self)


class RoleDetails(RoleSummary):
	@staticmethod
	def CreateFromXML(xml_data):
		detail = RoleDetails()
		detail.InitalizeFromXML(xml_data, 'Description', get_content_of)
		detail.assetgroup_privileges = RoleDetails._ExtractPrivileges(xml_data, 'AssetGroupPrivileges')
		detail.global_privileges = RoleDetails._ExtractPrivileges(xml_data, 'GlobalPrivileges')
		detail.site_privileges = RoleDetails._ExtractPrivileges(xml_data, 'SitePrivileges')
		return detail

	@staticmethod
	def Create():
		details = RoleDetails()
		details.id = -1
		return details

	@staticmethod
	def CreateNamed(name, fullname=None):
		details = RoleDetails.Create()
		details.name = name
		details.fullname = name if fullname is None else fullname
		return details

	@staticmethod
	def CreateNamedBasedOn(source, name, fullname=None):
		if not isinstance(source, RoleDetails):
			raise ValueError('source must be a nexpose.RoleDetails instance')
		details = deepcopy(source)
		details.id = -1
		details.name = name
		details.fullname = name if fullname is None else fullname
		return details

	def __init__(self):
		RoleSummary.__init__(self)
		self.assetgroup_privileges = {}
		self.global_privileges = {}
		self.site_privileges = {}

	def AsXML(self, exclude_id):
		attributes = {}
		if not exclude_id: attributes['id'] = self.id
		attributes['name'] = self.name
		attributes['full-name'] = self.fullname
		attributes['enabled'] = '1' if self.is_enabled else '0'
		attributes['scope'] = self.scope
		xml_description = create_element('Description')
		xml_data = create_element('Role', attributes)
		xml_description.text = self.description
		xml_data.append(xml_description)
		xml_data.append(RoleDetails._CreatePrivelegesElement('AssetGroupPrivileges', self.assetgroup_privileges))
		xml_data.append(RoleDetails._CreatePrivelegesElement('GlobalPrivileges', self.global_privileges))
		xml_data.append(RoleDetails._CreatePrivelegesElement('SitePrivileges', self.site_privileges))
		return xml_data

	@staticmethod
	def _ExtractPrivileges(xml_data, tag):
		xml_children = get_children_of(xml_data, tag)
		return dict([(e.tag, e.attrib.get('enabled') in ['1','true']) for e in xml_children])

	@staticmethod
	def _CreatePrivelegesElement(tag, privileges):
		xml_data = create_element(tag)
		for key, value in privileges.iteritems():
			attribute = {'enabled': 1 if value else 0}
			xml_subdata = create_element(key, attribute)
			xml_data.append(xml_subdata)
		return xml_data
