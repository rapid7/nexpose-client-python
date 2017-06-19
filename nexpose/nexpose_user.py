from xml_utils import get_attribute, create_element

class UserRoles:
	global_admin = 'global-admin'
	security_manager = 'security-manager'
	site_admin = 'siteadmin'
	system_admin = 'system-admin'
	user = 'user'
	custom = 'custom'


class UserSummaryStatistics:
	def __init__(self):
		self.site_count = 0
		self.assetgroup_count = 0


class UserBase:
	def InitalizeFromXML(self, xml_data, user_fieldname):
		self.id = int(get_attribute(xml_data, 'id', self.id))
		self.username = get_attribute(xml_data, user_fieldname, self.username)
		self.fullname = get_attribute(xml_data, 'fullname', self.fullname)
		self.email = get_attribute(xml_data, 'email', self.email)

	def __init__(self):
		self.id = 0
		self.username = ''
		self.fullname = ''
		self.email = ''

		
class UserSummary(UserBase):
	@staticmethod
	def CreateFromXML(xml_data):
		summary = UserSummary()
		summary.InitalizeFromXML(xml_data, 'userName')
		summary.authenticator_source = get_attribute(xml_data, 'authSource', summary.authenticator_source)
		summary.authenticator_module = get_attribute(xml_data, 'authModule', summary.authenticator_module)
		summary.is_administrator = get_attribute(xml_data, 'administrator') == '1'
		summary.is_disabled = get_attribute(xml_data, 'disabled') == '1'
		summary.is_locked = get_attribute(xml_data, 'locked') == '1'
		summary.statistics.site_count = get_attribute(xml_data, 'siteCount', summary.statistics.site_count)
		summary.statistics.assetgroup_count = get_attribute(xml_data, 'groupCount', summary.statistics.assetgroup_count)
		return summary

	def __init__(self):
		UserBase.__init__(self)
		self.authenticator_source = ''
		self.authenticator_module = ''
		self.is_administrator = False
		self.is_disabled = False
		self.is_locked = False
		self.statistics = UserSummaryStatistics()


class UserConfiguration(UserBase):
	@staticmethod
	def CreateFromXML(xml_data):
		config = UserConfiguration()
		config.InitalizeFromXML(xml_data, 'name')
		config.authenticator_id = int(get_attribute(xml_data, 'authsrcid', config.authenticator_id))
		config.role_name = get_attribute(xml_data, 'role-name', config.role_name)
		config.password = get_attribute(xml_data, 'password', config.password)
		config.is_enabled = get_attribute(xml_data, 'enabled') == '1'
		config.has_access_to_all_sites = None       # Due to a Nexpose bug this information is not returned
		config.has_access_to_all_assetgroups = None # Due to a Nexpose bug this information is not returned
		config.accessible_sites = None              # Due to a Nexpose bug this information is not returned
		config.accessible_assetgroups = None        # Due to a Nexpose bug this information is not returned
		return config
	
	@staticmethod
	def Create():
		config = UserConfiguration()
		config.id = -1
		config.role_name = UserRoles.user
		config.has_access_to_all_sites = True
		config.has_access_to_all_assetgroups = True
		return config
	
	@staticmethod
	def CreateNamed(username, fullname):
		config = UserConfiguration.Create()
		config.username = username
		config.fullname = fullname
		return config

	def __init__(self):
		UserBase.__init__(self)
		self.authenticator_id = 0
		self.role_name = UserRoles.user
		self.password = ''
		self.is_enabled = True
		self.has_access_to_all_sites = False
		self.has_access_to_all_assetgroups = False
		self.accessible_sites = []
		self.accessible_assetgroups = []
	
	def AsXML(self, exclude_id):
		attributes = {}
		if not exclude_id:
			attributes['id'] = self.id
		attributes['name'] = self.username
		attributes['password'] = self.password
		attributes['enabled'] = '1' if self.is_enabled else '0'
		attributes['fullname'] = self.fullname
		attributes['email'] = self.email
		attributes['role-name'] = self.role_name
		attributes['authsrcid'] = self.authenticator_id if self.authenticator_id else 0
		attributes['allSites'] = True if self.has_access_to_all_sites else False
		attributes['allGroups'] = True if self.has_access_to_all_assetgroups else False
		xml_data = create_element('UserConfig', attributes)
		
		if not self.has_access_to_all_sites:
			xml_sites = create_element('Sites') # We are just nice, in practice Nexpose doesn't care for this subelement
			for site_id in self.accessible_sites:
				xml_site = create_element('site', {'id': site_id})
				xml_sites.append(xml_site)
			xml_data.append(xml_sites)
			
		if not self.has_access_to_all_assetgroups:
			xml_assetgroups = create_element('Groups') # We are just nice, in practice Nexpose doesn't care for this subelement
			for site_id in self.accessible_assetgroups:
				xml_assetgroup = create_element('group', {'id': site_id})
				xml_assetgroups.append(xml_assetgroup)
			xml_data.append(xml_assetgroups)
			
		return xml_data
