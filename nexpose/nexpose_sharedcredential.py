from xml_utils import get_attribute, get_content_of, get_element, get_children_of, create_element
from nexpose_credential import Credential

"""
      sites = xml.add_element('Sites')
      sites.add_attribute('all', @all_sites ? 1 : 0)
      @sites.each do |s|
        site = sites.add_element('Site')
        site.add_attribute('id', s)
        site.add_attribute('enabled', 0) if @disabled.member? s
      end
      if @sites.empty?
        @disabled.each do |s|
          site = sites.add_element('Site')
          site.add_attribute('id', s)
          site.add_attribute('enabled', 0)
        end
      end

      xml
    end
"""

class SharedCredentialBase:
    def __init__(self):
        self.id = 0
        self.name = ''
        self.all_sites = True
        
    def _get_service(self):
        return ''
    
    @property
    def service(self):
        return self._get_service()

class SharedCredentialSummary(SharedCredentialBase):
    @staticmethod
    def CreateFromJSON(json):
        credential = SharedCredentialSummary()
        
        # SharedCredentialBase:
        credential.id = int(json['credentialID']['ID'])
        credential.name = json['name']
        credential.all_sites = json['scope'] == 'ALL_SITES_ENABLED_DEFAULT'
        
        #SharedCredentialSummary-specific:
        credential._service = json['service']
        credential.username = json['username']
        credential.domain = json['domain']
        credential.privilege_username = json['privilegeElevationUsername']
        credential.site_count = json['assignedSites']
        credential.last_modified = json['lastModified']['time'] # TODO
        
        return credential
    
    def __init__(self):
        SharedCredentialBase.__init__(self)
        self.username = ''
        self.domain = ''
        self.privilege_username = ''
        self.site_count = 0
        self.last_modified = ''
    
    def _get_service(self):
        return self._service

class SharedCredentialConfiguration(SharedCredentialBase):
    @staticmethod
    def CreateFromXML(xml):
        sites = [site for site in get_children_of(xml, 'Sites') if site.tag == 'Site']

        service = get_attribute(get_element(xml, "Services/Service"), 'type')
        credential = SharedCredentialConfiguration()
        credential.id = int(get_attribute(xml, "id"))
        credential.name = get_content_of(xml, "Name")
        credential.description = get_content_of(xml, "Description")
        credential.credential = Credential.CreateFromXML(get_element(xml, "Account"), service)
        credential.restriction_host = get_content_of(xml, "Restrictions/Restriction/[@type='host']", credential.restriction_host)
        credential.restriction_port = int(get_content_of(xml, "Restrictions/Restriction/[@type='port']", credential.restriction_port))
        credential.all_sites = get_attribute(get_element(xml, "Sites"), 'all') == '1'
        credential.enabled_sites  = [get_attribute(site, 'id') for site in sites if get_attribute(site, 'enabled') == '1']
        credential.disabled_sites = [get_attribute(site, 'id') for site in sites if get_attribute(site, 'enabled') != '1']
        return credential
    
    @staticmethod
    def Create():
        credential = SharedCredentialConfiguration()
        credential.id = -1
        return credential

    def _get_service(self):
        if self.credential:
            return self.credential.SERVICE_TYPE
        return None
    
    def __init__(self):
        SharedCredentialBase.__init__(self)
        self.description = ''
        self.credential = None
        self.restriction_host = ''
        self.restriction_port = 0
        self.enabled_sites  = []
        self.disabled_sites = []

    def AsXML(self):
        xml = create_element('Credential', {'shared': 1, 'enabled': 0, 'id': self.id})
        if self.credential:
            xml.append(self.credential.AsXML())
        xml_name = create_element('Name')
        xml_name.text = self.name
        xml.append(xml_name)
        xml_description = create_element('Description')
        xml_description.text = self.description
        xml.append(xml_description)
        xml_services = create_element('Services')
        xml_services.append(create_element('Service', {'type': self.service}))
        xml.append(xml_services)
        xml_restrictions = create_element('Restrictions')
        if self.restriction_host:
            xml_restriction = create_element('Restriction', {'type': 'host'})
            xml_restriction.text = self.restriction_host
            xml_restrictions.append(xml_restriction)
        if self.restriction_port:
            xml_restriction = create_element('Restriction', {'type': 'port'})
            xml_restriction.text = self.restriction_port
            xml_restrictions.append(xml_restriction)
        xml.append(xml_restrictions)
        xml.append(create_element('Sites', {'all': 1 if self.all_sites else 0})) # TODO: enabled/disabled sites
        return xml
