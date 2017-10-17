# Future Imports for py2/3 backwards compat.
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from builtins import object
from .xml_utils import get_attribute
from future import standard_library
standard_library.install_aliases()


class AssetHostTypes(object):
    Empty = ''
    Guest = 'GUEST'
    Hypervisor = 'HYPERVISOR'
    Physical = 'PHYSICAL'
    Mobile = 'MOBILE'


class AssetBase(object):
    def InitializeFromXML(self, xml_data):
        self.id = int(get_attribute(xml_data, 'id', self.id))
        self.risk_score = float(get_attribute(xml_data, 'riskscore', self.risk_score))

    def InitializeFromJSON(self, json_dict):
        self.id = json_dict['id']
        self.risk_score = json_dict['assessment']['json']['risk_score']

    def __init__(self):
        self.id = 0
        self.risk_score = 0.0


class AssetSummary(AssetBase):
    @staticmethod
    def Create():
        return AssetSummary()

    @staticmethod
    def CreateFromXML(xml_data, site_id=None):
        asset = AssetSummary.Create()
        asset.InitializeFromXML(xml_data)
        asset.site_id = int(site_id if site_id is not None else get_attribute(xml_data, 'site-id', asset.site_id))
        asset.host = get_attribute(xml_data, 'address', asset.host)
        asset.risk_factor = float('0' + get_attribute(xml_data, 'riskfactor', asset.risk_factor))  # riskfactor can be an emtpy string
        return asset

    def __init__(self):
        AssetBase.__init__(self)
        self.site_id = 0
        self.host = ''
        self.risk_factor = 1.0


class AssetDetails(AssetBase):
    @staticmethod
    def CreateFromJSON(json_dict):
        host_names = json_dict["host_names"]
        host_type = json_dict["host_type"]
        details = AssetDetails()
        details.InitializeFromJSON(json_dict)
        details.ip_address = json_dict["ip"]
        details.mac_address = json_dict["mac"]
        details.addresses = json_dict["addresses"]
        if host_names is not None:
            details.host_names = host_names
        if host_type is not None:
            details.host_type = host_type
        details.os_name = json_dict["os_name"]
        details.os_cpe = json_dict["os_cpe"]
        details.last_scan_id = json_dict['assessment']['json']['last_scan_id']
        details.last_scan_date = json_dict['assessment']['json']['last_scan_date']
        details.files = json_dict['files']
        details.vulnerability_instances = json_dict['vulnerability_instances']
        details.unique_identifiers = json_dict['unique_identifiers']
        details.group_accounts = json_dict['group_accounts']
        details.user_accounts = json_dict['user_accounts']
        details.vulnerabilities = json_dict['vulnerabilities']
        details.software = json_dict['software']
        details.services = json_dict['services']

        return details

    def __init__(self):
        AssetBase.__init__(self)
        self.ip_address = ''
        self.mac_address = ''
        self.addresses = []
        self.host_names = []
        self.host_type = AssetHostTypes.Empty
        self.os_name = ''
        self.os_cpe = ''
        self.last_scan_id = 0
        self.last_scan_date = ''
        self.files = []
        self.vulnerability_instances = []
        self.unique_identifiers = []
        self.group_accounts = []
        self.user_accounts = []
        self.vulnerabilities = []
        self.software = []
        self.services = []
