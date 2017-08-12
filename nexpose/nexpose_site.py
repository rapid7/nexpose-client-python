# Future Imports for py2/3 backwards compat.
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from builtins import object
from xml_utils import get_attribute, get_content_of, get_children_of, create_element, as_string, as_xml, get_element
from future import standard_library
standard_library.install_aliases()


class Range(object):
    def __init__(self, start, end):
        self.start = start
        self.end = end if end else start

    def AsXML(self):
        attributes = {}
        attributes['from'] = self.start
        if self.end != self.start:
            attributes['to'] = self.end
        xml_data = create_element('range', attributes)
        return xml_data


class Host(object):
    def __init__(self, name):
        self.name = name

    def AsXML(self):
        xml_data = create_element('host')
        xml_data.text = self.name
        return xml_data


def _host_to_object(host):
    if host.tag == "host":
        return Host(host.text)
    if host.tag == "range":
        return Range(get_attribute(host, 'from'), get_attribute(host, 'to'))
    raise ValueError('Unknown host type: {0}'.format(host.tag))


class ScanConfiguration(object):
    def __init__(self):
        self.id = 0
        self.name = ''
        self.version = 0
        self.template_id = "full-audit-without-web-spider"
        self.engine_id = 0


class SiteBase(object):
    def InitalizeFromXML(self, xml_data):
        self.id = int(get_attribute(xml_data, 'id', self.id))
        self.name = get_attribute(xml_data, 'name', self.name)
        self.short_description = get_attribute(xml_data, 'description', self.short_description)
        self.risk_factor = float(get_attribute(xml_data, 'riskfactor', self.risk_factor))

    def __init__(self):
        self.id = 0
        self.name = ''
        self.short_description = ''  # newlines are removed by Nexpose, use SiteConfiguration.description instead
        self.risk_factor = 1.0


class SiteSummary(SiteBase):
    @staticmethod
    def CreateFromXML(xml_data):
        summary = SiteSummary()
        summary.InitalizeFromXML(xml_data)
        summary.risk_score = float(get_attribute(xml_data, 'riskscore', summary.risk_score))
        return summary

    def __init__(self):
        SiteBase.__init__(self)
        self.risk_score = 0.0


class SiteConfiguration(SiteBase):
    @staticmethod
    def CreateFromXML(xml_data):
        config = SiteConfiguration()
        config.InitalizeFromXML(xml_data)
        config.description = get_content_of(xml_data, 'Description', config.description)
        config.is_dynamic = get_attribute(xml_data, 'isDynamic', config.is_dynamic) in ['1', 'true', True]
        config.hosts = [_host_to_object(host) for host in get_children_of(xml_data, 'Hosts')]
        config.alerting = [alert for alert in get_children_of(xml_data, 'Alerting')]
        config.credentials = [credential for credential in get_children_of(xml_data, 'Credentials')]
        config.users = [user for user in get_children_of(xml_data, 'Users')]

        # Use scanconfig elements for the SiteConfiguration
        scanconfig = get_element(xml_data, "ScanConfig")
        config.configid = scanconfig.get("configID")
        config.configtemplateid = scanconfig.get("templateID")
        config.configname = scanconfig.get("name")
        config.configversion = scanconfig.get("configVersion")
        config.configengineid = scanconfig.get("engineID")
        config.schedules = [schedule for schedule in get_children_of(scanconfig, 'Schedules')]

        return config

    @staticmethod
    def Create():
        config = SiteConfiguration()
        config.id = -1
        return config

    @staticmethod
    def CreateNamed(name):
        config = SiteConfiguration.Create()
        config.name = name
        return config

    def __init__(self):
        SiteBase.__init__(self)
        self.description = ''
        self.is_dynamic = False
        self.hosts = []
        self.credentials = []
        self.alerting = []
        self.scan_configuration = []  # TODO
        self.configid = self.id
        self.configtemplateid = "full-audit-without-web-spider"
        self.configname = "Full audit without Web Spider"
        self.configversion = 3
        self.configengineid = 3
        self.users = []
        self.schedules = []

    def AsXML(self, exclude_id):
        attributes = {}
        if not exclude_id:
            attributes['id'] = self.id
        attributes['name'] = self.name
        attributes['description'] = self.short_description
        attributes['isDynamic'] = '1' if self.is_dynamic else '0'
        attributes['riskfactor'] = self.risk_factor

        xml_data = create_element('Site', attributes)

        xml_description = create_element('Description')
        xml_description.text = self.description
        xml_data.append(xml_description)

        xml_hosts = create_element('Hosts')
        for host in self.hosts:
            xml_hosts.append(host.AsXML())
        xml_data.append(xml_hosts)

        xml_credentials = create_element('Credentials')
        for credential in self.credentials:
            xml_credentials.append(credential)
        xml_data.append(xml_credentials)

        xml_alerting = create_element('Alerting')
        for alert in self.alerting:
            xml_alerting.append(alert)
        xml_data.append(xml_alerting)

        xml_users = create_element('Users')
        for user in self.users:
            xml_users.append(user)
        xml_data.append(xml_users)

        # Include ScanConfig attributes
        attributes = {}
        attributes['configID'] = self.configid
        attributes['name'] = self.configname
        attributes['templateID'] = self.configtemplateid
        attributes['engineID'] = self.configengineid
        attributes['configVersion'] = self.configversion

        xml_scanconfig = create_element('ScanConfig', attributes)
        xml_scheduling = create_element('Scheduling')
        for schedule in self.schedules:
            xml_scheduling.append(schedule)
        xml_scanconfig.append(xml_scheduling)
        xml_data.append(xml_scanconfig)

        # TODO: implement the xxxPrivileges
        # print(as_string(as_xml(as_string(xml_data))))
        return xml_data
