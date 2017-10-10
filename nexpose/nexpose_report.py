# Future Imports for py2/3 backwards compat.
from __future__ import (absolute_import, division, print_function, unicode_literals)
from builtins import object
from .xml_utils import create_element, get_attribute, get_content_of, get_children_of, get_element
from future import standard_library
standard_library.install_aliases()


class ReportStatus(object):
    STARTED = 'Started'
    GENERATED = 'Generated'
    FAILED = 'Failed'
    ABORTED = 'Aborted'
    UNKNOWN = 'Unknown'


class ReportTemplate(object):
    pass


class _ReportBase(object):
    def _InitalizeFromXML(self, xml_data, name_of_id_field):
        self.id = int(get_attribute(xml_data, name_of_id_field, self.id))
        self.status = get_attribute(xml_data, 'status', self.status)
        self.generated_on = get_attribute(xml_data, 'generated-on', self.generated_on)  # TODO: parse this as a date
        self.URI = get_attribute(xml_data, 'report-URI', self.URI)
        self.scope = get_attribute(xml_data, 'scope', self.scope)

    def __init__(self):
        self.id = 0
        self.status = ReportStatus.UNKNOWN
        self.generated_on = ''  # TODO: default date?
        self.URI = ''
        self.scope = 'silo'


class _ReportConfigurationBase(object):
    def _InitalizeFromXML(self, xml_data):
        self.template_id = get_attribute(xml_data, 'template-id', self.template_id)
        self.name = get_attribute(xml_data, 'name', self.name)

    def __init__(self, template_id=None, name=None):
        self.template_id = template_id
        self.name = name


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


class AdhocReportConfiguration(_ReportConfigurationBase):
    def __init__(self, template_id, format, site_id=None, owner=None, timezone=None):
        _ReportConfigurationBase.__init__(self, template_id)
        self.format = format
        self.owner = owner
        self.timezone = timezone
        self.language = None
        self.filters = []
        self.baseline = None

        if site_id:
            self.add_filter('site', site_id)

    def add_filter(self, type, id):
        self.filters.append(Filter(type, id))

    def add_common_vuln_filters(self):
        for vuln_filter in ['potential', 'vulnerable-version', 'vulnerable-exploited']:
            self.add_filter('vuln-status', vuln_filter)

    def AsXML(self):
        attributes = {'name': self.name, 'template-id': self.template_id, 'format': self.format}
        if self.owner:
            attributes['owner'] = self.owner
        if self.timezone:
            attributes['timezone'] = self.timezone

        xml_data = create_element('AdhocReportConfig', attributes)

        xml_filters = create_element('Filters')
        for report_filter in self.filters:
            xml_filters.append(report_filter.AsXML())
        xml_data.append(xml_filters)

        if self.baseline:
            xml_baseline = create_element('Baseline', {'compareTo': self.baseline})
        else:
            xml_baseline = create_element('Baseline')
        xml_data.append(xml_baseline)

        return xml_data


class ReportConfiguration(AdhocReportConfiguration):
    @staticmethod
    def CreateFromXML(xml_data):
        template_id = get_attribute(xml_data, 'template-id')
        name = get_attribute(xml_data, 'name')
        format = get_attribute(xml_data, 'format')
        id = get_attribute(xml_data, 'id')
        owner = get_attribute(xml_data, 'owner')
        timezone = get_attribute(xml_data, 'timezone')

        cfg = ReportConfiguration(name, template_id, format, id, owner, timezone)
        filters = [Filter.CreateFromXML(filter) for filter in get_children_of(xml_data, 'Filters')]
        cfg.filters = filters if filters is not None else []

        baseline = get_element(xml_data, 'Baseline')
        cfg.baseline = get_attribute(baseline, 'compareTo')

        users = [get_attribute(user, 'id') for user in get_children_of(xml_data, 'Users')]
        cfg.users = users if users is not None else []

        frequency = get_element(xml_data, 'Generate')
        if frequency is not None:
            cfg.frequency = Frequency.CreateFromXML(frequency)

        delivery = get_element(xml_data, 'Delivery')
        if delivery is not None:
            cfg.delivery = Delivery.CreateFromXML(delivery)

        # TODO: draw the rest of the owl

        return cfg

    def __init__(self, name, template_id, format, id=-1, owner=None, timezone=None):
        """

        :param name: The name of the report configuration
        :type name: str
        :param template_id: The report template ID
        :type template_id: str
        :param format: The report output format (pdf|html|rtf|xml|text|csv|db|raw-xml|raw-xml-v2|ns-xml|qualys-xml|sql)
        :type format: str
        :param id: The report configuration ID, or -1 for a new configuration
        :type id: int
        :param owner: The user ID of the report owner
        :type owner: int or None
        :param timezone: The timezone of the report by name, e.g. America/Los_Angeles for Pacific (PDT/PST)
        :type timezone: str
        """
        AdhocReportConfiguration.__init__(self, template_id, format, None, owner, timezone)
        self.name = name
        self.id = id
        self.users = []
        self.generate = None
        self.frequency = None
        self.delivery = None
        self.dbexport = None  # TODO: needs DBExport class implemented
        self.credentials = None  # TODO: needs ExportCredential class implemented

    def AsXML(self, exclude_id=False):
        attributes = {'id': self.id, 'name': self.name, 'template-id': self.template_id, 'format': self.format}
        if self.owner:
            attributes['owner'] = self.owner
        if self.timezone:
            attributes['timezone'] = self.timezone

        xml_data = create_element('ReportConfig', attributes)

        xml_filters = create_element('Filters')
        for report_filter in self.filters:
            xml_filters.append(report_filter.AsXML())

        xml_data.append(xml_filters)

        if self.baseline:
            xml_baseline = create_element('Baseline', {'compareTo': self.baseline})
        else:
            xml_baseline = create_element('Baseline')

        xml_data.append(xml_baseline)

        xml_users = create_element('Users')
        for user in self.users:
            xml_users.append(create_element('user', {'id': user}))
        xml_data.append(xml_users)

        if self.frequency:
            xml_data.append(self.frequency.AsXML())

        if self.delivery:
            xml_data.append(self.delivery.AsXML())

        if self.dbexport:
            pass  # TODO needs DBExport class implemented

        return xml_data


class Filter:
    def __init__(self, type, id):
        """
        The type can be one of:

        - site
        - group
        - device
        - tag
        - scan
        - vuln-categories
        - vuln-severity
        - vuln-status
        - cyberscope-component
        - cyberscope-bureau
        - cyberscope-enclave

        For site, group, device, tag, and scan the ID is the numeric ID.
        For scan, the ID can also be "last" for the most recently run scan.
        For vuln-status, the ID can have one of the following values:

        1. vulnerable-exploited (The check was positive. An exploit verified the vulnerability.)
        2. vulnerable-version (The check was positive. The version of the scanned service or software is associated with
            known vulnerabilities.)
        3. potential (The check for a potential vulnerability was positive.)

        These values are supported for CSV and XML formats.

        :param type: The type of filter.
        :type type: str
        :param id: The numeric ID or string value for the given filter.
        :type id: int or str
        """
        self.type = type
        self.id = id

    def AsXML(self):
        return create_element('filter', {'type': self.type, 'id': self.id})

    @staticmethod
    def CreateFromXML(xml_data):
        type = get_attribute(xml_data, 'type')
        id = get_attribute(xml_data, 'id')
        return Filter(type, id)


class Schedule:
    def __init__(self, type, interval, start):
        """

        :param type: Valid schedule types: daily, hourly, monthly-date, monthly-day, weekly.
        :type type: str
        :param interval: The repeat interval based upon type.
        :type interval: int
        :param start: Starting time of the scheduled scan (in ISO 8601 format) (yyyyMMdd'T'HHmmssSSS).
        :type start: str
        """
        self.type = type
        self.interval = interval
        self.start = start  # TODO make sure this value is formatted correctly to: yyyyMMdd'T'HHmmssSSS

    def AsXML(self):
        attributes = {'type': self.type, 'interval': self.interval, 'start': self.start}
        return create_element('Schedule', attributes)

    @staticmethod
    def CreateFromXML(xml_data):
        type = get_attribute(xml_data, 'type')
        interval = get_attribute(xml_data, 'interval')
        start = get_attribute(xml_data, 'start')
        return Schedule(type, interval, start)


class Frequency:
    def __init__(self, after_scan=False, scheduled=False, schedule=None):
        """

        :param after_scan: Whether to generate after scan completes on any in-scope assets, sites, groups, or tags
        :type after_scan: bool
        :param scheduled: Whether to generate this report on a schedule (cannot be used with after_scan)
        :type scheduled: bool
        :param schedule: The schedule for recurring report generation
        :type schedule: Schedule
        """
        self.after_scan = after_scan
        self.scheduled = scheduled
        self.schedule = schedule

    def AsXML(self):
        attributes = {'after-scan': 1 if self.after_scan else 0, 'schedule': 1 if self.schedule else 0}
        xml_data = create_element('Generate', attributes)
        if self.schedule:
            xml_data.append(self.schedule.AsXML())
        return xml_data

    @staticmethod
    def CreateFromXML(xml_data):
        after_scan = get_attribute(xml_data, 'after-scan')
        schedule_enabled = get_attribute(xml_data, 'schedule')
        schedule_xml = get_element(xml_data, 'Schedule')
        schedule = Schedule.CreateFromXML(schedule_xml) if schedule_xml is not None else None
        truthy = [1, '1', 'true', 'True', 'TRUE']
        return Frequency(after_scan in truthy, schedule_enabled in truthy, schedule)


class Email:
    def __init__(self, to_all_authorized, send_to_owner_as=None, send_to_acl_as=None, send_as=None):
        """

        :param to_all_authorized: Send to all the authorized users of sites, groups, and assets.
        :type to_all_authorized: bool
        :param send_to_owner_as: Format to send to users on the report access list (file|zip|url).
        :type send_to_owner_as: str
        :param send_to_acl_as: Format to send to users on the report access list (file|zip|url).
        :type send_to_acl_as: str
        :param send_as: Send as file attachment or zipped file to individuals who are not members (file|zip).
        :type send_as: str
        """
        self.to_all_authorized = to_all_authorized
        self.send_to_owner_as = send_to_owner_as
        self.send_to_acl_as = send_to_acl_as
        self.send_as = send_as
        self.sender = None
        self.smtp_relay_server = None
        self.recipients = []

    def AsXML(self):
        attributes = {'toAllAuthorized': 1 if self.to_all_authorized else 0}
        if self.send_to_owner_as:
            attributes['sendToOwnerAs'] = self.send_to_owner_as
        if self.send_to_acl_as:
            attributes['sendToAclAs'] = self.send_to_acl_as
        if self.send_as:
            attributes['sendAs'] = self.send_as

        xml_data = create_element('Email', attributes)

        if self.sender:
            xml_sender = create_element('Sender')
            xml_sender.text = self.sender
            xml_data.append(xml_sender)

        if self.smtp_relay_server:
            xml_smtp = create_element('SmtpRelayServer')
            xml_smtp.text = self.smtp_relay_server
            xml_data.append(xml_smtp)

        if len(self.recipients) > 0:
            xml_recipients = create_element('Recipients')
            for recipient in self.recipients:
                xml_recipient = create_element('Recipient')
                xml_recipient.text = recipient
                xml_recipients.append(xml_recipient)
            xml_data.append(xml_recipients)

        return xml_data

    @staticmethod
    def CreateFromXML(xml_data):
        to_all_authorized = get_attribute(xml_data, 'toAllAuthorized')
        send_to_owner_as = get_attribute(xml_data, 'sendToOwnerAs')
        send_to_acl_as = get_attribute(xml_data, 'sendToAclAs')
        send_as = get_attribute(xml_data, 'sendAs')
        truthy = [1, '1', 'true', 'True', 'TRUE']
        email = Email(to_all_authorized in truthy, send_to_owner_as, send_to_acl_as, send_as)
        email.sender = get_content_of(xml_data, 'Sender')
        email.smtp_relay_server = get_content_of(xml_data, 'SmtpRelayServer')
        recipients = [recipient.text for recipient in get_children_of(xml_data, 'Recipients')]
        email.recipients = recipients if recipients else []
        return email


class Delivery:
    def __init__(self, store_on_server, location=None, email=None):
        """

        :param store_on_server: Whether to store the generated report on server.
        :type store_on_server: bool
        :param location: Directory location to store report in (for non-default storage).
        :type location: str
        :param email: E-mail configuration.
        :type email: Email
        """
        self.store_on_server = store_on_server
        self.location = location
        self.email = email

    def AsXML(self):
        xml_data = create_element('Delivery')
        xml_storage = create_element('Storage', {'storeOnServer': 1 if self.store_on_server else 0})
        if self.location:
            xml_location = create_element('location')
            xml_location.text = self.location
            xml_storage.append(xml_location)
        xml_data.append(xml_storage)
        if self.email:
            xml_data.append(self.email.AsXML())

        return xml_data

    @staticmethod
    def CreateFromXML(xml_data):
        storage = get_element(xml_data, 'Storage')
        store_on_server = get_attribute(storage, 'storeOnServer')
        location_xml = get_element(xml_data, 'location')
        location = location_xml.text if location_xml is not None else None
        email_xml = get_element(xml_data, 'Email')
        email = Email.CreateFromXML(email_xml) if email_xml is not None else None
        truthy = [1, '1', 'true', 'True', 'TRUE']
        return Delivery(store_on_server in truthy, location, email)


# TODO: implement db export for report config
class DBExport:
    def __init__(self):
        pass

    def AsXML(self):
        pass


# TODO: implement db export credential
class ExportCredential:
    def __init__(self):
        pass

    def AsXML(self):
        pass
