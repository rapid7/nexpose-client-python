from __future__ import (absolute_import, division, print_function, unicode_literals)
from future import standard_library
standard_library.install_aliases()
import os
import sys
import pytest
import nexpose.nexpose as nexpose
from nexpose.nexpose_report import Email, Delivery, Frequency, Schedule


@pytest.fixture
def vcr_cassette_path(request, vcr_cassette_name):
    # Put all cassettes in test_fixtures/cassettes/{module}/{test}.yaml
    return os.path.join('test_fixtures', 'cassettes', request.module.__name__, vcr_cassette_name)


@pytest.mark.skipif(sys.version_info < (3, 4), reason="vcr not working on py2")
@pytest.mark.vcr()
def test_report_config():
    # login to Nexpose console
    session = nexpose.NexposeSession.Create('localhost', 3780, 'nxadmin', 'nxadmin')
    session._session_id = 'C949AAFB1DDF91B1865A4471F9E53A79D186B526'  # skip opening a session for real

    # create report config object
    report = nexpose.ReportConfiguration('Python API Client Test Report', 'audit-report', 'raw-xml-v2')
    report.add_filter('scan', 'last')  # this should use site/group/tag filter(s) instead of scan in real world use
    report.add_common_vuln_filters()  # adds vuln filters to match UI defaults
    email = Email(True, send_as='file')
    email.smtp_relay_server = 'whatever.example.com'
    email.sender = 'whatever@example.com'
    email.recipients.append('someone@example.com')
    delivery = Delivery(True, None, email)
    report.delivery = delivery
    schedule = Schedule('weekly', 1, "20171105T164239700")
    freq = Frequency(False, True, schedule)
    report.frequency = freq
    report.timezone = 'America/Los_Angeles'

    # save the report config to the console
    resp = session.SaveReportConfiguration(report)
    assert resp == 4604  # Don't be too sad if/when this changes

    # load the report configuration from the console into a new report config object
    loaded_report = nexpose.ReportConfiguration.CreateFromXML(session.RequestReportConfig(resp))
    assert isinstance(loaded_report, nexpose.ReportConfiguration)
    assert loaded_report.name == report.name

    # finally, delete the report configuration
    session.DeleteReportConfiguration(resp)
