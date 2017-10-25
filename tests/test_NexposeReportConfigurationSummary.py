# Future Imports for py2/3 backwards compat.
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from .load_unittest import unittest
from .LoadFixture import CreateEmptyFixture, LoadFixture, XML, JSON
from nexpose.nexpose_report import ReportStatus, ReportConfigurationSummary, ReportSummary
from future import standard_library
standard_library.install_aliases()


class NexposeReportConfigurationSummaryTestCase(unittest.TestCase):
    def testCreateFromXML(self):
        fixture = CreateEmptyFixture(XML)
        report_cfg = ReportConfigurationSummary.CreateFromXML(fixture)
        self.assertEquals(0, report_cfg.id)
        self.assertEquals(None, report_cfg.template_id)
        self.assertEquals(None, report_cfg.name)
        self.assertEquals(ReportStatus.UNKNOWN, report_cfg.status)
        self.assertEquals('', report_cfg.generated_on)
        self.assertEquals('', report_cfg.URI)
        self.assertEquals('silo', report_cfg.scope)

        fixture = LoadFixture('ReportListingResponse.xml')

        report_cfg = ReportConfigurationSummary.CreateFromXML(fixture[0])
        self.assertEquals(2, report_cfg.id)
        self.assertEquals('audit-report', report_cfg.template_id)
        self.assertEquals('Report 2.0 - Complete Site', report_cfg.name)
        self.assertEquals(ReportStatus.GENERATED, report_cfg.status)
        self.assertEquals('20160303T122452808', report_cfg.generated_on)
        self.assertEquals('/reports/00000002/00000002/report.xml', report_cfg.URI)
        self.assertEquals('silo', report_cfg.scope)

        report_cfg = ReportConfigurationSummary.CreateFromXML(fixture[1])
        self.assertEquals(3, report_cfg.id)
        self.assertEquals('audit-report', report_cfg.template_id)
        self.assertEquals('Report 2.0 - Including non-vuln', report_cfg.name)
        self.assertEquals(ReportStatus.GENERATED, report_cfg.status)
        self.assertEquals('20160303T122922250', report_cfg.generated_on)
        self.assertEquals('/reports/00000003/00000003/report.xml', report_cfg.URI)
        self.assertEquals('silo', report_cfg.scope)

        report_cfg = ReportConfigurationSummary.CreateFromXML(fixture[2])
        self.assertEquals(1, report_cfg.id)
        self.assertEquals('audit-report', report_cfg.template_id)
        self.assertEquals('XML 2.0 export', report_cfg.name)
        self.assertEquals(ReportStatus.GENERATED, report_cfg.status)
        self.assertEquals('20160219T062407874', report_cfg.generated_on)
        self.assertEquals('/reports/00000001/00000001/report.xml', report_cfg.URI)
        self.assertEquals('global', report_cfg.scope)


class NexposeReportSummaryTestCase(unittest.TestCase):
    def testCreateFromXML(self):
        fixture = CreateEmptyFixture(XML)
        report_summary = ReportSummary.CreateFromXML(fixture)
        self.assertEquals(0, report_summary.id)
        self.assertEquals(ReportStatus.UNKNOWN, report_summary.status)
        self.assertEquals('', report_summary.generated_on)
        self.assertEquals('', report_summary.URI)
        self.assertEquals('silo', report_summary.scope)

        fixture = LoadFixture('ReportHistoryResponse.xml')

        report_summary = ReportSummary.CreateFromXML(fixture[0])
        self.assertEquals(6, report_summary.id)
        self.assertEquals(2, report_summary.configuration_id)
        self.assertEquals(ReportStatus.GENERATED, report_summary.status)
        self.assertEquals('20160303T161938459', report_summary.generated_on)
        self.assertEquals('/reports/00000002/00000006/report.xml', report_summary.URI)
        self.assertEquals('silo', report_summary.scope)

        report_summary = ReportSummary.CreateFromXML(fixture[1])
        self.assertEquals(2, report_summary.id)
        self.assertEquals(2, report_summary.configuration_id)
        self.assertEquals(ReportStatus.GENERATED, report_summary.status)
        self.assertEquals('20160303T122452808', report_summary.generated_on)
        self.assertEquals('/reports/00000002/00000002/report.xml', report_summary.URI)
        self.assertEquals('silo', report_summary.scope)
