# Future Imports for py2/3 backwards compat.
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from builtins import object
from future import standard_library
standard_library.install_aliases()


class AssetGroupPrivileges(object):
    ConfigureAssets = 'ConfigureAssets'
    ConfigureAssets = 'ViewAssetData'


class GlobalPrivileges(object):
    AddUsersToGroup = 'AddUsersToGroup'
    AddUsersToReport = 'AddUsersToReport'
    AddUsersToSite = 'AddUsersToSite'
    ApproveVulnExceptions = 'ApproveVulnExceptions'
    ApproveVulnerabilityExceptions = ApproveVulnExceptions
    CloseTickets = 'CloseTickets'
    ConfigureGlobalSettings = 'ConfigureGlobalSettings'
    CreateReports = 'CreateReports'
    CreateTickets = 'CreateTickets'
    DeleteVulnExceptions = 'DeleteVulnExceptions'
    DeleteVulnerabilityExceptions = DeleteVulnExceptions
    GenerateRestrictedReports = 'GenerateRestrictedReports'
    ManageAssetGroups = 'ManageAssetGroups'
    ManageDynamicAssetGroups = 'ManageDynamicAssetGroups'
    ManagePolicies = 'ManagePolicies'
    ManageReportTemplates = 'ManageReportTemplates'
    ManageScanEngines = 'ManageScanEngines'
    ManageScanTemplates = 'ManageScanTemplates'
    ManageSites = 'ManageSites'
    ManageTags = 'ManageTags'
    SubmitVulnExceptions = 'SubmitVulnExceptions'
    SubmitVulnerabilityExceptions = SubmitVulnExceptions
    TicketAssignee = 'TicketAssignee'


class SitePrivileges(object):
    ConfigureAlerts = 'ConfigureAlerts'
    ConfigureCredentials = 'ConfigureCredentials'
    ConfigureEngines = 'ConfigureEngines'
    ConfigureScanTemplates = 'ConfigureScanTemplates'
    ConfigureScheduleScans = 'ConfigureScheduleScans'
    ConfigureSiteSettings = 'ConfigureSiteSettings'
    ConfigureTargets = 'ConfigureTargets'
    ManualScans = 'ManualScans'
    PurgeData = 'PurgeData'
    ViewAssetData = 'ViewAssetData'
