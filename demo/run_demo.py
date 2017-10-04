#!/usr/bin/env python
# Future Imports for py2/3 backwards compat.
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

from builtins import map
from builtins import input
from builtins import range
from time import sleep
from io import BytesIO
from zipfile import ZipFile
import sslfix
import nexpose.nexpose as nexpose
from nexpose.xml_utils import as_string, as_xml
from future import standard_library
standard_library.install_aliases()


def xrange_as_customstr(xrange_object):
    return repr(xrange_object).replace('xrange', '').replace('(', '[').replace(')', ']').replace(', ', '..')


def as_percentage(current, total):
    return current * 100.0 / total


def wait_for_status(expected_status, message):
    print(message)
    while True:
        status = session.GetSecurityConsoleStatus()
        print("  Current status:", status)
        if status == expected_status:
            break
        sleep(5)


def DemonstrateBackupAPI():
    def GetDownloadCallback(filename, total_size):
        def DownloadCallback(already_downloaded_data, new_data):
            downloaded_size = len(already_downloaded_data) + len(new_data)
            print("\rDownload of {0} is {1:.2f}% complete".format(filename, as_percentage(downloaded_size, total_size)), end=' ')
        return DownloadCallback

    print("Backup API")
    print("----------")

    name_of_backup_made = None

    original_backups = list(session.GetBackups())
    if session.CreateBackup(platform_independent=True, description='This a test...'):
        print("A backup has been scheduled and the security console is now restarting...")

        wait_for_status(nexpose.NexposeStatus.MAINTENANCE_MODE, "Waiting for the security console to enter maintenance mode...")
        wait_for_status(nexpose.NexposeStatus.NORMAL_MODE, "Waiting for the security console to re-enter normal mode...")

        print("The security console entered normal mode again (as expected).")
        print("Creating a new session..")
        InitializeGlobalSession()  # We need to login again as the session became invalid!

        # Assume the backup we made is the difference
        original_backup_names = [backup.name for backup in original_backups]
        new_backup_names = [backup.name for backup in session.GetBackups()]
        difference_in_backups = list(set(new_backup_names) - set(original_backup_names))
        if difference_in_backups:
            print("Backups that were created:", ', '.join(difference_in_backups))
            if len(difference_in_backups) == 1:
                name_of_backup_made = difference_in_backups[0]
        else:
            print("No backups were created!?")
    else:
        print("A backup couldn't be created!?")

    print("Backups stored on the appliance (in no specific order):")
    backups = list(session.GetBackups())
    if backups:
        for backup in backups:
            isinstance(backup, nexpose.Backup)
            print("  Name:", backup.name)
            print("  Details:")
            print("    Size:", backup.size)
            print("    Date:", backup.date)
            print("    Description:", backup.description)
            print("    Nexpose Version:", backup.nexpose_version)
            print("    Platform-Independent?:", 'yes' if backup.platform_independent else 'no')

        last_backup = backups[-1]
        backup_data = session.DownloadBackup(last_backup, GetDownloadCallback(last_backup.name, last_backup.size))
        backup_zip = ZipFile(BytesIO(backup_data))
        print("\nFiles inside the last enumerated backup:")
        for filename in backup_zip.namelist():
            print("  {0}".format(filename))
        print("Downloaded Size:", len(backup_data))
        print("Expected Size:", last_backup.size)
    else:
        print("  (none)")
        print("Download test skipped because there were no backups found!")

    if name_of_backup_made:
        print("Deleting backup {0}...".format(name_of_backup_made))
        if session.DeleteBackup(name_of_backup_made):
            print("  Succeeded!")
        else:
            print("  Failed!?")


def DemonstrateCriteriaAPI():
    print("Criteria API")
    print("------------")

    print("Supported Fields:")
    for field in nexpose.Criteria.GetFields():
        print(" ", field.Name)
        if field.Name == field.Code or not field.Code in nexpose.Criteria.GetFieldNames():  # The extra or-test is to handle the exceptional SITE_ID(SITE_NAME)
            if field.Name == "SITE_ID":
                assert field.Code == "SITE_NAME" and not field.Code in nexpose.Criteria.GetFieldNames()
            print("    Code:", field.Code)
            print("    Valid Operators:", 'None!?' if not field.ValidOperators else '')
            for operator in field.ValidOperators:
                print("     ", operator)
            print("    Valid Values:")
            if field.ValidValues is None:
                print("      {0}".format('(any)'))
            elif isinstance(field.ValidValues, xrange):
                print("      {0}".format(xrange_as_customstr(field.ValidValues)))
            else:
                for value in field.ValidValues:
                    print("      {0}".format(value))
        else:
            assert field.Name != "SITE_ID"
            print("    See: {0}".format(field.Code))


def DemonstrateSharedCredentialsAPI():
    print("Shared Credentials API")
    print("----------------------")

    credential = nexpose.Credential_CIFS.Create()
    credential.username = 'Administrator'
    credential.password = 'LOL'
    shared_credential = nexpose.SharedCredentialConfiguration.Create()
    shared_credential.name = 'Shared Credential Testing'
    shared_credential.credential = credential
    shared_credential_id = session.SaveSharedCredentialConfiguration(shared_credential)
    print("A new shared credential was created:")
    print("  Created ID:", shared_credential_id)

    print("Shared Credential:")
    for summary in session.GetSharedCredentialSummaries():
        assert isinstance(summary, nexpose.SharedCredentialSummary)
        config = session.GetSharedCredentialConfiguration(summary)
        assert isinstance(config, nexpose.SharedCredentialConfiguration)
        account = config.credential

        site_count_sum = len(config.enabled_sites) + len(config.disabled_sites)

        print("  ID:", summary.id)
        print("  Summary:")
        print("    Name:", summary.name)
        print("    Service:", summary.service)
        print("    Username:", summary.username)
        print("    Domain:", summary.domain)
        print("    Privilege Username:", summary.privilege_username)
        print("    All Sites?:", 'yes' if summary.all_sites else 'no')
        print("    Site Count:", summary.site_count)
        print("    Last Modified:", summary.last_modified)
        print("  Configuration:")
        print("    Name:", config.name)
        print("    Description:", repr(config.description))
        print("    Service:", config.service)
        print("    Account:")
        for name in [name for name in dir(account) if name.islower() and name[0].isalpha()]:
            print("      {0}: {1}".format(name.capitalize(), account.__dict__[name]))
        print("    Restriction, Host:", config.restriction_host)
        print("    Restriction, Port:", config.restriction_port)
        print("    All Sites?:", 'yes' if config.all_sites else 'no')
        print("    Enabled Sites:")
        for id in config.enabled_sites:
            print("      Site ID:", id)
        print("    Disabled Sites:")
        for id in config.disabled_sites:
            print("      Site ID:", id)
        print("    Enabled/Disabled Site Count:", site_count_sum)
        print("    Site Count Verification:", "passed" if site_count_sum == summary.site_count else "mismatch?!")

    print("Deleting the (new) shared credential:")
    if session.DeleteSharedCredential(shared_credential_id):
        print("    Deleted ID:", shared_credential_id)
    else:
        print("    Failed to delete ID:", shared_credential_id)


def DemonstrateTagAPI():
    print("Tag API (2.0)")
    print("-------")

    print("Adding tag 1 to site 1...")
    session.AddTagToSite(1, 1)
    print("  Done!")

    print("Tag:")
    for tag in session.GetTags():
        assert isinstance(tag, nexpose.Tag)
        config = tag.config
        if config is not None:
            assert isinstance(config, nexpose.TagConfiguration)
        print("  ID:", tag.id)
        print("  Name:", tag.name.encode('ascii', 'xmlcharrefreplace'))
        print("  Type:", tag.type)
        print("  Asset ID's:")
        for asset_id in tag.asset_ids:
            print("    ID:", asset_id)
        print("  Attributes:")
        for attribute in tag.attributes:
            assert isinstance(attribute, nexpose.TagAttribute)
            print("    ID:", attribute.id)
            print("    Name:", attribute.name)
            print("    Type:", attribute.value)
        if config:
            print("  Configuration:")
            print("    Asset Group ID's:")
            for assetgroup_id in config.assetgroup_ids:
                print("      ID:", assetgroup_id)
            print("    Associated Asset ID's:")
            for asset_id in config.associated_asset_ids:
                print("    ID:", asset_id)
            print("    Site ID's:")
            for site_id in config.site_ids:
                print("    ID:", site_id)
            print("    Search Criteria:", config.search_criteria)

    print("Removing tag 1 from site 1...")
    session.RemoveTagFromSite(1, 1)
    print("  Done!")


def DemonstrateAssetAPI():
    print("Asset Management API (2.1)")
    print("--------------------")

    print("Asset summaries:")
    for asset in session.GetAssetSummaries():
        assert isinstance(asset, nexpose.AssetSummary)
        details = session.GetAssetDetails(asset)
        print("  ID:", asset.id)
        print("  Site ID:", asset.site_id)
        print("  Last Scan ID:", details.last_scan_id)
        print("  Last Scan Date:", details.last_scan_date)
        print("  Risk Factor:", asset.risk_factor)
        print("  Risk Score:", asset.risk_score)
        print("  OS Name:", details.os_name)
        print("  OS CPE:", details.os_cpe)
        print("  Host:", asset.host)
        print("  Host Type:", details.host_type)
        print("  Host Names:", ', '.join(details.host_names))
        print("  Addresses:", ', '.join(details.addresses))
        print("  IP Address:", details.ip_address)
        print("  MAC Address:", details.mac_address)


def DemonstrateAssetFilterAPI():
    print("Asset Filter API")
    print("----------------")

    print("Listing all sites with a non-zero ID:")
    criterion = nexpose.Criteria.Criterion(nexpose.Criteria.SITE_ID, nexpose.Criteria.NOT_IN, '0')
    for asset in session.GetFilteredAssets(criterion):
        assert isinstance(asset, nexpose.FilteredAsset)
        print("  ID:", asset.id)
        print("  Asset Name:", asset.asset_name)
        print("  IP Address:", asset.ip_address)
        print("  Last Scan Date:", asset.last_scan_date)
        print("  Assessed?:", 'yes' if asset.assessed else 'no')
        if asset.assessed:
            print("  Assesment details:")
            print("    Risk Score:", asset.risk_score)
            print("    OS ID:", asset.os_id)
            print("    OS Name:", asset.os_name)
            print("    Exploit Count:", asset.exploit_count)
            print("    Malware Count:", asset.malware_count)
            print("    Vulnerability Count:", asset.vulnerability_count)


def DemonstrateRoleAPI():
    print("Role Management API")
    print("-------------------")

    source = session.GetRoleDetails(list(session.GetRoleSummaries())[-1])
    custom_role = nexpose.RoleDetails.CreateNamedBasedOn(source, 'test', 'Test')
    custom_role.description = 'Test role'
    print('Adding:', session.SaveRole(custom_role))

    for details in map(session.GetRoleDetails, session.GetRoleSummaries()):
        assert isinstance(details, nexpose.RoleDetails)
        print('ID:', details.id)
        print('Name:', details.name)
        print('Full name:', details.fullname)
        print('Description:', details.description)
        print('Enabled?:', 'yes' if details.is_enabled else 'no')
        print('Scope:', details.scope)
        if details.name == 'test' or True:  # remove 'or True' for testing
            print('Asset Group Privileges:')
            for key, value in details.assetgroup_privileges.items():
                print('  {0}:'.format(key), value)
            print('Global Privileges:')
            for key, value in details.global_privileges.items():
                print('  {0}:'.format(key), value)
            print('Site Privileges:')
            for key, value in details.site_privileges.items():
                print('  {0}:'.format(key), value)

    print('Deleting:', session.DeleteRole(custom_role))


def DemonstrateVulnerabilityAPI():
    print("Vulnerability Management API")
    print("----------------------------")

    for vulnerability in session.GetVulnerabilities():
        assert isinstance(vulnerability, nexpose.VulnerabilitySummary)
        print('ID:', vulnerability.id)
        print('Title:', vulnerability.title.encode('ascii', 'xmlcharrefreplace'))  # dns-bind-cve-2010-0218 contains unicode
        print('Published:', vulnerability.published)
        print('Added:', vulnerability.added)
        print('Modified:', vulnerability.modified)
        print('Is Safe?: ', 'yes' if vulnerability.is_safe else 'no')
        print('Requires Credentials?: ', 'yes' if vulnerability.requires_credentials else 'no')
        print('Severity:', vulnerability.severity)
        print('PCI Severity:', vulnerability.pci_severity)
        print('CVSS Score:', vulnerability.cvss_score)
        print('CVSS Vector:', vulnerability.cvss_vector)
        if not vulnerability.is_safe:
            # for this demo, we only print the details of unsafe vulnerabilities
            vulnerability = session.GetVulnerabilityDetails(vulnerability)
            assert isinstance(vulnerability, nexpose.VulnerabilityDetail)
            print("Description:")
            print(vulnerability.description.strip())
            print("Solution:")
            print(vulnerability.solution.strip())
            print("References:")
            for reference in vulnerability.references:
                assert isinstance(reference, nexpose.VulnerabilityReference)
                print("  Source:", reference.source)


def DemonstrateVulnerabilityExceptionAPI():
    print("Vulnerability Exception Management API")
    print("--------------------------------------")

    print("Silo Vulnerability Exception Details:")
    for i, details in enumerate(session.GetAllSiloVulnerabilityExceptionDetails()):
        assert isinstance(details, nexpose.SiloVulnerabilityExceptionDetails)
        print("  Silo {0}:".format(i + 1))
        print("    ID:", details.silo_id)
        print("    Oldest Exception Creation Date:", details.oldest_exception_creation_date)
        print("    Pending Exception Count:", details.pending_exception_count)
    for i, o in enumerate(session.GetVulnerabilityExceptions()):
        assert isinstance(o, nexpose.VulnerabilityException)
        print("  Vulnerability Exception {0}:".format(i + 1))
        print("    ID:", o.id)
        print("    Vulnerability ID:", o.vulnerability_id)
        print("    Vulnerability Key:", o.vulnerability_key)
        print("    Submitter:", o.submitter)
        print("    Submitter Comment:", repr(o.submitter_comment) if o.submitter_comment else '')
        print("    Reviewer:", o.reviewer)
        print("    Reviewer Comment:", repr(o.reviewer_comment) if o.reviewer_comment else '')
        print("    Status:", o.status)
        print("    Reason:", o.reason)
        print("    Scope:", o.scope)
        print("    Asset ID:", o.asset_id)
        print("    Asset Port:", o.asset_port)
    #try:
    #    session.RejectVulnerabilityException(3)
    #except:
    #    pass
    #session.ResubmitVulnerabilityException(3, nexpose.VulnerabilityExceptionReason.FALSE_POSITIVE)
    session.DeleteVulnerabilityException(3)
    #print as_string(session.DeleteVulnerabilityException(0x7FFFFFFF))
    eval(input())


def DemonstrateSiteAPI():
    print("Site Management API")
    print("-------------------")

    for site in session.GetSiteSummaries():
        assert isinstance(site, nexpose.SiteSummary)
        config = session.GetSiteConfiguration(site)
        assert isinstance(config, nexpose.SiteConfiguration)

        print("Site:")
        print("  ID:", site.id)
        print("  Short Description:", repr(site.short_description))
        print("  Description:", repr(config.description))
        print("  Risk Factor:", site.risk_factor)
        print("  Risk Score:", site.risk_score)
        print("  Type:", "Dynamic" if config.is_dynamic else "Static")
        print("  Asset Summaries:")
        for asset in session.GetSiteAssetSummaries(site):
            assert isinstance(asset, nexpose.AssetSummary)
            assert asset.site_id == site.id
            print("    ID:", asset.id)
            print("    Host:", asset.host)
            print("    Risk Factor:", asset.risk_factor)
            print("    Risk Score:", asset.risk_score)
            session.DeleteAsset(asset)
        print("  Scan Summaries:")
        for summary in session.GetSiteScanSummaries(site):
            assert isinstance(summary, nexpose.ScanSummary)
            assert summary.site_id == site.id
            print("    ID:", summary.id)
            print("    Name:", summary.name)
            print("    Message:", summary.message)

    config = session.GetSiteConfiguration(1)
    session.SaveSiteConfiguration(config)


def DemonstrateEngineAPI():
    print("Engine Management API")
    print("---------------------")

    custom_engine = nexpose.EngineConfiguration.CreateNamed('test')
    custom_engine.host = 'localhost'
    try:
        session.SaveEngineConfiguration(custom_engine)
    except nexpose.NexposeException:
        print("Failed to add scan engine")

    local_engine = session.GetLocalEngineSummary()

    print("Available Scan Engines:")
    for engine in session.GetEngineSummaries():
        assert isinstance(engine, nexpose.EngineSummary)
        config = session.GetEngineConfiguration(engine)
        assert isinstance(config, nexpose.EngineConfiguration)

        print("  Scan Engine:")
        print("    ID:", engine.id)
        print("    Name:", engine.name)
        print("    Host:", engine.host)
        print("    Port:", engine.port)
        print("    Scope:", engine.scope)
        print("    Priority:", config.priority)
        print("    Status:", engine.status)
        print("    Assigned Sites:")
        for site_id, site_name in config.assigned_sites:
            print("      ID:", site_id)
            print("      Name:", site_name)
        print("    Local scan engine?:", 'yes' if engine.id == local_engine.id else 'no')

    try:
        print("Starting a scan on site with ID 1:")
        scan_id, engine_id = session.StartSiteScan(1)
        print("  Scan ID:", scan_id)
        print("  Engine ID:", engine_id)

        print("Waiting for scan to end:")
        while session.GetScanStatus(scan_id)[1] == nexpose.ScanStatus.Running:
            for scan in session.GetEngineActiveScanSummaries(engine_id):
                assert isinstance(scan, nexpose.ScanSummary)
                node_counts = scan.node_counts
                assert isinstance(node_counts, nexpose.ScanSummaryNodeCounts)
                task_counts = scan.task_counts
                assert isinstance(task_counts, nexpose.ScanSummaryTaskCounts)
                if scan.id != scan_id:
                    continue
                print("  Site ID:", scan.site_id)
                print("  Name:", scan.name)
                print("  Message:", scan.message)
                print("  Start Time:", scan.start_time)
                print("  End Time:", scan.end_time)
                print("  Node Counts:")
                print("    Dead:", node_counts.dead)
                print("    Live:", node_counts.live)
                print("    Filtered:", node_counts.filtered)
                print("    Unresolved:", node_counts.unresolved)
                print("    Other:", node_counts.other)
                print("  Task Counts:")
                print("    Completed:", task_counts.completed)
                print("    Active:", task_counts.active)
                print("    Pending:", task_counts.pending)
                print("  Vulnerabilities:")
                for i, vulnerability in enumerate(scan.vulnerabilities):
                    assert isinstance(vulnerability, nexpose.ScanSummaryVulnerability)
                    print("    Vulnerability {0}".format(i + 1))
                    print("      Status:", vulnerability.status)
                    print("      Severity:", vulnerability.severity)
                    print("      Count:", vulnerability.count)

            print("  Updating in 5 seconds:", end=' ')
            for i in range(5):
                sleep(1)
                print(".", end=' ')
            print("")

        print("Test ended.")
    except Exception as ex:
        scan_id, engine_id = 0, 0
        print("  Failure:", ex)
        print("Test skipped.")

    if custom_engine.id > 0:
        session.DeleteEngine(custom_engine)


def DemonstrateDiscoveryConnectionAPI():
    print("Discovery Connection API")
    print("------------------------")

    custom_dc = nexpose.DiscoveryConnectionConfiguration.CreateNamedFromURL('test', 'http://www.google.be', 'admin', 'password')
    session.SaveDiscoveryConnection(custom_dc)

    for dc in session.GetDiscoveryConnectionSummaries():
        assert isinstance(dc, nexpose.DiscoveryConnectionSummary)
        print("ID:", dc.id)


def DemonstrateScanPI():
    print("Scan API")
    print("--------")

    try:
        print("Starting a scan on site with ID 1:")
        scan_id, engine_id = session.StartSiteScan(1)
        print("  Scan ID:", scan_id)
        print("  Engine ID:", engine_id)
    except Exception as ex:
        scan_id, engine_id = 0, 0
        print("  Failure:", ex)

    print("Active scans after pause:")
    for scan in session.GetActiveScanSummaries():
        assert isinstance(scan, nexpose.ScanSummary)
        print("  ID:", scan.id)
        print("  Status:", scan.scan_status)
        print("  Start Time:", scan.start_time)

    if scan_id:
        print("Testing scan pause:", end=' ')
        session.PauseScan(scan_id)
        print("OK")

    print("Active scans after pause:")
    for scan in session.GetActiveScanSummaries():
        assert isinstance(scan, nexpose.ScanSummary)
        print("  ID:", scan.id)
        print("  Status:", scan.scan_status)

    if scan_id:
        print("Testing scan resume:", end=' ')
        session.ResumeScan(scan_id)
        print("OK")

    print("Active scans after resume:")
    for scan in session.GetActiveScanSummaries():
        assert isinstance(scan, nexpose.ScanSummary)
        print("  ID:", scan.id)
        print("  Status:", scan.scan_status)

    if scan_id:
        print("Testing scan stop:", end=' ')
        session.StopScan(scan_id)
        print("OK")

        engine_id, status = session.GetScanStatus(scan_id)
        print("  Engine ID:", engine_id)
        print("  Status:", status)

        print("Scan Summary:")
        scan = session.GetScanSummary(scan_id)
        assert isinstance(scan, nexpose.ScanSummary)
        print("  Start Time:", scan.start_time)
        print("  End Time:", scan.end_time)


def DemonstrateUserAPI():
    print("User API")
    print("--------")

    print("User Authenticators:")
    for authenticator in session.GetUserAuthenticatorSummaries():
        assert isinstance(authenticator, nexpose.UserAuthenticatorSummary)
        print("  ID:", authenticator.id)
        print("  Is External?:", 'yes' if authenticator.is_external else 'no')
        print("  Module:", authenticator.module)
        print("  Source:", authenticator.source)

    custom_user = nexpose.UserConfiguration.CreateNamed("test_user", "Test User")
    isinstance(custom_user, nexpose.UserConfiguration)
    custom_user.password = "123456"
    custom_user_id = session.SaveUserConfiguration(custom_user)
    print("A new user was created with id {0}".format(custom_user_id))

    print("Users:")
    for user in session.GetUserSummaries():
        assert isinstance(user, nexpose.UserSummary)
        statistics = user.statistics
        assert isinstance(statistics, nexpose.UserSummaryStatistics)
        config = session.GetUserConfiguration(user)
        assert isinstance(config, nexpose.UserConfiguration)
        print("  ID:", user.id)
        print("  Password:", config.password)
        print("  User Name:", user.username)
        print("  Full Name:", user.fullname)
        print("  Role Name:", config.role_name)
        print("  e-Mail Address:", user.email)
        print("  Authenticator ID:", config.authenticator_id)
        print("  Authenticator Module:", user.authenticator_module)
        print("  Authenticator Source:", user.authenticator_source)
        print("  All Asset Groups Access?:", 'yes' if config.has_access_to_all_assetgroups else 'no')
        print("  All Sites Access?:", 'yes' if config.has_access_to_all_sites else 'no')
        print("  Is Administrator?:", 'yes' if user.is_administrator else 'no')
        print("  Is Disabled?:", 'yes' if user.is_disabled else 'no')
        print("  Is Enabled?:", 'yes' if config.is_enabled else 'no')
        print("  Is Locked?:", 'yes' if user.is_locked else 'no')
        print("  Statistics:")
        print("    Asset Group Count:", statistics.assetgroup_count)
        print("    Asset Groups:", ', '.join(map(str, config.accessible_assetgroups)))
        print("    Site Count:", statistics.site_count)
        print("    Sites:", ', '.join(map(str, config.accessible_sites)))

    session.DeleteUser(custom_user)
    print("The new user was deleted.")


def DemonstrateAssetGroupAPI():
    print("Asset Group API")
    print("---------------")

    print("Asset Groups:")
    for asset_group in session.GetAssetGroupSummaries():
        assert isinstance(asset_group, nexpose.AssetGroupSummary)
        config = session.GetAssetGroupConfiguration(asset_group)
        assert isinstance(config, nexpose.AssetGroupConfiguration)
        print("  ID:", asset_group.id)
        print("  Name:", asset_group.name)
        print("  Short Description:", repr(asset_group.short_description))
        print("  Description:", repr(config.description))
        print("  Risk Score:", asset_group.risk_score)
        print("  Asset Summaries:")
        for asset in config.asset_summaries:
            assert isinstance(asset, nexpose.AssetSummary)
            print("    ID:", asset.id)
            print("    Site ID:", asset.site_id)
            print("    Host:", asset.host)
            print("    Risk Factor:", asset.risk_factor)
            print("    Risk Score:", asset.risk_score)


def DemonstrateTicketAPI():
    print("Ticket API")
    print("----------")

    print("Tickets:")
    for ticket in session.GetTicketSummaries():
        assert isinstance(ticket, nexpose.TicketSummary)
        details = session.GetTicketDetails(ticket)
        assert isinstance(details, nexpose.TicketDetails)
        print("  ID:", ticket.id)
        print("  Name:", ticket.name)
        print("  Asset ID:", ticket.asset_id)
        print("  Author:", ticket.author)
        print("  Created On:", ticket.created_on)
        print("  Assigned To:", ticket.assigned_to)
        print("  State:", ticket.state)
        print("  Priority:", ticket.priority)
        print("  Vulnerability ID's:")
        for vulnerability_id in details.vulnerabilities_ids:
            print("    {0}".format(vulnerability_id))
        print("  History:")
        for i, event in enumerate(details.events):
            assert isinstance(event, nexpose.TicketEvent)
            print("    Event {0}:".format(i + 1))
            print("      Title:", event.title)
            print("      Author:", event.author)
            print("      Created On:", event.created_on)
            print("      State:", event.state)
            print("      Comment:", repr(event.comment))


def DemonstrateReportAPI():
    print('Report API')
    print('----------')
    report = nexpose.ReportConfiguration('Python API Client Test Report', 'audit-report', 'raw-xml-v2')
    report.add_common_vuln_filters()
    print('Saving report configuration...')
    print(as_string(report.AsXML()))
    resp = session.SaveReportConfiguration(report)
    print('Saved Report ID: {}'.format(resp))

    print('Loading report configuration with ID {}...'.format(resp))
    loaded_report = session.GetReportConfigurationDetails(resp)
    print(as_string(loaded_report.AsXML()))

    print('Deleting report configuration with ID {}...'.format(resp))
    session.DeleteReportConfiguration(resp)
    print('Done with Report API demo.')

def GetNexposeLoginSettings():
    """
    Returns a list with following information: hostname_or_ip, port, username, password.
    An exception is raised if "demo.cfg" is not found or contains invalid/no data.
    """
    try:
        with open("demo.cfg") as config_file:
            for line in config_file.readlines():
                if not line.strip().startswith('#'):
                    data = line.split()
                    if len(data) != 4:
                        raise ValueError("demo.cfg contains invalid data")
                    return data
        raise ValueError("demo.cfg contains no data")
    except:
        raise Exception("demo.cfg could not be found, please refer to demo.cfg.default")


def InitializeGlobalSession():
    """Returns a tuple with following information: (hostname_or_ip, port, username, password)"""
    global session

    login_info = GetNexposeLoginSettings()
    session = nexpose.NexposeSession.Create(*login_info)
    wait_for_status(nexpose.NexposeStatus.NORMAL_MODE, "Waiting for the console to be ready:")
    print("The Security Console is ready...")
    session.Open()


def main():
    sslfix.patch()  # NOTE: this bypasses SSL verification, do not use this solution in production!
    InitializeGlobalSession()
    assert isinstance(session, nexpose.NexposeSession)

    #DemonstrateBackupAPI()
    #DemonstrateCriteriaAPI()
    #DemonstrateSharedCredentialsAPI()
    #DemonstrateTagAPI()
    #DemonstrateAssetAPI()
    #DemonstrateAssetFilterAPI()
    #DemonstrateVulnerabilityAPI()
    #DemonstrateVulnerabilityExceptionAPI()
    #DemonstrateRoleAPI()
    #DemonstrateSiteAPI()
    #DemonstrateEngineAPI()
    #DemonstrateDiscoveryConnectionAPI()
    #DemonstrateScanPI()
    #DemonstrateUserAPI()
    #DemonstrateAssetGroupAPI()
    #DemonstrateTicketAPI()
    DemonstrateReportAPI()

    #print session.GenerateScanReport(1)

    session.Close()


if __name__ == "__main__":
    main()
