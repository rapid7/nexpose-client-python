import urllib, urllib2
import base64
from itertools import imap

import json
from json_utils import load_urls

from lxml import etree
from xml_utils import create_element, get_attribute, get_element, get_content_of, get_children_of, as_string, as_xml

from python_utils import remove_front_slash, utf8_encoded

from nexpose_asset import AssetHostTypes, AssetBase, AssetSummary, AssetDetails
from nexpose_assetgroup import AssetGroupSummary, AssetGroupConfiguration
from nexpose_assetfilter import AssetFilter, FilteredAsset
from nexpose_backup import Backup
from nexpose_credential import GetSupportedCredentials, Credential, PrivilegeElevationType
from nexpose_credential import Credential_CIFS, Credential_CIFS_Hash, Credential_AS400, Credential_CVS, Credential_RemoteExecution, Credential_TDS
from nexpose_credential import Credential_DB2, Credential_MySQL, Credential_Oracle, Credential_PostgreSQL, Credential_Sybase, Credential_Notes
from nexpose_credential import Credential_FTP, Credential_HTTP, Credential_SNMP, Credential_SNMPV3, Credential_SSH, Credential_SSH_KEY, Credential_Telnet
from nexpose_discoveryconnection import DiscoveryConnectionProtocol, DiscoveryConnectionSummary, DiscoveryConnectionConfiguration
from nexpose_engine import EngineStatus, EnginePriority, EngineBase, EngineSummary, EngineConfiguration
from nexpose_node import NodeScanStatus, NodeBase, Node
from nexpose_privileges import AssetGroupPrivileges, GlobalPrivileges, SitePrivileges
from nexpose_report import ReportStatus, ReportTemplate, ReportConfigurationSummary, ReportConfiguration, ReportSummary
from nexpose_role import RoleScope, RoleSummary, RoleDetails
from nexpose_scansummary import VulnerabilityStatus, ScanStatus, ScanSummary, ScanSummaryNodeCounts, ScanSummaryTaskCounts, ScanSummaryVulnerability
from nexpose_site import Host, Range, SiteBase, SiteSummary, SiteConfiguration
from nexpose_sharedcredential import SharedCredentialBase, SharedCredentialSummary, SharedCredentialConfiguration
from nexpose_status import NexposeStatus
from nexpose_tag import DEFAULT_SOURCENAME, DEFAULT_TAGCOLOR, TagConfiguration, TagAttribute, Tag, TagColors
from nexpose_ticket import TicketState, TicketPriority, TicketEvent, NewTicket, TicketSummary, TicketDetails
from nexpose_user import UserRoles, UserSummaryStatistics, UserBase, UserSummary, UserConfiguration
from nexpose_userauthenticator import UserAuthenticatorSummary
from nexpose_vulnerability import VulnerabilityReference, VulnerabilitySummary, VulnerabilityDetail
from nexpose_vulnerabilityexception import VulnerabilityExceptionStatus, VulnerabilityExceptionReason, VulnerabilityExceptionScope, SiloVulnerabilityExceptionDetails, VulnerabilityException
import nexpose_criteria as Criteria

DEFAULT_BLOCK_SIZE = 32768

def OpenWebRequest(uri, post_data, headers, timeout, get_method=None):
    request = urllib2.Request(uri, post_data, headers)
    if get_method:
        request.get_method = get_method
    if timeout == 0:
        response = urllib2.urlopen(request)
    else:
        response = urllib2.urlopen(request, timeout=timeout)
    return response

def ExecuteWebRequest(uri, post_data, headers, timeout, get_method=None):
    response = OpenWebRequest(uri, post_data, headers, timeout, get_method)
    return response.read()

def Execute_APIv1d1(uri, xml_input, timeout):
    post_data = as_string(xml_input)
    headers = {"Content-type" : "text/xml"} # TODO: add charset=UTF-8'
    response = ExecuteWebRequest(uri, post_data, headers, timeout)
    return as_xml(response)

def Execute_APIv1d2(uri, xml_input, timeout):
    return Execute_APIv1d1(uri, xml_input, timeout)

def CreateHeadersWithSessionCookie(session_id):
    headers = {}
    headers["Cookie"] = "nexposeCCSessionID={0}".format(session_id)
    return headers

def CreateHeadersWithSessionCookieAndCustomHeader(session_id):
    headers = CreateHeadersWithSessionCookie(session_id)
    headers["nexposeCCSessionID"] = "{0}".format(session_id)
    return headers

# SOURCE: https://github.com/rapid7/nexpose-client/blob/master/lib/nexpose/ajax.rb
def ExecuteGet_JSON(session_id, uri, sub_url, timeout, options=None):
    if options == None:
        options = {}
    options = map(lambda a: "{0}={1}".format(a[0], a[1]), options.iteritems())
    headers = CreateHeadersWithSessionCookie(session_id)
    #headers["Accept-Encoding"] = "utf-8"
    if sub_url.startswith('http'): # TODO: refactor uri & sub_url so that json_utils.resolve_urls can work better
        uri = sub_url
    else:
        uri = uri + sub_url + ("" if not options else "?" + "&".join(options))
    return ExecuteWebRequest(uri, None, headers, timeout).decode("utf-8")

def ExecuteWithPostData_FORM(session_id, uri, sub_url, timeout, post_data):
    headers = CreateHeadersWithSessionCookieAndCustomHeader(session_id)
    # TODO: another clue that refactor/redesign is required, xml testing if form code
    if isinstance(post_data, etree._Element):
        headers["Content-Type"] = "text/xml; charset=UTF-8"
        post_data = as_string(post_data)
    else:
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
        post_data = urllib.urlencode(utf8_encoded(post_data))
    return ExecuteWebRequest(uri + sub_url, post_data, headers, timeout, lambda: 'POST')

def ExecuteWithPostData_JSON(session_id, uri, sub_url, timeout, post_data, get_method):
    headers = CreateHeadersWithSessionCookieAndCustomHeader(session_id)
    headers["Content-Type"] = "application/json; charset=UTF-8"
    if isinstance(post_data, dict) or isinstance(post_data, list):
        post_data = json.dumps(post_data, separators=(',', ':'))
    post_data = post_data.encode('utf-8')
    return ExecuteWebRequest(uri + sub_url, post_data, headers, timeout, get_method)

def ExecutePost_JSON(session_id, uri, sub_url, timeout, post_data):
    return ExecuteWithPostData_JSON(session_id, uri, sub_url, timeout, post_data, None)

def ExecutePut_JSON(session_id, uri, sub_url, timeout, post_data):
    return ExecuteWithPostData_JSON(session_id, uri, sub_url, timeout, post_data, lambda: 'PUT')

def ExecuteDelete_JSON(session_id, uri, sub_url, timeout):
    headers = CreateHeadersWithSessionCookieAndCustomHeader(session_id)
    uri = uri + sub_url
    try:
        ExecuteWebRequest(uri, None, headers, timeout, lambda: 'DELETE')
    except urllib2.HTTPError as e:
        if e.code == 410:
            return True
        raise e
    try:
        ExecuteGet_JSON(session_id, uri, sub_url, timeout)
    except urllib2.HTTPError as e:
        if e.code == 404:
            return True
        raise e
    return False

def ExecutePagedGet_JSON(session_id, uri, sub_url, timeout, per_page = 2147483647):
    options = {}
    options["per_page"] = per_page # NOTA: API 2.0 defaults this to 500 if not set
    result = ExecuteGet_JSON(session_id, uri, sub_url, timeout, options)
    return json.loads(result)

def BuildRootURI(host, port):
    if not host: host = "localhost"
    if not port: port = 3780
    return "https://{0}:{1}/".format(host, port)

def BuildURI(host, port, version, sub_url=None):
    if not sub_url: sub_url = ''
    return BuildRootURI(host, port) + "api/{0}/{1}".format(version, sub_url)

def BuildURI_root(host, port=None):
    return BuildRootURI(host, port)

def BuildURI_APIv1d1(host, port=None):
    return BuildURI(host, port, "1.1", "xml")

def BuildURI_APIv1d2(host, port=None):
    return BuildURI(host, port, "1.2", "xml")

def BuildURI_APIv2d0(host, port=None):
    return BuildURI(host, port, "2.0")

def BuildURI_APIv2d1(host, port=None):
    return BuildURI(host, port, "2.1")

def create_objects_from_xml(elements, object_creator):
    return imap(object_creator, elements)

def request_and_create_objects_from_xml(requestor, xpath, object_creator):
    return create_objects_from_xml(requestor().iterfind(xpath), object_creator.__call__)

def BuildLoginRequest(username, password):
    attributes = {'user-id': username, 'password': password}
    login_request = create_element("LoginRequest", attributes)
    return login_request

def BuildRequest(session_id, tag, extra_attributes=None):
    request = create_element(tag, extra_attributes)
    request.attrib["session-id"] = session_id
    return request

def _HasSucceeded(result):
    return result.startswith('<result') and result.endswith('>') and 'succeded' in result

def DownloadFromStreamReader(reader, callback_function=None, block_size=DEFAULT_BLOCK_SIZE):
    if block_size < 1:
        block_size = 1

    data = bytearray()
    downloaded_size = 0
    if callback_function is not None:
        callback_function(data, bytearray())
    while True:
        buffer = reader.read(block_size)
        if not buffer:
            break

        if callback_function is not None:
            callback_function(data, buffer)

        downloaded_size += len(buffer)
        data.extend(buffer)

    return data


APIURL_SITES = "sites/{0}/"
APIURL_ASSETS = "assets/{0}/"
APIURL_ASSETGROUPS = "asset_groups/{0}/"


class NexposeException(Exception):
    def __init__(self, message):
        super(NexposeException, self).__init__(message)

class NexposeConnectionException(NexposeException):
    def __init__(self, message, inner_exception):
        super(NexposeConnectionException, self).__init__(message)
        self.inner_exception = inner_exception

class SessionIsNotOpenException(NexposeException):
    def __init__(self, message):
        super(SessionIsNotOpenException, self).__init__(message)

class SessionIsNotClosedException(NexposeException):
    def __init__(self, message):
        super(SessionIsNotClosedException, self).__init__(message)

class NexposeFailureException(NexposeException):
    def __init__(self, message):
        super(NexposeFailureException, self).__init__(message)


class DynTableColumn:
    def __init__(self, name, type):
        self.name = name
        self.type = type


class NexposeSessionBase:
    def __init__(self, host, port):
        self._URI_root = BuildURI_root(host, port)
        self._URI_APIv2d0 = BuildURI_APIv2d0(host, port)
        self._URI_APIv2d1 = BuildURI_APIv2d1(host, port)
        self.timeout = 60

    #
    # The following functions are public:
    # ==================================

    def GetSecurityConsoleStatus(self):
        """
        Returns the status of the Nexpose Security Console.
        If the appliance is unreachable, the status will be assumed to be 'unknown'.
        This functions returns a constant string as defined in dl_nexpose.NexposeStatus.
        """
        try:
            response = OpenWebRequest(self._URI_root, None, {}, self.timeout)
            return NexposeStatus.GetStatusFromURL(response.geturl())
        except:
            return NexposeStatus.UNKNOWN


class NexposeSession_APIv1d1(NexposeSessionBase):
    def __init__(self, host, port, username, password):
        NexposeSessionBase.__init__(self, host, port)
        self._URI_APIv1d1 = BuildURI_APIv1d1(host, port)
        self._login_request = BuildLoginRequest(username, password)
        self._session_id = None

    #
    # The following functions are internal:
    # ====================================

    def _Execute_APIv1d1(self, request):
        try:
            return Execute_APIv1d1(self._URI_APIv1d1, request, self.timeout)
        except Exception as ex:
            raise NexposeConnectionException("Unable to execute the request: {0}!".format(ex), ex)

    def _RequireAnOpenSession(self):
        if not self._session_id:
            raise SessionIsNotOpenException("Please open the session first!")

    #
    # The following functions are internal but can be used external:
    # =============================================================

    def ExecuteBasicXML(self, tag_name, initial_attributes=None):
        self._RequireAnOpenSession()
        request = BuildRequest(self._session_id, tag_name, initial_attributes)
        return self._Execute_APIv1d1(request)

    def ExecuteBasicWithElement(self, tag, extra_attributes, element_or_name, element_attributes=None):
        self._RequireAnOpenSession()
        request = BuildRequest(self._session_id, tag, extra_attributes)
        if element_or_name is None:
            pass
        else:
            if not isinstance(element_or_name, etree._Element):
                element_or_name = create_element(element_or_name, element_attributes)
            elif element_attributes is not None:
                raise ValueError('element_attributes should be None')
            request.append(element_or_name)
        return self._Execute_APIv1d1(request)

    def ExecuteBasicOnSite(self, tag, site_id):
        extra = {'site-id': site_id}
        return self.ExecuteBasicXML(tag, extra)

    def ExecuteBasicOnOptionalSite(self, tag, site_id):		
        extra = {'site-id': site_id} if site_id else None
        return self.ExecuteBasicXML(tag, extra)

    def ExecuteBasicOnDevice(self, tag, device_id):		
        extra = {'device-id': device_id}
        return self.ExecuteBasicXML(tag, extra)

    def ExecuteBasicOnScan(self, tag, scan_id):		
        extra = {'scan-id': scan_id}
        return self.ExecuteBasicXML(tag, extra)

    def ExecuteBasicOnUser(self, tag, user_id):
        extra = {'id': user_id}
        return self.ExecuteBasicXML(tag, extra)

    def ExecuteBasicOnAssetGroup(self, tag, assetgroup_id):
        extra = {'group-id': assetgroup_id}
        return self.ExecuteBasicXML(tag, extra)		

    def ExecuteBasicOnReport(self, tag, reportcfg_id):
        extra = {'report-id': reportcfg_id}
        return self.ExecuteBasicXML(tag, extra)

    def ExecuteBasicOnReportConfiguration(self, tag, reportcfg_id):
        extra = {'reportcfg-id': reportcfg_id}
        return self.ExecuteBasicXML(tag, extra)

    #
    # The following functions implement the Session Management API (without using the Request-prefix):
    # ============================================================

    def Open(self):
        """
        Opens a session to the nexpose appliance by logging in.
        This function with raise an exception on error or if the session is already open.
        """
        if self._session_id:
            raise SessionIsNotClosedException("Please close the session first!")
        try:
            response = self._Execute_APIv1d1(self._login_request)
        except NexposeConnectionException as ex:
            if isinstance(ex.inner_exception, etree.XMLSyntaxError):
                raise NexposeException("Unexpected error! Is the Nexpose appliance activated?")
            raise ex
        if response.tag == "LoginResponse":
            if response.attrib["success"] == "1":
                self._session_id = response.attrib["session-id"]
        if not self._session_id:
            raise NexposeFailureException("Login failure!")

    def Close(self):
        """
        Closes a session to the nexpose appliance by logging out.
        If the appliance is unreachable, the session will be assumed to be in a closed state.
        This function will do nothing if the session is in a closed state already.
        """
        if not self._session_id:
            return
        try:
            self.ExecuteBasicXML("LogoutRequest")
        finally:
            self._session_id = None

    #
    # The following functions implement the Site Management API:
    # =========================================================

    def RequestSiteListing(self):
        """
        Return all sites (summary) for the Scan Engine.
        This function will return a single SiteListingResponse XML object (API 1.1).
        """
        return self.ExecuteBasicXML("SiteListingRequest")

    def RequestSiteConfig(self, site_id):
        """
        Get the configuration of the specified site.
        This function will return a single SiteConfigResponse XML object (API 1.1).
        """
        return self.ExecuteBasicOnSite("SiteConfigRequest", site_id)

    def RequestSiteSave(self, xml_site_configuration):
        """
        Save the configuration of a site.
        To create a new site, specify -1 as id.
        This function will return a single SiteSaveResponse XML object (API 1.1).
        """
        return self.ExecuteBasicWithElement("SiteSaveRequest", {}, xml_site_configuration)

    def RequestSiteScan(self, site_id):
        """
        Start scanning the specified site.
        This function will return a single SiteScanResponse XML object (API 1.1).
        """
        return self.ExecuteBasicOnSite("SiteScanRequest", site_id)

    def RequestSiteDelete(self, site_id):
        """
        Delete the specified site and all associated scan data.
        A site cannot be deleted if an associated scan is running or paused.
        This function will return a single SiteDeleteResponse XML object (API 1.1).
        """
        return self.ExecuteBasicOnSite("SiteDeleteRequest", site_id)

    def RequestSiteScanHistory(self, site_id):
        """
        Return the scan history (summaries) of a site.
        This function will return a single SiteScanHistoryResponse XML object (API 1.1).
        """
        return self.ExecuteBasicOnSite("SiteScanHistoryRequest", site_id)

    #
    # The following functions implement the Asset Management API:
    # ==========================================================

    def RequestSiteDeviceListing(self, site_id=None):
        """
        Return all devices (assets) in a site.
        If site_id is None then all devices (asset summaries) for the Scan Engine, grouped by site-id are returned.
        This function will return a single SiteDeviceListingResponse XML object (API 1.1).
        """
        return self.ExecuteBasicOnOptionalSite("SiteDeviceListingRequest", site_id)

    def RequestDeviceDelete(self, device_id):
        """
        Delete a device (asset).
        This function will return a single DeviceDeleteResponse XML object (API 1.1).
        """
        return self.ExecuteBasicOnDevice("DeviceDeleteRequest", device_id)

    def RequestSiteDevicesScan(self):
        raise NotImplementedError() # TODO ?

    #
    # The following functions implement the Asset Group Management API:
    # =================================================================

    def RequestAssetGroupListing(self):
        """
        Return all asset groups the logged in user has access to.
        This function will return a single AssetGroupListingResponse XML object (API 1.1).
        """
        return self.ExecuteBasicXML("AssetGroupListingRequest")

    def RequestAssetGroupConfig(self, assetgroup_id):
        """
        Return the detailed configuration of a asset group.
        This function will return a single AssetGroupConfigResponse XML object (API 1.1).
        """
        return self.ExecuteBasicOnAssetGroup("AssetGroupConfigRequest", assetgroup_id)

    def RequestAssetGroupSave(self):
        raise NotImplementedError() # TODO

    def RequestAssetGroupDelete(self):
        raise NotImplementedError() # TODO

    #
    # The following functions implement the Scan Engine Management API:
    # ================================================================

    def RequestEngineListing(self):
        return self.ExecuteBasicXML("EngineListingRequest")

    def RequestEngineActivity(self, engine_id):
        raise NotImplementedError() # implemented in API 1.2

    #
    # The following functions implement the Scan API:
    # ==============================================

    def RequestScanActivity(self):
        """
        Return the scan activities (scan summaries) across all Scan Engines managed by the Security Console.
        This function will return a single ScanActivityResponse XML object (API 1.1).
        """
        return self.ExecuteBasicXML("ScanActivityRequest")

    def RequestScanPause(self, scan_id):
        """
        Pause a running scan.
        This function will return a single ScanPauseResponse XML object (API 1.1).
        """
        return self.ExecuteBasicOnScan("ScanPauseRequest", scan_id)

    def RequestScanResume(self, scan_id):
        """
        Resume a paused scan.
        This function will return a single ScanResumeResponse XML object (API 1.1).
        """
        return self.ExecuteBasicOnScan("ScanResumeRequest", scan_id)

    def RequestScanStop(self, scan_id):
        """
        Stop a paused or running scan.
        This function will return a single ScanStopResponse XML object (API 1.1).
        """
        return self.ExecuteBasicOnScan("ScanStopRequest", scan_id)

    def RequestScanStatus(self, scan_id):
        """
        Return the current status of a scan.
        This function will return a single ScanStatusResponse XML object (API 1.1).
        """
        return self.ExecuteBasicOnScan("ScanStatusRequest", scan_id)

    def RequestScanStatistics(self, scan_id):
        """
        Return the statistics (scan summary) of a scan.
        This function will return a single ScanStatisticsResponse XML object (API 1.1).
        """
        return self.ExecuteBasicOnScan("ScanStatisticsRequest", scan_id)

    #
    # The following functions implement the Vulnerability Management API:
    # ==================================================================

    def RequestVulnerabilityListing(self):
        raise NotImplementedError() # implemented in API 1.2

    def RequestVulnerabilityDetails(self, vulnerability_id):
        raise NotImplementedError() # implemented in API 1.2

    #
    # The following functions implement the Reporting API:
    # ===================================================

    def RequestReportTemplateListing(self):
        """
        Return a list of all report template summaries which are accessible by the user.
        This function will return a single ReportTemplateListingResponse XML object (API 1.1).
        """
        return self.ExecuteBasicXML("ReportTemplateListingRequest")

    def RequestReportTemplateConfig(self):
        raise NotImplementedError() # TODO

    def RequestReportTemplateSave(self):
        raise NotImplementedError() # TODO

    def RequestReportListing(self):
        """
        Return information (report configuration summary) about all report definitions,
        which are accessible by the user.
        This function will return a single ReportListingResponse XML object (API 1.1).
        """
        return self.ExecuteBasicXML("ReportListingRequest")

    def RequestReportHistory(self, reportconfiguration_id):
        """
        Return a history (report summary) of all reports generated with the specified report definition.
        This function will return a single ReportHistoryResponse XML object (API 1.1).
        """
        return self.ExecuteBasicOnReportConfiguration("ReportHistoryRequest", reportconfiguration_id)

    def RequestReportConfig(self, reportconfiguration_id):
        """
        Retreive the detailed report configuration (definition) of the specified report configuration.
        This function will return a single ReportConfigResponse XML object (API 1.1).
        """
        return self.ExecuteBasicOnReportConfiguration("ReportConfigRequest", reportconfiguration_id)

    def RequestReportSave(self):
        raise NotImplementedError() # TODO

    def RequestReportGenerate(self, reportconfiguration_id):
        """
        Generate a new report using the specified report configuration (definition).
        This function will return a single ReportGenerateResponse XML object (API 1.1).
        """
        # NOTE: for some reason whatsoever we have to specify a report-id and not a reportcfg-id...???
        return self.ExecuteBasicOnReport("ReportGenerateRequest", reportconfiguration_id)

    def RequestReportDelete(self, report_id, reportconfiguration_id=0):
        """
        Delete a report or report configuration (definition).
        If the reportconfiguration_id is specified, then the report_id argument is ignored.
        This function will return a single ReportDeleteResponse XML object (API 1.1).
        """
        if reportconfiguration_id:
            return self.ExecuteBasicOnReportConfiguration("ReportDeleteRequest", reportconfiguration_id)
        else:
            return self.ExecuteBasicOnReport("ReportDeleteRequest", report_id)

    def RequestReportAdhocGenerate(self, id):
        request = """
<AdhocReportConfig format="raw-xml-v2" template-id="audit-report">
<Filters>
<filter type="scan" id="{0}" />
</Filters>
</AdhocReportConfig>
"""
        return self.ExecuteBasicWithElement("ReportAdhocGenerateRequest", {}, as_xml(request.format(id)))
        raise NotImplementedError() # TODO
    
    #
    # The following functions implement the User Management API:
    # =========================================================

    def RequestUserListing(self):
        """
        Return information (user summary) about all user accounts.
        This function will return a single UserListingResponse XML object (API 1.1).
        """
        return self.ExecuteBasicXML("UserListingRequest")

    def RequestUserAuthenticatorListing(self):
        """
        Return all user authentication sources.
        This function will return a single UserAuthenticatorListingResponse XML object (API 1.1).
        """
        return self.ExecuteBasicXML("UserAuthenticatorListingRequest")

    def RequestUserConfig(self, user_id):
        """
        Return the detailed configuration of a user.
        This function will return a single UserConfigResponse XML object (API 1.1).
        """
        return self.ExecuteBasicOnUser("UserConfigRequest", user_id)

    def RequestUserSave(self, xml_user_configuration):
        """
        Save the configuration of a user.
        To create a new user, specify -1 as id.
        This function will return a single UserSaveResponse XML object (API 1.1).
        """
        return self.ExecuteBasicWithElement("UserSaveRequest", {}, xml_user_configuration)

    def RequestUserDelete(self, user_id):
        """
        Delete the specified user.
        This function will return a single UserDeleteResponse XML object (API 1.1).
        """
        return self.ExecuteBasicOnUser("UserDeleteRequest", user_id)

    #
    # The following functions implement the General Management and Diagnostics API:
    # ============================================================================

    def RequestConsoleCommand(self, xml_or_command):
        """
        Execute an arbitrary command on the Security Console.
        This function will return a single ConsoleCommandResponse XML object (API 1.1).
        """
        if isinstance(xml_or_command, etree._Element):
            xml_command = xml_or_command
        else:
            xml_command = create_element("Command")
            xml_command.text = xml_or_command
        return self.ExecuteBasicWithElement("ConsoleCommandRequest", {}, xml_command)

    def RequestSystemInformation(self):
        """
        Get system information about Security Console.
        This function will return a single SystemInformationResponse XML object (API 1.1).
        """
        return self.ExecuteBasicXML("SystemInformationRequest")

    def RequestRestart(self):
        """
        Restart the Security Console application.
        """
        return self.ExecuteBasicXML("RestartRequest")

    def RequestStartUpdate(self):
        """
        Start updating the Security Console application and restart if necessary.
        This function will return a single StartUpdateResponse XML object (API 1.1).
        """
        return self.ExecuteBasicXML("StartUpdateRequest")

    def RequestSendLog(self, xml_transport, keyid=0):
        """
        Send zipped (and PHP signed) diagnostic log files to a specified destination.
        This function will return a single SendLogResponse XML object (API 1.1).
        """
        attributes = {}
        if keyid:
            attributes['keyid'] = keyid
        return self.ExecuteBasicWithElement("SendLogRequest", attributes, xml_transport)


class NexposeSession_APIv1d2(NexposeSession_APIv1d1):
    def __init__(self, host, port, username, password):
        NexposeSession_APIv1d1.__init__(self, host, port, username, password)
        self._URI_APIv1d2 = BuildURI_APIv1d2(host, port)

    #
    # The following functions are internal:
    # ====================================

    def _Execute_APIv1d2(self, request):
        try:
            return Execute_APIv1d2(self._URI_APIv1d2, request, self.timeout)
        except Exception as ex:
            raise NexposeConnectionException("Unable to execute the request: {0}!".format(ex), ex)

    #
    # The following functions are internal but can be used external:
    # =============================================================

    def ExecuteAdvancedWithElement(self, tag, extra_attributes, element_or_name, element_attributes=None):
        self._RequireAnOpenSession()
        request = BuildRequest(self._session_id, tag, extra_attributes)
        if element_or_name is None:
            pass
        else:
            if not isinstance(element_or_name, etree._Element):
                element_or_name = create_element(element_or_name, element_attributes)
            elif element_attributes is not None:
                raise ValueError('element_attributes should be None')
            request.append(element_or_name)
        return self._Execute_APIv1d2(request)

    def ExecuteAdvanced(self, tag, extra_attributes=None):
        return self.ExecuteAdvancedWithElement(tag, extra_attributes, None)

    def ExecuteAdvancedAfterCallingAsXML(self, tag, nexpose_object, exclude_id):		
        return self.ExecuteAdvancedWithElement(tag, {}, nexpose_object.AsXML(exclude_id))

    def ExecuteAdvancedOnVulnerability(self, tag, vulnerability_id):		
        extra = {'vuln-id': vulnerability_id}
        return self.ExecuteAdvanced(tag, extra)

    def ExecuteAdvancedOnVulnerabilityException(self, tag, exception_id):		
        extra = {'exception-id': exception_id}
        return self.ExecuteAdvanced(tag, extra)

    def ExecuteAdvancedOnEngine(self, tag, engine_id, scope=None):		
        extra = {'engine-id': engine_id}
        if scope is not None:
            extra['scope'] = scope
        return self.ExecuteAdvanced(tag, extra)

    def ExecuteAdvancedOnRole(self, tag, role_name, role_scope):		
        return self.ExecuteAdvancedWithElement(tag, {}, "Role", {'name': role_name, 'scope': role_scope})

    def ExecuteAdvancedOnTicket(self, tag, ticket_id):
        return self.ExecuteAdvancedWithElement(tag, {}, "Ticket", {'id': ticket_id})

    #
    # The following functions implement the Discovery Connection Management API:
    # =========================================================================

    def RequestDiscoveryConnectionConnect(self):
        """
        Return all details of a specified DiscoveryConnection (by name and scope).
        This function will return a single DiscoveryConnectionConfigurationResponse XML object (API 1.2).
        """
        return self.ExecuteAdvancedOnDiscoveryConnection("DiscoveryConnectionConfigurationRequest", DiscoveryConnection_name, DiscoveryConnection_scope) # TODO

    def RequestDiscoveryConnectionCreate(self, discoveryconnection_configuration):
        """
        Create a new DiscoveryConnection.
        Both name and fullname must be unique.
        This function will return a single DiscoveryConnectionCreateResponse XML object (API 1.2).
        """
        return self.ExecuteAdvancedAfterCallingAsXML("DiscoveryConnectionCreateRequest", discoveryconnection_configuration, exclude_id=True) # TODO

    def RequestDiscoveryConnectionListing(self):
        """
        Return all DiscoveryConnections.
        This function will return a single DiscoveryConnectionListingResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("DiscoveryConnectionListingRequest") # TODO

    def RequestDiscoveryConnectionUpdate(self, discoveryconnection_configuration):
        """
        Update an existing DiscoveryConnection.
        Both name and fullname must be unique.
        This function will return a single DiscoveryConnectionUpdateResponse XML object (API 1.2).
        """
        return self.ExecuteAdvancedAfterCallingAsXML("DiscoveryConnectionUpdateRequest", discoveryconnection_configuration, exclude_id=False) # TODO

    def RequestDiscoveryConnectionDelete(self, DiscoveryConnection_name, DiscoveryConnection_scope):
        """
        Delete a specified DiscoveryConnection (by name and scope).
        This function will return a single DiscoveryConnectionDeleteResponse XML object (API 1.2).
        """
        return self.ExecuteAdvancedOnDiscoveryConnection("DiscoveryConnectionDeleteRequest", DiscoveryConnection_name, DiscoveryConnection_scope) # TODO

    #
    # The following functions implement the Scan Engine Management API:
    # ================================================================

    def RequestEngineSave(self, xml_engine_configuration):
        """
        This function will return a single EngineSaveResponse XML object (API 1.2).
        """
        return self.ExecuteAdvancedWithElement("EngineSaveRequest", {}, xml_engine_configuration)

    def RequestEngineListing(self):
        """
        Return all available scan engines.
        This function will return a single EngineListingResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("EngineListingRequest")

    def RequestEngineConfig(self, engine_id):
        """
        Return the configuration of a scan engine.
        This function will return a single EngineConfigResponse XML object (API 1.2).
        """
        return self.ExecuteAdvancedOnEngine("EngineConfigRequest", engine_id)

    def RequestEngineActivity(self, engine_id):
        """
        Return the scan activities (scan summaries) of the specified scan engine.
        This function will return a single EngineActivityResponse XML object (API 1.2).
        """
        response = self.ExecuteAdvancedOnEngine("EngineActivityRequest", engine_id)
        return response

    def RequestEngineDelete(self, engine_id, scope):
        """
        Delete the specified engine (by id and scope).
        This function will return a single EngineDeleteResponse XML object (API 1.2).
        """
        return self.ExecuteAdvancedOnEngine("EngineDeleteRequest", engine_id, scope)

    #
    # The following functions implement the Ticket Management API:
    # ===========================================================

    def RequestTicketCreate(self, xml_ticket_details):
        """
        This function will return a single TicketCreateResponse XML object (API 1.2).
        """
        return self.ExecuteAdvancedWithElement("TicketCreateRequest", {}, xml_ticket_details)

    def RequestTicketListing(self):
        """
        This function will return a single TicketListingResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("TicketListingRequest")

    def RequestTicketDetails(self, ticket_id):
        """
        This function will return a single TicketDetailsResponse XML object (API 1.2).
        """
        return self.ExecuteAdvancedOnTicket("TicketDetailsRequest", ticket_id)

    def RequestTicketDelete(self, ticket_id):
        """
        This function will return a single TicketDeleteResponse XML object (API 1.2).
        """
        return self.ExecuteAdvancedOnTicket("TicketDeleteRequest", ticket_id)

    #
    # The following functions implement the Multi-Tenant User Management API:
    # ======================================================================

    def RequestMultiTenantUserCreate(self):
        """
        This function will return a single MultiTenantUserCreateResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("MultiTenantUserCreateRequest") # TODO

    def RequestMultiTenantUserListing(self):
        """
        This function will return a single MultiTenantUserListingResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("MultiTenantUserListingRequest") # TODO

    def RequestMultiTenantUserUpdate(self):
        """
        This function will return a single MultiTenantUserUpdateResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("MultiTenantUserUpdateRequest") # TODO

    def RequestMultiTenantUserConfig(self):
        """
        This function will return a single MultiTenantUserConfigResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("MultiTenantUserConfigRequest") # TODO

    def RequestMultiTenantUserDelete(self):
        """
        This function will return a single MultiTenantUserDeleteResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("MultiTenantUserDeleteRequest") # TODO

    #
    # The following functions implement the Silo Profile Management API:
    # =================================================================

    def RequestSiloProfileCreate(self):
        """
        This function will return a single SiloProfileCreateResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("SiloProfileCreateRequest") # TODO

    def RequestSiloProfileListing(self):
        """
        This function will return a single SiloProfileListingResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("SiloProfileListingRequest") # TODO

    def RequestSiloProfileUpdate(self):
        """
        This function will return a single SiloProfileUpdateResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("SiloProfileUpdateRequest") # TODO

    def RequestSiloProfileConfig(self):
        """
        This function will return a single SiloProfileConfigResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("SiloProfileConfigRequest") # TODO

    def RequestSiloProfileDelete(self):
        """
        This function will return a single SiloProfileDeleteResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("SiloProfileDeleteRequest") # TODO

    #
    # The following functions implement the Silo Management API:
    # =========================================================

    def RequestSiloCreate(self):
        """
        This function will return a single SiloCreateResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("SiloCreateRequest") # TODO

    def RequestSiloListing(self):
        """
        This function will return a single SiloListingResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("SiloListingRequest") # TODO

    def RequestSiloConfig(self):
        """
        This function will return a single SiloConfigResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("SiloConfigRequest") # TODO

    def RequestSiloUpdate(self):
        """
        This function will return a single SiloUpdateResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("SiloUpdateRequest") # TODO

    def RequestSiloDelete(self):
        """
        This function will return a single SiloDeleteResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("SiloDeleteRequest") # TODO

    #
    # The following functions implement the Role Management API:
    # =========================================================

    def RequestRoleCreate(self, role_details):
        """
        Create a new role.
        Both name and fullname must be unique.
        This function will return a single RoleCreateResponse XML object (API 1.2).
        """
        return self.ExecuteAdvancedAfterCallingAsXML("RoleCreateRequest", role_details, exclude_id=True)

    def RequestRoleListing(self):
        """
        Return all roles.
        This function will return a single RoleListingResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("RoleListingRequest")

    def RequestRoleDetails(self, role_name, role_scope):
        """
        Return all details of a specified role (by name and scope).
        This function will return a single RoleDetailsResponse XML object (API 1.2).
        """
        return self.ExecuteAdvancedOnRole("RoleDetailsRequest", role_name, role_scope)

    def RequestRoleUpdate(self, role_details):
        """
        Update an existing role.
        Both name and fullname must be unique.
        This function will return a single RoleUpdateResponse XML object (API 1.2).
        """
        return self.ExecuteAdvancedAfterCallingAsXML("RoleUpdateRequest", role_details, exclude_id=False)

    def RequestRoleDelete(self, role_name, role_scope):
        """
        Delete a specified role (by name and scope).
        This function will return a single RoleDeleteResponse XML object (API 1.2).
        """
        return self.ExecuteAdvancedOnRole("RoleDeleteRequest", role_name, role_scope)

    #
    # The following functions implement the Scan Engine Pool Management API:
    # =====================================================================

    def RequestEnginePoolCreate(self):
        """
        This function will return a single EnginePoolCreateResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("EnginePoolCreateRequest") # TODO

    def RequestEnginePoolListing(self):
        """
        This function will return a single EnginePoolListingResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("EnginePoolListingRequest") # TODO

    def RequestEnginePoolDetails(self):
        """
        This function will return a single EnginePoolDetailsResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("EnginePoolDetailsRequest") # TODO

    def RequestEnginePoolUpdate(self):
        """
        This function will return a single EnginePoolUpdateResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("EnginePoolUpdateRequest") # TODO

    def RequestEnginePoolDelete(self):
        """
        This function will return a single EnginePoolDeleteResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("EnginePoolDeleteRequest") # TODO

    #
    # The following functions implement the Vulnerability Management API:
    # ==================================================================

    def RequestVulnerabilityListing(self):
        """
        Return all vulnerabilities that can be checked.
        This function will return a single VulnerabilityListingResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("VulnerabilityListingRequest")

    def RequestVulnerabilityDetails(self, vulnerability_id):
        """
        Return detailed information about a specified vulnerability.
        This function will return a single VulnerabilityDetailsResponse XML object (API 1.2).
        """
        return self.ExecuteAdvancedOnVulnerability("VulnerabilityDetailsRequest", vulnerability_id)

    #
    # The following functions implement the Vulnerability Exception Management API:
    # ============================================================================

    def RequestPendingVulnExceptionCount(self):
        """
        This function will return a single PendingVulnExceptionsCountResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("PendingVulnExceptionsCountRequest")

    def RequestVulnerabilityExceptionListing(self):
        """
        This function will return a single VulnerabilityExceptionListingResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("VulnerabilityExceptionListingRequest")

    def RequestVulnerabilityExceptionCreate(self):
        """
        This function will return a single VulnerabilityExceptionCreateResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("VulnerabilityExceptionCreateRequest") # TODO

    def RequestVulnerabilityExceptionResubmit(self, exception_id, reason, comment):
        """
        This function will return a single VulnerabilityExceptionResubmitResponse XML object (API 1.2).
        """
        xml_comment = create_element("comment")
        xml_comment.text = comment
        attributes = {'exception-id': exception_id}
        attributes['reason'] = reason
        return self.ExecuteAdvancedWithElement("VulnerabilityExceptionResubmitRequest", attributes, xml_comment)

    def RequestVulnerabilityExceptionRecall(self, exception_id):
        """
        Recalls the specified vulnerability exception.
        This function will return a single VulnerabilityExceptionDeleteResponse XML object (API 1.2).
        """
        return self.ExecuteAdvancedOnVulnerabilityException("VulnerabilityExceptionRecallRequest", exception_id)

    def RequestVulnerabilityExceptionApprove(self, exception_id, comment):
        """
        This function will return a single VulnerabilityExceptionApproveResponse XML object (API 1.2).
        """
        xml_comment = create_element("comment")
        xml_comment.text = comment
        return self.ExecuteAdvancedWithElement("VulnerabilityExceptionApproveRequest", {'exception-id': exception_id}, xml_comment)

    def RequestVulnerabilityExceptionReject(self, exception_id, comment):
        """
        This function will return a single VulnerabilityExceptionRejectResponse XML object (API 1.2).
        """
        xml_comment = create_element("comment")
        xml_comment.text = comment
        return self.ExecuteAdvancedWithElement("VulnerabilityExceptionRejectRequest", {'exception-id': exception_id}, xml_comment)

    def RequestVulnerabilityExceptionDelete(self, exception_id):
        """
        Delete the specified vulnerability exception.
        This function will return a single VulnerabilityExceptionDeleteResponse XML object (API 1.2).
        """
        return self.ExecuteAdvancedOnVulnerabilityException("VulnerabilityExceptionDeleteRequest", exception_id)

    def RequestVulnerabilityExceptionUpdateComment(self):
        """
        This function will return a single VulnerabilityExceptionUpdateCommentResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("VulnerabilityExceptionUpdateCommentRequest") # TODO

    def RequestVulnerabilityExceptionUpdateExpirationDate(self):
        """
        This function will return a single VulnerabilityExceptionUpdateExpirationDateResponse XML object (API 1.2).
        """
        return self.ExecuteAdvanced("VulnerabilityExceptionUpdateExpirationDateRequest") # TODO


class NexposeSession(NexposeSession_APIv1d2):
    @staticmethod
    def CreateAndOpen(host, port, username, password):
        session = NexposeSession.Create(host, port, username, password)
        session.Open()
        return session

    @staticmethod
    def Create(host, port, username, password):
        return NexposeSession(host, port, username, password)

    def __init__(self, host, port, username, password):
        NexposeSession_APIv1d2.__init__(self, host, port, username, password)
        self.session_username = username

    #
    # The following functions are internal:
    # ====================================

    def _ExecuteSave(self, save_function, object_to_save, expected_tag, id_attribute):
        response = self.VerifySuccess(save_function(object_to_save.AsXML(exclude_id=False)))
        if response.tag != expected_tag:
            raise ValueError("response.tag ('{0}') doesn't equal expected_tag ('{0}')".format(response.tag, expected_tag))
        id = int(get_attribute(response, id_attribute))
        if id <= 0:
            raise ValueError('The returned id should be a positive integer instead of {0}'.format(id))
        object_to_save.id = id
        return id

    def ExecutePagedGet_vXX(self, sub_url, api_uri):
        self._RequireAnOpenSession()
        return ExecutePagedGet_JSON(self._session_id, api_uri, sub_url, self.timeout)

    def ExecutePagedGet_v20(self, sub_url):
        return self.ExecutePagedGet_vXX(sub_url, self._URI_APIv2d0)

    def ExecutePagedGet_v21(self, sub_url):
        return self.ExecutePagedGet_vXX(sub_url, self._URI_APIv2d1)

    def ExecutePost(self, sub_url, post_data):
        self._RequireAnOpenSession()
        return ExecutePost_JSON(self._session_id, self._URI_APIv2d0, sub_url, self.timeout, post_data)

    def ExecutePut(self, sub_url, post_data):
        self._RequireAnOpenSession()
        return ExecutePut_JSON(self._session_id, self._URI_APIv2d0, sub_url, self.timeout, post_data)

    def ExecuteDelete(self, sub_url):
        self._RequireAnOpenSession()
        return ExecuteDelete_JSON(self._session_id, self._URI_APIv2d0, sub_url, self.timeout)

    def ExecuteFormPost(self, sub_url, post_data):
        self._RequireAnOpenSession()
        return ExecuteWithPostData_FORM(self._session_id, self._URI_root, sub_url, self.timeout, post_data)

    def ExecuteGet(self, sub_url, options=None):
        self._RequireAnOpenSession()
        return as_xml(ExecuteGet_JSON(self._session_id, self._URI_root, sub_url, self.timeout, options))

    def ExecuteMaintenanceCommand(self, target_task, command, extra_parameters):
        parameters = dict(extra_parameters)
        parameters['cmd'] = command
        parameters['targetTask'] = target_task
        result = self.ExecuteFormPost('admin/global/maintenance/maintCmd.txml', parameters)
        return _HasSucceeded(result)

    def ExecuteMaintenanceCommandAndRestartOnSuccess(self, target_task, command, extra_parameters):
        result = self.ExecuteMaintenanceCommand(target_task, command, extra_parameters)
        if result:
            return self.RestartSecurityConsoleForMaintenance()
        return False

    def ExecuteGetRecords(self, sub_url, filter_data):
        if isinstance(filter_data, AssetFilter):
            filter_data = filter_data.as_json()

        filter_data['startIndex'] = 0
        filter_data['results'] = 500
        raw_data = self.ExecuteFormPost(sub_url, filter_data)
        json_data = json.loads(raw_data)
        record_count = json_data.get('totalRecords', 0)
        if not record_count:
            return []

        records = json_data.get('records', None)
        if not records:
            return []

        while len(records) < record_count:
            filter_data['startIndex'] = len(records)
            json_data = json.loads(self.ExecuteFormPost(sub_url, filter_data))
            records.extend(json_data.get('records', None)) # adding None to a list will crash, this is good :-)

        return records

    def ExecuteGetDynTable(self, sub_url, post_data=None):
        self._RequireAnOpenSession()
        if post_data == None:
            # TODO: refactor the name ExecuteGet_JSON as a returned DynTable is in xml
            dyntable = as_xml(ExecuteGet_JSON(self._session_id, self._URI_root, sub_url, self.timeout))
            if dyntable.tag != 'DynTable':
                raise Exception("The expected DynTable definition was not found")
            columns = list()
            for column in get_children_of(dyntable, 'MetaData'):
                if column.tag != 'Column':
                    raise Exception("The DynTable column definition contains an invalid tag")
                name = get_attribute(column, 'name')
                type = get_attribute(column, 'type')
                if not (name and type):
                    raise Exception("The DynTable contains an invalid column definition")
                columns.append(DynTableColumn(name, type))
            if not columns:
                raise Exception("The DynTable contains no column definition")
            all_data = list()
            for row in get_children_of(dyntable, "Data"):
                if row.tag != "tr":
                    raise Exception("The DynTable data row definition contains an invalid tag")
                data = dict()
                for index, column in enumerate(row.getchildren()):
                    if column.tag != "td":
                        raise Exception("The DynTable data row contains an invalid tag")
                    column_definition = columns[index]
                    data[column_definition.name] = column.text
                all_data.append(data)
            return columns, all_data
        return (), list()

    def _RequireInstanceOf(self, object_to_test, required_class):
        if not isinstance(object_to_test, required_class):
            raise ValueError('input must be a ' + required_class.__name__ + ' instance')
    
    def _GetStreamReader(self, sub_url):
        headers = CreateHeadersWithSessionCookie(self._session_id)
        response = OpenWebRequest(self._URI_root + sub_url, None, headers, self.timeout)
        metadata = response.info()
        return response

    #
    # The following functions are internal but can be used external:
    # =============================================================

    def VerifySuccess(self, response):
        """
        If the response indicates a failure, the error message is extracted and
        a NexposeFailureException is raised. Otherwise the response is returned.
        """
        if response.tag == 'Failure':
            message = get_content_of(response, 'Exception/Message')
            if message is None:
                message = get_content_of(response, 'Message')
            raise NexposeFailureException(message)
        if get_attribute(response, 'success') == '0':
            message = get_content_of(response, 'Failure/message')
            if message is None:
                message = get_content_of(response, 'Failure/Exception/message')
            if message is None:
                message = get_content_of(response, 'Error') # Used by unofficial API's (for example: TestAdminCredentialsResult)
            raise NexposeFailureException(message)
        return response

    #
    # The following functions implement the Site Management API:
    # =========================================================

    def GetSiteSummaries(self):
        """
        Return all site summaries for the Scan Engine.
        This function will generate dl_nexpose.SiteSummary objects using a SiteListingRequest.
        """
        requestor = self.RequestSiteListing
        object_creator = SiteSummary.CreateFromXML
        return request_and_create_objects_from_xml(requestor, 'SiteSummary', object_creator)

    def GetSiteConfiguration(self, site_or_id):
        """"
        Get the configuration of the specified site.
        This function will return a single dl_nexpose.SiteConfiguration object using a SiteConfigRequest.
        Raises an exception on failure.
        """
        if isinstance(site_or_id, SiteBase): site_or_id = site_or_id.id
        response = self.VerifySuccess(self.RequestSiteConfig(site_or_id))
        element = get_element(response, 'Site')
        return SiteConfiguration.CreateFromXML(element)

    def SaveSiteConfiguration(self, site_configuration):
        """
        Save the configuration of a site and return the id of the saved site.
        If successful, the id will also have been updated in the provided dl_nexpose.SiteConfiguration object.
        To create a new site, specify -1 as id.
        """
        self._RequireInstanceOf(site_configuration, SiteConfiguration)
        return self._ExecuteSave(self.RequestSiteSave, site_configuration, 'SiteSaveResponse', 'site-id') # TODO: if this turns out to be 'id' instead of 'site-id' than remove the parameter from the function

    def StartSiteScan(self, site_or_id):
        """"
        Start scanning the specified site.
        This function will return a tuple containing the Scan ID and the Engine ID using a SiteScanRequest.
        Raises an exception on failure.
        """
        if isinstance(site_or_id, SiteBase): site_or_id = site_or_id.id
        response = self.VerifySuccess(self.RequestSiteScan(site_or_id))
        element_scan = get_element(response, 'Scan')
        return int(get_attribute(element_scan, 'scan-id')), int(get_attribute(element_scan, 'engine-id'))

    def DeleteSite(self, site_or_id):
        """
        Delete the specified site and all associated scan data.
        A site cannot be deleted if an associated scan is running or paused.
        Raises an exception on failure.
        """
        if isinstance(site_or_id, SiteBase): site_or_id = site_or_id.id
        self.VerifySuccess(self.RequestSiteDelete(site_or_id))

    def GetSiteScanSummaries(self, site_or_id):
        """
        Return all scan summaries (history) of a site.
        This function will generate dl_nexpose.ScanSummary objects using a SiteScanHistoryRequest.
        """
        if isinstance(site_or_id, SiteBase): site_or_id = site_or_id.id
        requestor = lambda: self.RequestSiteScanHistory(site_or_id)
        object_creator = ScanSummary.CreateFromXML
        return request_and_create_objects_from_xml(requestor, 'ScanSummary', object_creator)

    #
    # The following functions implement the Asset Management API:
    # ==========================================================

    def GetAssetSummaries(self):
        """
        Return all assets (summary) for the Scan Engine, grouped by site-id.
        This function will generate dl_nexpose.AssetSummary objects using a SiteDeviceListingRequest.
        """
        return self.GetSiteAssetSummaries(None)

    def GetSiteAssetSummaries(self, site_or_id):
        """
        Return all assets (summary) in a site.
        If site_or_id is None then all assets for the Scan Engine, grouped by site-id are returned.
        This function will generate dl_nexpose.AssetSummary objects using a SiteDeviceListingRequest.
        """
        if isinstance(site_or_id, SiteBase): site_or_id = site_or_id.id
        requestor = lambda: self.RequestSiteDeviceListing(site_or_id)
        object_creator = lambda xml_data: AssetSummary.CreateFromXML(xml_data, site_id=xml_data.getparent().attrib['site-id'])
        return request_and_create_objects_from_xml(requestor, 'SiteDevices/device', object_creator)

    def GetAssetDetails(self, asset_or_id):
        """
        Get detailed information of an asset.
        Requires the 2.1 API!
        """
        if isinstance(asset_or_id, AssetBase): asset_or_id = asset_or_id.id
        sub_url = APIURL_ASSETS.format(asset_or_id)
        json_dict = self.ExecutePagedGet_v21(sub_url)
        load_urls(json_dict, self.ExecutePagedGet_v21)
        return AssetDetails.CreateFromJSON(json_dict)

    def DeleteAsset(self, asset_or_id):
        """
        Delete an asset (device).
        Raises an exception on failure.
        """
        if isinstance(asset_or_id, AssetBase): asset_or_id = asset_or_id.id
        self.VerifySuccess(self.RequestDeviceDelete(asset_or_id))

    def GetFilteredAssets(self, filter_or_criteria_or_criterion):
        """
        Generate dl_nexpose.FilteredAsset objects.
        The assests are filtered by a dl_nexpose.AssetFilter, -.Criteria or -.Criterion object.
        Exceptions are raised as-is.
        """
        if not isinstance(filter_or_criteria_or_criterion, AssetFilter):
            filter_or_criteria_or_criterion = AssetFilter(filter_or_criteria_or_criterion)
        result = self.ExecuteGetRecords('data/asset/filterAssets', filter_or_criteria_or_criterion)
        return imap(FilteredAsset.CreateFromJSON, result)

    #
    # The following functions implement the Asset Group Management API:
    # =================================================================

    def GetAssetGroupSummaries(self):
        """
        Return all asset groups the logged in user has access to.
        This function will generate dl_nexpose.AssetGroup objects using a AssetGroupListingRequest.
        """
        requestor = self.RequestAssetGroupListing
        object_creator = AssetGroupSummary.CreateFromXML
        return request_and_create_objects_from_xml(requestor, 'AssetGroupSummary', object_creator)

    def GetAssetGroupConfiguration(self, assetgroup_or_id):
        """
        Return the detailed configuration of an asset group.
        This function will return a dl_nexpose.AssetGroupConfiguration object using a AssetGroupConfigRequest.
        """
        if isinstance(assetgroup_or_id, AssetGroupSummary): assetgroup_or_id = assetgroup_or_id.id
        response = self.VerifySuccess(self.RequestAssetGroupConfig(assetgroup_or_id))
        xml_data = get_element(response, 'AssetGroup')		
        asset_group = AssetGroupConfiguration.CreateFromXML(xml_data)

        # fetch the description (with newline support) using the 2.0 API
        try:
            sub_url = APIURL_ASSETGROUPS.format(asset_group.id)
            json_dict = self.ExecutePagedGet_v20(sub_url)
            asset_group.description = json_dict.get['description']
            if asset_group.description is None:
                asset_group.description = asset_group.short_description
        except:
            pass

        return asset_group

    #
    # The following functions implement the Scan API:
    # ==============================================

    def GetActiveScanSummaries(self):
        """
        Return the scan summaries of all running scans managed by the Security Console.
        This function will generate dl_nexpose.ScanSummary objects using a ScanActivityRequest.
        """
        requestor = lambda: self.RequestScanActivity()
        object_creator = ScanSummary.CreateFromXML
        return request_and_create_objects_from_xml(requestor, 'ScanSummary', object_creator)

    def PauseScan(self, scan_or_id):
        """
        Pause a running scan using a ScanPauseRequest.
        Raises an exception on failure.
        """
        if isinstance(scan_or_id, ScanSummary):
            scan_or_id = scan_or_id.id
        self.VerifySuccess(self.RequestScanPause(scan_or_id))

    def ResumeScan(self, scan_or_id):
        """
        Resume a paused scan using a ScanResumeRequest.
        Raises an exception on failure.
        """
        if isinstance(scan_or_id, ScanSummary):
            scan_or_id = scan_or_id.id
        self.VerifySuccess(self.RequestScanResume(scan_or_id))

    def StopScan(self, scan_or_id):
        """
        Stop a paused or running scan using a ScanStopRequest.
        Raises an exception on failure.
        """
        if isinstance(scan_or_id, ScanSummary):
            scan_or_id = scan_or_id.id
        self.VerifySuccess(self.RequestScanStop(scan_or_id))

    def GetScanStatus(self, scan_or_id):
        """
        Returns a tuple containing the Engine ID and the status of a scan using a ScanStatusRequest.
        Raises an exception on failure.
        """
        if isinstance(scan_or_id, ScanSummary):
            scan_or_id = scan_or_id.id
        response = self.VerifySuccess(self.RequestScanStatus(scan_or_id))
        return int(get_attribute(response, 'engine-id')), get_attribute(response, 'status')

    def GetScanSummary(self, scan_or_id):
        """
        Return the (up-to-date) scan summary (statistics) of a scan.
        This function will return a dl_nexpose.ScanSummary object using a ScanStatisticsRequest.
        Raises an exception on failure.
        """
        if isinstance(scan_or_id, ScanSummary):
            scan_or_id = scan_or_id.id
        response = self.VerifySuccess(self.RequestScanStatistics(scan_or_id))
        element = get_element(response, 'ScanSummary')
        return ScanSummary.CreateFromXML(element)

    def GetScannedAssets(self, scan_or_id):
        """
        TODO
        Return a list of nodes (a node is an asset linked with a specific scan).
        This function will return a dl_nexpose.NodeSummary object using a .
        Raises an exception on failure.
        """
        xxx
        if isinstance(scan_or_id, ScanSummary):
            scan_or_id = scan_or_id.id
        response = self.VerifySuccess(self.RequestScanStatistics(scan_or_id))
        element = get_element(response, 'ScanSummary')
        return ScanSummary.CreateFromXML(element)

    def GetScanLogStreamReader(self, scan_or_id):
        """
        Get a reader that can be used to download a scan log stored on the security console.
        This function will return a file-like object. (see urllib2.urlopen)
        NOTE: no official documentation exists except the Rapid7 Nexpose Ruby API.
        """
        if isinstance(scan_or_id, ScanSummary):
            scan_or_id = scan_or_id.id
        sub_url = 'data/scan/log?scan-id={0}'.format(scan_or_id)
        return self._GetStreamReader(sub_url)

    def DownloadScanLog(self, scan_or_id, callback_function=None, block_size=DEFAULT_BLOCK_SIZE):
        """
        Download a scan log.
        The callback_function has the following signature:
          callback_function(already_downloaded_data, new_data)
        This function will return a bytearray object containing the zipped scan log.
        NOTE: no official documentation exists except the Rapid7 Nexpose Ruby API.
        """
        reader = self.GetScanLogStreamReader(scan_or_id)
        return DownloadFromStreamReader(reader, callback_function, block_size)

    #
    # The following functions implement the User Management API:
    # =========================================================

    def GetUserSummaries(self):
        """
        Return information (user summary) about all user accounts.
        This function will generate dl_nexpose.UserSummary objects using a UserListingRequest.
        """
        requestor = lambda: self.RequestUserListing()
        object_creator = UserSummary.CreateFromXML
        return request_and_create_objects_from_xml(requestor, 'UserSummary', object_creator)

    def GetUserAuthenticatorSummaries(self):
        """
        Return information (user authenticator summary) about all user authenticators.
        This function will generate dl_nexpose.UserAuthenticatorSummary objects using a UserAuthenticatorListingRequest.
        """
        requestor = lambda: self.RequestUserAuthenticatorListing()
        object_creator = UserAuthenticatorSummary.CreateFromXML
        return request_and_create_objects_from_xml(requestor, 'AuthenticatorSummary', object_creator)

    def GetUserConfiguration(self, user_or_id):
        """
        Return the detailed configuration of a user.
        This function will return a dl_nexpose.UserConfiguration object using a UserConfigRequest.
        """
        if isinstance(user_or_id, UserBase):
            user_or_id = user_or_id.id
        response = self.VerifySuccess(self.RequestUserConfig(user_or_id))
        xml_data = get_element(response, 'UserConfig')
        config = UserConfiguration.CreateFromXML(xml_data)

        # Because of a bug in the API not all expected information is returned in the UserConfiguration object
        # Retrieve the information using an undocumented method
        xml_data = self.ExecuteGet('ajax/user_config.txml', {'userid': user_or_id})
        config.has_access_to_all_sites = get_attribute(xml_data, 'allSites') == 'true'
        config.has_access_to_all_assetgroups = get_attribute(xml_data, 'allGroups') == 'true'
        config.accessible_sites = [int(get_attribute(xml_site, 'id')) for xml_site in xml_data.findall('Sites/site')]
        config.accessible_assetgroups = [int(get_attribute(xml_assetgroup, 'id')) for xml_assetgroup in xml_data.findall('Groups/group')] # Groups/group or Groups/Group

        return config

    def SaveUserConfiguration(self, user_configuration):
        """
        Save the configuration of a user and return the id of the saved user.
        To create a new user, specify -1 as id.
        If successful, the id will also have been updated in the provided dl_nexpose.UserConfiguration object.
        Raises an exception on failure.
        """
        self._RequireInstanceOf(user_configuration, UserConfiguration)
        return self._ExecuteSave(self.RequestUserSave, user_configuration, 'UserSaveResponse', 'id')

    def DeleteUser(self, user_or_id):
        """
        Delete the specified user.
        Raises an exception on failure.
        """
        if isinstance(user_or_id, UserBase):
            user_or_id = user_or_id.id
        self.VerifySuccess(self.RequestUserDelete(user_or_id))

    #
    # The following functions implement the General Management and Diagnostics API:
    # ============================================================================

    def RestartSecurityConsole(self):
        """
        Restart the Security Console application.
        Raises an exception on failure.
        """
        self.VerifySuccess(self.RequestRestart())

    def StartSecurityConsoleUpdate(self):
        """
        Start updating the Security Console application and restart if necessary.
        Raises an exception on failure.
        """		
        self.VerifySuccess(self.RequestStartUpdate())

    #
    # The following functions implement the Maintenance API (not documented):
    # =====================================================

    def StartDatabaseMaintenance(self, clean_up=False, compress=False, reindex=False):
        """
        Restart the security console and run a database maintenance task.
        This function will return a boolean indicating if the request has been received.
        NOTE: no official documentation exists except the Rapid7 Nexpose Ruby API.
        """
        if not (clean_up or compress or reindex):
            return False
        parameters = {}
        parameters['cleanup'] = 1 if clean_up else 0
        parameters['compress'] = 1 if compress else 0
        parameters['reindex'] = 1 if reindex else 0
        return self.ExecuteMaintenanceCommandAndRestartOnSuccess('dbMaintenance', 'startMaintenance', parameters)

    def RestartSecurityConsoleForMaintenance(self, cancel_all_tasks=False):
        """
        Restart the security console and execute maintenance tasks (or cancel them).
        This function will return a boolean indicating success.
        NOTE: no official documentation exists except the Rapid7 Nexpose Ruby API.
        """
        parameters = {'cancelAllTasks': cancel_all_tasks}
        return self.ExecuteMaintenanceCommand('maintModeHandler', 'restartServer', parameters)

    #
    # The following functions implement the Discovery Connection Management API:
    # =========================================================================

    def SaveDiscoveryConnection(self, discoveryconnection_configuration):
        """
        Save a DiscoveryConnection (requires a dl_nexpose.DiscoveryConnectionSummary object) and return the id of the saved DiscoveryConnection.
        If successful, the id will also have been updated in the provided dl_nexpose.DiscoveryConnectionConfiguration object.
        To create a new DiscoveryConnection, specify -1 as id.
        Both name and fullname must be unique.
        Raises an exception on failure.
        """
        self._RequireInstanceOf(discoveryconnection_configuration, DiscoveryConnectionConfiguration)
        if discoveryconnection_configuration.id == -1:
            response = self.VerifySuccess(self.RequestDiscoveryConnectionCreate(discoveryconnection_configuration))
            id = int(get_attribute(response, 'id')) if response.tag == 'DiscoveryConnectionCreateResponse' else 0
            if id:
                discoveryconnection_configuration.id = id
        else:
            response = self.VerifySuccess(self.RequestDiscoveryConnectionUpdate(discoveryconnection_configuration))
        return discoveryconnection_configuration.id

    def GetDiscoveryConnectionSummaries(self):
        """
        Return all DiscoveryConnections.
        This function will generate dl_nexpose.DiscoveryConnectionSummary objects using a DiscoveryConnectionListingRequest.
        """
        requestor = lambda: self.RequestDiscoveryConnectionListing()
        object_creator = DiscoveryConnectionSummary.CreateFromXML
        return request_and_create_objects_from_xml(requestor, 'DiscoveryConnectionSummary', object_creator)

    def GetDiscoveryConnectionConfiguration(self, discoveryconnection_summary):
        """
        Return all details of a specified DiscoveryConnection (requires a dl_nexpose.DiscoveryConnectionSummary object).
        This function will return a dl_nexpose.DiscoveryConnectionConfiguration object using a DiscoveryConnectionConfigurationRequest.
        Raises an exception on failure.
        """
        self._RequireInstanceOf(discoveryconnection_summary, DiscoveryConnectionSummary)
        response = self.VerifySuccess(self.RequestDiscoveryConnectionConfiguration(discoveryconnection_summary.name, discoveryconnection_summary.scope))
        xml_data = get_element(response, 'DiscoveryConnection')
        return DiscoveryConnectionConfiguration.CreateFromXML(xml_data)

    def DeleteDiscoveryConnection(self, discoveryconnection_summary):
        """
        Delete a specified DiscoveryConnection (requires a dl_nexpose.DiscoveryConnectionSummary object).
        Raises an exception on failure.
        """
        self._RequireInstanceOf(discoveryconnection_summary, DiscoveryConnectionSummary)
        self.VerifySuccess(self.RequestDiscoveryConnectionDelete(discoveryconnection_summary.name, discoveryconnection_summary.scope))

    #
    # The following functions implement the Scan Engine Management API:
    # ================================================================

    def SaveEngineConfiguration(self, engine_configuration):
        """
        Save the configuration of a scan engine and return the id of the saved scan engine.
        If successful, the id will also have been updated in the provided dl_nexpose.EngineConfiguration object.
        To create a new scan engine, specify -1 as id.
        Raises an exception on failure.
        """
        self._RequireInstanceOf(engine_configuration, EngineConfiguration)
        return self._ExecuteSave(self.RequestEngineSave, engine_configuration, 'EngineSaveResponse', 'id')

    def GetEngineSummaries(self):
        """
        Return all available scan engines.
        This function will generate dl_nexpose.EngineSummary objects using an EngineListingRequest.
        """
        requestor = lambda: self.RequestEngineListing()
        object_creator = EngineSummary.CreateFromXML
        return request_and_create_objects_from_xml(requestor, 'EngineSummary', object_creator)

    def GetEngineConfiguration(self, engine_or_id):
        """
        Return the configuration of a scan engine.
        This function will return a single dl_nexpose.EngineConfiguration XML object.
        Raises an exception on failure.
        """
        if isinstance(engine_or_id, EngineBase):
            engine_or_id = engine_or_id.id
        response = self.VerifySuccess(self.RequestEngineConfig(engine_or_id))
        element = get_element(response, 'EngineConfig')
        return EngineConfiguration.CreateFromXML(element)

    def GetEngineActiveScanSummaries(self, engine_or_id):
        """
        Return the scan summaries of all running scans of the specified scan engine.
        This function will generate dl_nexpose.ScanSummary objects using an EngineActivityRequest.
        Raises an exception on failure.
        """
        if isinstance(engine_or_id, EngineBase):
            engine_or_id = engine_or_id.id
        requestor = lambda: self.VerifySuccess(self.RequestEngineActivity(engine_or_id))
        object_creator = ScanSummary.CreateFromXML
        return request_and_create_objects_from_xml(requestor, 'ScanSummary', object_creator)

    def DeleteEngine(self, engine_summary_or_configuration):
        """
        Delete the specified engine (requires a dl_nexpose.EngineSummary or dl_nexpose.EngineConfiguration object).
        Raises an exception on failure.
        """
        self._RequireInstanceOf(engine_summary_or_configuration, EngineBase)
        self.VerifySuccess(self.RequestEngineDelete(engine_summary_or_configuration.id, engine_summary_or_configuration.scope))

    def GetLocalEngineSummary(self):
        """
        Return the scan engine summary of the local scan engine.
        This function will return a dl_nexpose.EngineSummary object.
        Raises an exception on failure.
        """
        scan_engines = self.GetEngineSummaries()
        for scan_engine in scan_engines:
            if scan_engine.name == 'Local scan engine':
                return scan_engine
        raise NexposeFailureException('Unable to locate the local scan engine')

    #
    # The following functions implement the Ticket Management API:
    # ===========================================================

    def CreateTicket(self, new_ticket):
        """
        Creates a new ticket and return its id.
        Raises an exception on failure.
        """
        self._RequireInstanceOf(new_ticket, NewTicket)
        response = self.VerifySuccess(self.RequestTicketCreate(new_ticket.AsXML()))
        return int(get_attribute(response, 'id'))

    def GetTicketSummaries(self, state_filter=None): # TODO: implement complete support for ticket filtering
        """
        Return (all) ticket summaries.
        An optional state filter either takes a string or an iterable of dl_nexpose.TicketState values.
        This function will generate dl_nexpose.EngineSummary objects using an EngineListingRequest.
        """
        requestor = lambda: self.RequestTicketListing()
        object_creator = TicketSummary.CreateFromXML
        tickets = request_and_create_objects_from_xml(requestor, 'TicketSummary', object_creator)
        if not state_filter:
            return tickets
        return filter(lambda ticket: ticket.state in state_filter, tickets)

    def GetTicketDetails(self, ticket_or_id):
        """
        Return the details of a ticket.
        This function will return a single dl_nexpose.TicketDetails XML object.
        Raises an exception on failure.
        """
        if isinstance(ticket_or_id, TicketSummary):
            ticket_or_id = ticket_or_id.id
        response = self.VerifySuccess(self.RequestTicketDetails(ticket_or_id))
        element = get_element(response, 'TicketInfo')
        return TicketDetails.CreateFromXML(element)

    def DeleteTicket(self, ticket_or_id):
        """
        Delete a ticket.
        Raises an exception on failure.
        """
        if isinstance(ticket_or_id, TicketSummary):
            ticket_or_id = ticket_or_id.id
        self.VerifySuccess(self.RequestTicketDelete(ticket_or_id))


    #
    # The following functions implement the Multi-Tenant User Management API:
    # ======================================================================

    def MultiTenantUserCreate(self):
        """
        """
        return self.RequestMultiTenantUserCreate()

    def MultiTenantUserListing(self):
        """
        """
        return self.RequestMultiTenantUserListing()

    def MultiTenantUserUpdate(self):
        """
        """
        return self.RequestMultiTenantUserUpdate()

    def MultiTenantUserConfig(self):
        """
        """
        return self.RequestMultiTenantUserConfig()

    def MultiTenantUserDelete(self):
        """
        """
        return self.RequestMultiTenantUserDelete()

    #
    # The following functions implement the Silo Profile Management API:
    # =================================================================

    def SiloProfileCreate(self):
        """
        """
        return self.RequestSiloProfileCreate()

    def SiloProfileListing(self):
        """
        """
        return self.RequestSiloProfileListing()

    def SiloProfileUpdate(self):
        """
        """
        return self.RequestSiloProfileUpdate()

    def SiloProfileConfig(self):
        """
        """
        return self.RequestSiloProfileConfig()

    def SiloProfileDelete(self):
        """
        """
        return self.RequestSiloProfileDelete()

    #
    # The following functions implement the Silo Management API:
    # =========================================================

    def SiloCreate(self):
        """
        """
        return self.RequestSiloCreate()

    def SiloListing(self):
        """
        """
        return self.RequestSiloListing()

    def SiloConfig(self):
        """
        """
        return self.RequestSiloConfig()

    def SiloUpdate(self):
        """
        """
        return self.RequestSiloUpdate()

    def SiloDelete(self):
        """
        """
        return self.RequestSiloDelete()

    #
    # The following functions implement the Report Management API:
    # ===========================================================
    
    def _LocateReportOnServer(self, id):
        for config in self.GetReportConfigurationSummaries():
            for summary in self.GetReportHistory(config.id):
                if summary.id == id:
                    return summary
        return ReportSummary() # Return an empty object in case of failure
    
    def _GetReportURI(self, report_or_id):
        if not isinstance(report_or_id, ReportConfigurationSummary):
            if not isinstance(report_or_id, ReportSummary):
                report_or_id = self._LocateReportOnServer(report_or_id)
        sub_url = remove_front_slash(report_or_id.URI)
        if not sub_url:
            sub_url = "reports/00000000/00000000/report.xml" # Assume this URI does not exist and force an error
        return sub_url

    def GetReportConfigurationSummaries(self):
        """
        Return information about all report definitions accessible by the user.
        This function will generate dl_nexpose.ReportConfigurationSummary objects
        using a ReportListingRequest.
        """
        requestor = lambda: self.RequestReportListing()
        object_creator = ReportConfigurationSummary.CreateFromXML
        return request_and_create_objects_from_xml(requestor, 'ReportConfigSummary', object_creator)

    def GetReportConfigurationDetails(self, report_or_configuration_or_id):
        """
        Return detailed information about the specified report configuration.
        This function will return a dl_nexpose.ReportConfigurationSummary object
        using a ReportConfigRequest.
        """
        if isinstance(report_or_configuration_or_id, ReportConfigurationSummary):
            report_or_configuration_or_id = report_or_configuration_or_id.id
        elif isinstance(report_or_configuration_or_id, ReportSummary):
            report_or_configuration_or_id = report_or_configuration_or_id.configuration_id
        response = self.VerifySuccess(self.RequestReportConfig(report_or_configuration_or_id))
        element = get_element(response, 'ReportConfig')
        return ReportConfigurationSummary.CreateFromXML(element) # todo: THIS MUST BE A FULL CONFIGURATION

    def GetReportHistory(self, reportconfiguration_or_id):
        """
        Return a history (report summary) of all reports generated with the specified report configuration.
        This function will generate dl_nexpose.ReportSummary objects
        using a ReportHistoryRequest.
        """
        if isinstance(reportconfiguration_or_id, ReportConfigurationSummary):
            reportconfiguration_or_id = reportconfiguration_or_id.id
        requestor = lambda: self.RequestReportHistory(reportconfiguration_or_id)
        object_creator = ReportSummary.CreateFromXML
        return request_and_create_objects_from_xml(requestor, 'ReportSummary', object_creator)

    def DeleteReport(self, report_or_id):
        """
        Delete the specified report.
        Raises an exception on failure.
        """
        if isinstance(report_or_id, ReportSummary):
            report_or_id = report_or_id.id
        self.VerifySuccess(self.RequestReportDelete(report_or_id, None))
    
    def DeleteReportConfiguration(self, report_or_configuration_or_id):
        """
        Delete the specified report configuration.
        Raises an exception on failure.
        """
        if isinstance(report_or_configuration_or_id, ReportConfigurationSummary):
            report_or_configuration_or_id = report_or_configuration_or_id.id
        elif isinstance(report_or_configuration_or_id, ReportSummary):
            report_or_configuration_or_id = report_or_configuration_or_id.configuration_id
        self.VerifySuccess(self.RequestReportDelete(None, report_or_configuration_or_id))
    
    def GenerateReport(self, report_or_configuration_or_id):
        """
        Generate a new report using the specified report configuration.
        Raises an exception on failure.
        """
        if isinstance(report_or_configuration_or_id, ReportConfigurationSummary):
            report_or_configuration_or_id = report_or_configuration_or_id.id
        elif isinstance(report_or_configuration_or_id, ReportSummary):
            report_or_configuration_or_id = report_or_configuration_or_id.configuration_id
        self.VerifySuccess(self.RequestReportGenerate(report_or_configuration_or_id))

    def GetReportStreamReader(self, report_or_id):
        """
        Get a reader that can be used to download a report stored on the security console.
        This function will return a file-like object. (see urllib2.urlopen)
        """
        sub_url = self._GetReportURI(report_or_id)
        return self._GetStreamReader(sub_url)

    def DownloadReport(self, report_or_id, callback_function=None, block_size=DEFAULT_BLOCK_SIZE):        
        """
        Download a report.
        The callback_function has the following signature:
          callback_function(already_downloaded_data, new_data)
        This function will return a bytearray object containing the data.
        """
        reader = self.GetReportStreamReader(report_or_id)
        return DownloadFromStreamReader(reader, callback_function, block_size)

    def GenerateScanReport(self, scan_or_id):        
        """
        Generate a report of a scan.
        """
        if isinstance(scan_or_id, ScanSummary):
            scan_or_id = scan_or_id.id
        data = self.RequestReportAdhocGenerate(scan_or_id)
        data = self.VerifySuccess(data)
        data = data.tail.replace('\r', '').strip().split('\n')
        assert data[1] == 'Content-Type: text/xml; name=report.xml'
        assert data[2] == 'Content-Transfer-Encoding: base64'
        assert data[3] == ''
        assert data[0] == data[-1][:-2]
        body = ''.join(data[4:-1])
        return as_xml(base64.urlsafe_b64decode(body))


    #
    # The following functions implement the Role Management API:
    # =========================================================

    def SaveRole(self, role_details):
        """
        Save a role (requires a dl_nexpose.RoleSummary object) and return the id of the saved role.
        If successful, the id will also have been updated in the provided dl_nexpose.RoleDetails object.
        To create a new role, specify -1 as id.
        Both name and fullname must be unique.
        Raises an exception on failure.
        """
        self._RequireInstanceOf(role_details, RoleDetails)
        if role_details.id == -1:
            response = self.VerifySuccess(self.RequestRoleCreate(role_details))
            id = int(get_attribute(response, 'id')) if response.tag == 'RoleCreateResponse' else 0
            if id:
                role_details.id = id
        else:
            response = self.VerifySuccess(self.RequestRoleUpdate(role_details))
        return role_details.id

    def GetRoleSummaries(self):
        """
        Return all roles.
        This function will generate dl_nexpose.RoleSummary objects using a RoleListingRequest.
        """
        requestor = lambda: self.RequestRoleListing()
        object_creator = RoleSummary.CreateFromXML
        return request_and_create_objects_from_xml(requestor, 'RoleSummary', object_creator)

    def GetRoleDetails(self, role_summary):
        """
        Return all details of a specified role (requires a dl_nexpose.RoleSummary object).
        This function will return a dl_nexpose.RoleDetails object using a RoleDetailsRequest.
        Raises an exception on failure.
        """
        self._RequireInstanceOf(role_summary, RoleSummary)
        response = self.VerifySuccess(self.RequestRoleDetails(role_summary.name, role_summary.scope))
        xml_data = get_element(response, 'Role')
        return RoleDetails.CreateFromXML(xml_data)

    def DeleteRole(self, role_summary):
        """
        Delete the specified role (requires a dl_nexpose.RoleSummary object).
        Raises an exception on failure.
        """
        self._RequireInstanceOf(role_summary, RoleSummary)
        self.VerifySuccess(self.RequestRoleDelete(role_summary.name, role_summary.scope))

    #
    # The following functions implement the Scan Engine Pool Management API:
    # =====================================================================

    def EnginePoolCreate(self):
        """
        """
        return self.RequestEnginePoolCreate()

    def EnginePoolListing(self):
        """
        """
        return self.RequestEnginePoolListing()

    def EnginePoolDetails(self):
        """
        """
        return self.RequestEnginePoolDetails()

    def EnginePoolUpdate(self):
        """
        """
        return self.RequestEnginePoolUpdate()

    def EnginePoolDelete(self):
        """
        """
        return self.RequestEnginePoolDelete()

    #
    # The following functions implement the Vulnerability Management API:
    # ==================================================================

    def GetVulnerabilities(self):
        """
        Return all vulnerabilities that can be checked.
        This function will generate dl_nexpose.VulnerabilitySummary objects using a VulnerabilityListingRequest.
        """
        requestor = lambda: self.RequestVulnerabilityListing()
        object_creator = VulnerabilitySummary.CreateFromXML
        return request_and_create_objects_from_xml(requestor, 'VulnerabilitySummary', object_creator)

    def GetVulnerabilityDetails(self, vulnerability_or_id):
        """
        Return detailed information about a specified vulnerability.
        This function will return a dl_nexpose.VulnerabilityDetail object
        """
        if isinstance(vulnerability_or_id, VulnerabilitySummary): vulnerability_or_id = vulnerability_or_id.id
        response = self.VerifySuccess(self.RequestVulnerabilityDetails(vulnerability_or_id))
        element = get_element(response, 'Vulnerability')
        return VulnerabilityDetail.CreateFromXML(element)

    #
    # The following functions implement the Vulnerability Exception Management API:
    # ============================================================================

    def GetAllSiloVulnerabilityExceptionDetails(self):
        """
        Return all vulnerability exceptions marked "Under Review" (per silo).
        This function will generate dl_nexpose.SiloVulnerabilityDetails objects using a PendingVulnExceptionsCountRequest.
        """
        requestor = lambda: self.RequestPendingVulnExceptionCount()
        object_creator = SiloVulnerabilityExceptionDetails.CreateFromXML
        return request_and_create_objects_from_xml(requestor, 'SiloVulnDetails', object_creator)

    def GetVulnerabilityExceptions(self, state_filter=None): # TODO: implement complete support for vulnerability exception filtering
        """
        Return all vulnerability exceptions.
        This function will generate dl_nexpose.VulnerabilityException objects using a VulnerabilityExceptionListingRequest.
        """
        requestor = lambda: self.RequestVulnerabilityExceptionListing()
        object_creator = VulnerabilityException.CreateFromXML
        return request_and_create_objects_from_xml(requestor, 'VulnerabilityException', object_creator)

    def CreateVulnerabilityException(self, exception):
        """
        """
        return self.RequestVulnerabilityExceptionCreate(exception.AsXML())

    def ResubmitVulnerabilityException(self, exception_or_id, reason=None, comment=None):
        """
        Resubmit the specified (rejected) vulnerability exception.
        If no reason is specified, it will default to 'other'.
        If the reason is 'other', you must specify a comment!
        Raises an exception on failure.
        """
        comment = comment if comment else ''
        reason = reason if reason else VulnerabilityExceptionReason.OTHER
        self.VerifySuccess(self.RequestVulnerabilityExceptionResubmit(exception_or_id, reason, comment))

    def RecallVulnerabilityException(self, exception_or_id):
        """
        Recall/delete the specified (under review) vulnerability exception.		
        Raises an exception on failure.
        """
        if isinstance(exception_or_id, VulnerabilityException):
            exception_or_id = exception_or_id.id
        self.VerifySuccess(self.RequestVulnerabilityExceptionRecall(exception_or_id))

    def ApproveVulnerabilityException(self, exception_or_id, comment=None):
        """
        Approve the specified (under review) vulnerability exception.
        The comment is only required if the current state of the exception is 'other'.
        Raises an exception on failure.
        """
        if isinstance(exception_or_id, VulnerabilityException):
            exception_or_id = exception_or_id.id
        comment = comment if comment else ''
        self.VerifySuccess(self.RequestVulnerabilityExceptionApprove(exception_or_id, comment))

    def RejectVulnerabilityException(self, exception_or_id, comment=None):
        """
        Reject the specified (under review) vulnerability exception.
        Raises an exception on failure.
        """
        if isinstance(exception_or_id, VulnerabilityException):
            exception_or_id = exception_or_id.id
        comment = comment if comment else ''
        self.VerifySuccess(self.RequestVulnerabilityExceptionReject(exception_or_id, comment))

    def DeleteVulnerabilityException(self, exception_or_id):
        """
        Delete the specified vulnerability exception.
        Raises an exception on failure.
        """
        if isinstance(exception_or_id, VulnerabilityException):
            exception_or_id = exception_or_id.id
        self.VerifySuccess(self.RequestVulnerabilityExceptionDelete(exception_or_id))

    def VulnerabilityExceptionUpdateComment(self):
        """
        """
        return self.RequestVulnerabilityExceptionUpdateComment()

    def VulnerabilityExceptionUpdateExpirationDate(self):
        """
        """
        return self.RequestVulnerabilityExceptionUpdateExpirationDate()

    #
    # The following functions implement the Tag Management API:
    # ========================================================

    def _GetTagsOf(self, pre_url, *args):
        if args:
            pre_url = pre_url.format(*args)
        json_dict = self.ExecutePagedGet_v20(pre_url + "tags")
        resources = json_dict.get("resources", None)
        if resources:
            return imap(Tag.CreateFromJSON, resources)
        return []

    def _AddIdTo(self, id_field_name, id, pre_url, sub_url):
        self.ExecutePost(pre_url + sub_url, {id_field_name: id})

    def _AddTagIdTo(self, tag_id, pre_url):
        self._AddIdTo("tag_id", tag_id, pre_url, "tags")

    def _SaveTag(self, tag, pre_url):
        data_to_post = tag.as_json() if isinstance(tag, Tag) else tag
        tag_id = Tag.GetID(tag)
        sub_url = pre_url + "tags"
        if tag_id:
            sub_url += "/{0}".format(tag_id)
            url = self.ExecutePut(sub_url, data_to_post)
        else:
            url = self.ExecutePost(sub_url, data_to_post)
        tag_id = url.split('/')[-1]
        if isinstance(tag, Tag):
            tag.id = int(tag_id)
        else:
            tag["tag_id"] = tag_id
        return tag_id

    def _SaveOrAddTagTo(self, tag_or_id, pre_url):
        tag_id = Tag.GetID(tag_or_id)
        if tag_id != 0:
            self._AddTagIdTo(tag_id, pre_url)
            return tag_id
        return self._SaveTag(tag_or_id, pre_url)

    def _AddTagTo(self, pre_url, tag_or_id, *args):
        pre_url = pre_url.format(*args)
        return self._SaveOrAddTagTo(tag_or_id, pre_url)

    def _RemoveTagFrom(self, pre_url, tag_or_id, *args):	
        if args:
            pre_url = pre_url.format(*args)
        sub_url = pre_url + "tags/{0}".format(Tag.GetID(tag_or_id))
        return self.ExecuteDelete(sub_url)

    def GetTags(self):
        """
        Get all the tags as a dl_nexpose.Tag object defined on the Nexpose Console.
        Requires the 2.0 API!
        """
        return self._GetTagsOf("")

    def GetTag(self, tag_id):
        """
        Get the information of a tag as a dl_nexpose.Tag object.
        Requires the 2.0 API!
        """
        sub_url = "tags/{0}".format(Tag.GetID(tag_id))
        json_dict = self.ExecutePagedGet_v20(sub_url)
        return Tag.CreateFromJSON(json_dict)

    def SaveTag(self, tag):
        """
        Save a tag.
        To create a new tag, set the id to -1.
        Requires the 2.0 API!
        """
        return self._SaveTag(tag, "")

    def DeleteTag(self, tag_or_id):
        """
        Delete a tag.
        Requires the 2.0 API!
        """
        return self._RemoveTagFrom("", tag_or_id)

    def GetSiteTags(self, site_or_id):
        """
        Get all the tags of a site as dl_nexpose.Tag objects.
        Requires the 2.0 API!
        """
        if isinstance(site_or_id, SiteBase): site_or_id = site_or_id.id
        return self._GetTagsOf(APIURL_SITES, site_or_id)

    def AddTagToSite(self, tag_or_id, site_or_id):
        """
        Add a tag to a site.
        Requires the 2.0 API!
        """
        if isinstance(site_or_id, SiteBase): site_or_id = site_or_id.id
        return self._AddTagTo(APIURL_SITES, tag_or_id, site_or_id)

    def RemoveTagFromSite(self, tag_or_id, site_or_id):	
        """
        Remove a tag from a site.
        Requires the 2.0 API!
        """
        if isinstance(site_or_id, SiteBase): site_or_id = site_or_id.id
        return self._RemoveTagFrom(APIURL_SITES, tag_or_id, site_or_id)

    def GetAssetTags(self, asset_or_id):
        """
        Get all the tags of an asset group as dl_nexpose.Tag objects.
        Requires the 2.0 API!
        """
        if isinstance(asset_or_id, AssetBase): asset_or_id = asset_or_id.id
        return self._GetTagsOf(APIURL_ASSETS, asset_or_id)

    def AddTagToAsset(self, tag_or_id, asset_or_id):
        """
        Add a tag to an asset.
        Requires the 2.0 API!
        """
        if isinstance(asset_or_id, AssetBase): asset_or_id = asset_or_id.id
        return self._AddTagTo(APIURL_ASSETS, tag_or_id, asset_or_id)

    def RemoveTagFromAsset(self, tag_or_id, asset_or_id):	
        """
        Remove a tag from an asset.
        Requires the 2.0 API!
        """
        if isinstance(asset_or_id, AssetBase): asset_or_id = asset_or_id.id
        return self._RemoveTagFrom(APIURL_ASSETS, tag_or_id, asset_or_id)

    def GetAssetGroupTags(self, assetgroup_or_id):
        """
        Get all the tags of an asset group as dl_nexpose.Tag objects.
        Requires the 2.0 API!
        """
        if isinstance(assetgroup_or_id, AssetGroupSummary): assetgroup_or_id = assetgroup_or_id.id
        return self._GetTagsOf(APIURL_ASSETGROUPS, assetgroup_or_id)

    def AddTagToAssetGroup(self, tag_or_id, assetgroup_or_id):
        """
        Add a tag to an asset group.
        Requires the 2.0 API!
        """
        if isinstance(assetgroup_or_id, AssetGroupSummary): assetgroup_or_id = assetgroup_or_id.id
        return self._AddTagTo(APIURL_ASSETGROUPS, tag_or_id, assetgroup_or_id)

    def RemoveTagFromAssetGroup(self, tag_or_id, assetgroup_or_id):
        """
        Remove a tag from an asset group.
        Requires the 2.0 API!
        """
        if isinstance(assetgroup_or_id, AssetGroupSummary): assetgroup_or_id = assetgroup_or_id.id
        return self._RemoveTagFrom(APIURL_ASSETGROUPS, tag_or_id, assetgroup_or_id)

    #
    # The following functions implement the Credentials API (not documented):
    # =====================================================

    def TestCredential(self, credential, target_host, target_port=0, engine_or_id=0, site_or_id=0):
        """
        Test a credential (dl_nexpose.Credential derived object) against the specified host.
        If no target_port is specified then the default port of the credential object is used.		
        If no scan engine is specified then the local scan engine will be queried and used.
        The site (or id) is optional.
        Returns true is the credential was valid, invalid credentials result in an exception.
        Raises an exception on failure.
        """
        assert isinstance(credential, Credential)

        if not target_port:
            target_port = credential.DEFAULT_PORT
        if not engine_or_id:
            engine_or_id = self.GetLocalEngineSummary()
        if isinstance(engine_or_id, EngineBase):
            engine_or_id = engine_or_id.id
        if isinstance(site_or_id, SiteBase):
            site_or_id = site_or_id.id

        parameters = dict()
        parameters['engineid'] = engine_or_id
        parameters['siteid'] = site_or_id
        parameters['sc_creds_dev'] = target_host
        parameters['sc_creds_port'] = target_port
        parameters['sc_creds_svc'] = credential.SERVICE_TYPE

        def add_parameter(para_name, attr_name):
            if hasattr(credential, attr_name):
                parameters[para_name] = credential.__dict__[attr_name]

        # TODO: how can we test NTLM hashes ?
        add_parameter('sc_creds_database', 'database')
        add_parameter('sc_creds_domain', 'domain')
        add_parameter('sc_creds_uname', 'username')
        add_parameter('sc_creds_password', 'password')
        add_parameter('sc_creds_pemkey', 'pemkey')
        add_parameter('sc_creds_privilegeelevationusername', 'privilege_elevation_username')
        add_parameter('sc_creds_privilegeelevationpassword', 'privilege_elevation_password')
        add_parameter('sc_creds_privilegeelevationtype', 'privilege_elevation_type')
        add_parameter('sc_creds_snmpv3authtype', 'snmpv3_authentication_type')
        add_parameter('sc_creds_snmpv3privtype', 'snmpv3_private_type')
        add_parameter('sc_creds_snmpv3privpassword', 'snmpv3_private_password')

        response = as_xml(self.ExecuteFormPost('/ajax/test_admin_credentials.txml', parameters))
        self.VerifySuccess(response)
        return True

    #
    # The following functions implement the Shared Credentials API (not documented):
    # ============================================================

    def GetSharedCredentialSummaries(self):
        # NOTE: if we assign a random string (such as 'DoS') to sort
        #       and we assign an empty string to dir
        #       or if we assign both 0 to dir and sort
        #       than the appliance will no longer be able to list the shared credentials
        #       to/for the logged in user
        filter_data = {'dir': '-1', 'sort': '-1', 'table-id': 'credential-listing'}
        data = self.ExecuteGetRecords('data/credential/shared/listing', filter_data)
        #print data
        return imap(SharedCredentialSummary.CreateFromJSON, data)

    def GetSharedCredentialConfiguration(self, id_or_shared_credential):
        if isinstance(id_or_shared_credential, SharedCredentialBase):
            id_or_shared_credential = id_or_shared_credential.id
        data = self.ExecuteGet('data/credential/shared/get', {'credid': id_or_shared_credential})
        #print as_string(data)
        return SharedCredentialConfiguration.CreateFromXML(data)

    def SaveSharedCredentialConfiguration(self, shared_credential):
        assert isinstance(shared_credential, SharedCredentialConfiguration)

        if shared_credential.id == -1:
            old_ids = set(imap(lambda summary: summary.id, self.GetSharedCredentialSummaries()))
        xml = shared_credential.AsXML()
        #print as_string(xml)
        response = as_xml(self.ExecuteFormPost('data/credential/shared/save', xml))
        if shared_credential.id == -1:
            new_ids = set(imap(lambda summary: summary.id, self.GetSharedCredentialSummaries()))

        if shared_credential.id == -1:
            diff_ids = new_ids.difference(old_ids)
            assert len(diff_ids) == 1
            shared_credential.id = diff_ids.pop()

        return shared_credential.id

    def DeleteSharedCredential(self, id_or_shared_credential):
        """
        Delete a shared credential from the security console.
        An id or dl_nexpose.SharedCredential object is expected.
        This function will return a boolean indicating success.
        NOTE: no official documentation exists except the Rapid7 Nexpose Ruby API.
        """
        # TODO: To be equal with the other delete functions, this one should raise an exception
        try:
            if isinstance(id_or_shared_credential, SharedCredentialBase):
                id_or_shared_credential = id_or_shared_credential.id
            return self.ExecuteFormPost('data/credential/shared/delete?credid={0}'.format(id_or_shared_credential), '') == 'true'
        except urllib2.HTTPError:
            return False

    #
    # The following functions implement the Backup Management API (not documented):
    # ===========================================================

    def GetBackups(self):
        """
        Get all backups stored on the security console.
        This function will generate dl_nexpose.Backup objects.
        NOTE: no official documentation exists except the Rapid7 Nexpose Ruby API.
        """
        # Uncomment this if you need to support older Nexpose Servers:
        # columns, data = self.ExecuteGetDynTable('admin/global/ajax/backup_listing.txml')
        columns, data = self.ExecuteGetDynTable('data/admin/backups?printDocType=0&tableID=BackupSynopsis')
        return imap(Backup.CreateFromJSON, data)

    def CreateBackup(self, platform_independent=False, description=None):
        """
        Restart the security console and create a backup.
        This function will return a boolean indicating if the request has been received.
        NOTE: no official documentation exists except the Rapid7 Nexpose Ruby API.
        """
        parameters = {'backup_desc': description, 'platform_independent': platform_independent}
        return self.ExecuteMaintenanceCommandAndRestartOnSuccess('backupRestore', 'backup', parameters)

    def RestoreBackup(self, backup_or_filename):
        """
        Restart the security console and restore a backup.
        A (file)name or dl_nexpose.Backup object is expected.
        This function will return a boolean indicating if the request has been received.
        NOTE: no official documentation exists except the Rapid7 Nexpose Ruby API.
        """
        if isinstance(backup_or_filename, Backup):
            backup_or_filename = backup_or_filename.name
        parameters = {'backupid': backup_or_filename}
        return self.ExecuteMaintenanceCommandAndRestartOnSuccess('backupRestore', 'restore', parameters)

    def GetBackupStreamReader(self, backup_or_filename):
        """
        Get a reader that can be used to download a backup stored on the security console.
        A (file)name or dl_nexpose.Backup object is expected.
        This function will return a file-like object. (see urllib2.urlopen)
        NOTE: no official documentation exists except the Rapid7 Nexpose Ruby API.
        """
        if isinstance(backup_or_filename, Backup):
            backup_or_filename = backup_or_filename.name
        sub_url = 'admin/global/download-backup/{0}'.format(backup_or_filename)
        return self._GetStreamReader(sub_url)

    def DownloadBackup(self, backup_or_filename, callback_function=None, block_size=DEFAULT_BLOCK_SIZE):
        """
        Download a backup stored on the security console.
        A (file)name or dl_nexpose.Backup object is expected.
        The callback_function has the following signature:
          callback_function(already_downloaded_data, new_data)
        This function will return a bytearray object containing the zipped backup data.
        NOTE: no official documentation exists except the Rapid7 Nexpose Ruby API.
        """
        reader = self.GetBackupStreamReader(backup_or_filename)
        return DownloadFromStreamReader(reader, callback_function, block_size)

    def DeleteBackup(self, backup_or_filename):
        """
        Delete a stored backup from the security console.
        A (file)name or dl_nexpose.Backup object is expected.
        This function will return a boolean indicating if the request has been received.
        NOTE: no official documentation exists except the Rapid7 Nexpose Ruby API.
        """
        # TODO: raise an exception on failure
        if isinstance(backup_or_filename, Backup):
            backup_or_filename = backup_or_filename.name
        parameters = {'backupid': backup_or_filename}
        return self.ExecuteMaintenanceCommand('backupRestore', 'deleteBackup', parameters)
