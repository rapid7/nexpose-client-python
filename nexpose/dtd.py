Device_DTD = """
<!DOCTYPE device [
<!ELEMENT device (description?)>
<!-- the ID of the device -->
<!ATTLIST device id CDATA #REQUIRED>
<!-- the ID of the site the device belongs to -->
<!ATTLIST device site-id CDATA #IMPLIED>
<!-- the primary address or hostname of the device -->
<!ATTLIST device address CDATA #IMPLIED>
<!-- the current riskfactor (weighting) for the device -->
<!ATTLIST device riskfactor CDATA "1.0">
<!-- the current risk score of the device -->
<!ATTLIST device riskscore CDATA #IMPLIED>
]>"""

SiteSummary_DTD = """
<!DOCTYPE SiteSummary [
<!ELEMENT SiteSummary EMPTY>
<!ATTLIST SiteSummary id CDATA #REQUIRED>
<!ATTLIST SiteSummary name CDATA #REQUIRED>
<!ATTLIST SiteSummary description CDATA #IMPLIED>
<!ATTLIST SiteSummary riskfactor CDATA "1.0">
<!-- The riskscore stored in the application is a computed value
equal to riskscore * riskfactor. The risk scores are only computed
after the site is scanned. This presents a problem when the site
administrator changes the site riskfactor. To account for changing
the riskfactor take the existing computed riskscore divide by the
old riskfactor and multiply by the new riskfactor.-->
<!ATTLIST SiteSummary riskscore CDATA "0.0">
]>"""

Site_DTD = """
<!-- Note: Only enter DNS names in the host element. Do not enter an IP address in that element.
Use the range element for IP address ranges. For a single IP address, use the range element
where the from value is the IP address and the to value is empty. -->
<!DOCTYPE Site [
<!ELEMENT Site (Hosts, Credentials, Alerting, ScanConfig, Tags)>
<!-- Use id="-1" to create a new Site -->
<!ATTLIST Site id CDATA #REQUIRED>
<!ATTLIST Site name CDATA #REQUIRED>
<!ATTLIST Site description CDATA #IMPLIED>
<!ATTLIST Site riskfactor CDATA "1.0">
<!ELEMENT Hosts ((range|host)+)>
<!-- IPv4 address range of the form 10.0.0.1 -->
<!ELEMENT range EMPTY>
<!ATTLIST range from CDATA #REQUIRED>
<!ATTLIST range to CDATA #IMPLIED>
<!-- named host (usually DNS or Netbios name -->
<!ELEMENT host (#PCDATA)>
<!ELEMENT Credentials (adminCredentials*)>
<!ELEMENT adminCredentials (#PCDATA|Headers|HTMLForms|PEMKey)*>
<!-- cifs Concurrent Versioning System (CVS) -->
<!-- ftp File Transfer Protocol (FTP) -->
<!-- http HyperText Transfer Protocol (HTTP) -->
<!-- htmlform Web form authentication -->
<!-- httpheaders HTTP session authentication -->
<!-- as400 IBM AS/400 -->
<!-- notes Lotus Notes/Domino -->
<!-- tds Microsoft SQL Server -->
<!-- sybase Sybase SQL Server -->
<!-- cifs Microsoft Windows/Samba (SMB/CIFS) -->
<!-- oracle Oracle -->
<!-- mysql MySQL Server -->
<!-- db2 IBM DB2 Server -->
<!-- postgresql PostgreSQL Server -->
<!-- pop Post Office Protocol (POP) -->
<!-- remote execution Remote Execution -->
<!-- snmp Simple Network Management Protocol -->
<!-- ssh Secure Shell (SSH) -->
<!-- ssh-key Secure Shell (SSH) Public Key -->
<!-- telnet TELNET -->
<!-- TODO: remote-execution is actually "remote execution" but spaces are not allowed in DTD enumerated values! -->
<!ATTLIST adminCredentials service (cvs|ftp|http|as400|notes|htmlform|httpheaders|tds|sybase|cifs|oracle|mysql|db2|pop|postgresql|remote-execution|snmp|ssh|ssh-key|telnet) #REQUIRED>
<!ATTLIST adminCredentials host CDATA #IMPLIED>
<!ATTLIST adminCredentials port CDATA #IMPLIED>
<!-- the userid, password and realm attributes should ONLY be used
if a security blob cannot be generated and the data is being
transmitted/stored using external encryption (eg, HTTPS)
SiteSaveRequest doesn't handle the security blob right now
So username/password attributes should be used in that case-->
<!ATTLIST adminCredentials USERID CDATA #IMPLIED>
<!ATTLIST adminCredentials PASSWORD CDATA #IMPLIED>
<!-- when using snmp assign the community name to the password
attribute -->
<!ATTLIST adminCredentials realm CDATA #IMPLIED>
<!-- when using httpheaders, this represents the set of headers to pass
with the
authentication request -->
<!ELEMENT Headers (Header+)>
<!-- A regular expression used to match against the response to
identify authentication
failures. -->
<!ATTLIST Headers soft403 CDATA #IMPLIED>
<!-- the base URL of the application for which the form authentication
applies. -->
<!ATTLIST Headers webapproot CDATA #IMPLIED>
<!ELEMENT Header (#PCDATA)>
<!ATTLIST Header name CDATA #REQUIRED>
<!ATTLIST Header value CDATA #IMPLIED>
<!-- when using htmlform, this represents the login form
information -->
<!ELEMENT HTMLForms (HTMLForm+)>
<!-- the URL of the login page containing the login form -->
<!ATTLIST HTMLForms parentpage CDATA #IMPLIED>
<!-- A regular expression used to match against the response to
identify
authentication failures. -->
<!ATTLIST HTMLForms soft403 CDATA #IMPLIED>
<!-- the base URL of the application for which the form
authentication applies. -->
<!ATTLIST HTMLForms webapproot CDATA #IMPLIED>
<!ELEMENT HTMLForm (Field*)>
<!-- the name of the form being submitted -->
<!ATTLIST HTMLForm name CDATA #IMPLIED>
<!-- the HTTP action (URL) through which to submit the login form -->
<!ATTLIST HTMLForm action CDATA #REQUIRED>
<!-- the HTTP request method with which to submit the form -->
<!ATTLIST HTMLForm method CDATA #IMPLIED>
<!-- the HTTP encoding type with which to submit the form -->
<!ATTLIST HTMLForm enctype CDATA #IMPLIED>
<!ELEMENT Field (#PCDATA)>
<!-- the name of the HTML field (form parameter) -->
<!ATTLIST Field name CDATA #IMPLIED>
<!-- the value of the HTML field (form parameter) -->
<!ATTLIST Field value CDATA #IMPLIED>
<!-- the type of the HTML field (form parameter) -->
<!ATTLIST Field type CDATA #IMPLIED>
<!-- is the HTML field (form parameter) dynamically generated? If
so, the login
page is requested and the value of the field is extracted from the
response. -->
<!ATTLIST Field dynamic CDATA #IMPLIED>
<!-- if the HTML field (form parameter) is a radio button, checkbox
or select field,
this flag determines if the field should be checked (selected) -->
<!ATTLIST Field checked CDATA #IMPLIED>
<!-- when using ssh-key, this represents the PEM-format keypair
information -->
<!ELEMENT PEMKey (#PCDATA)>
<!ELEMENT Alerting (Alert*)>
<!ELEMENT Alert (scanFilter?, vulnFilter?,
(smtpAlert|snmpAlert|syslogAlert))>
<!ATTLIST Alert name CDATA #REQUIRED>
<!ATTLIST Alert enabled (0|1) "0">
<!ATTLIST Alert maxAlerts CDATA #IMPLIED> <!-- TODO: COULD ALSO BE #REQUIRED -->
<!ELEMENT scanFilter (#PCDATA)>
<!ATTLIST scanFilter scanStart (0|1) "0">
<!ATTLIST scanFilter scanStop (0|1) "0">
<!ATTLIST scanFilter scanFailed (0|1) "0">
<!ATTLIST scanFilter scanPaused (0|1) "0">
<!ATTLIST scanFilter scanResumed (0|1) "0">
<!ELEMENT vulnFilter EMPTY>
<!-- severityThreshold defaults to 1. Currently the application
only supports values of 1 (Any Severity), 4 (Severe and Critical)
and 8 (Only Critical). -->
<!ATTLIST vulnFilter severityThreshold (1|2|3|4|5|6|7|8|9|10) #REQUIRED>
<!ATTLIST vulnFilter confirmed (0|1) "1">
<!ATTLIST vulnFilter unconfirmed (0|1) "1">
<!ELEMENT smtpAlert (recipient+)>
<!ATTLIST smtpAlert sender CDATA #IMPLIED>
<!ATTLIST smtpAlert server CDATA #IMPLIED>
<!ATTLIST smtpAlert port CDATA "25">
<!ATTLIST smtpAlert limitText (0|1) "0">
<!ELEMENT recipient (#PCDATA)>
<!ELEMENT snmpAlert EMPTY>
<!ATTLIST snmpAlert community CDATA #IMPLIED> <!-- TODO: COULD ALSO BE #REQUIRED -->
<!ATTLIST snmpAlert server CDATA #REQUIRED>
<!ATTLIST snmpAlert port CDATA "162">
<!ELEMENT syslogAlert EMPTY>
<!ATTLIST syslogAlert server CDATA #REQUIRED>
<!ATTLIST syslogAlert port CDATA "514">
<!ELEMENT Users (user+)>
<!ELEMENT user EMPTY>
<!-- the ID of a non-admin user who has access to this site -->
<!ATTLIST user id CDATA #REQUIRED>
<!-- See the ScanConfig DTD for more details -->
<!ELEMENT Tags (Tag+)>
<!ELEMENT Tag (param+)>
<!-- Use id="-1" to create a new tag -->
<!ATTLIST Tag id CDATA #REQUIRED>
<!-- the name of the tag. -->
<!ATTLIST Tag name CDATA #REQUIRED>
<!-- the type of the tag. -->
<!ATTLIST Tag type (general|location|owner|criticality) #REQUIRED>
<!ELEMENT Param EMPTY>
<!ATTLIST Param name (source|color) #REQUIRED>
<!ATTLIST Param value CDATA #REQUIRED>
]>"""

AssetGroupSummary_DTD = """
<!DOCTYPE AssetGroupSummary [
<!ELEMENT AssetGroupSummary EMPTY>
<!ATTLIST AssetGroupSummary id CDATA #REQUIRED>
<!ATTLIST AssetGroupSummary name CDATA #REQUIRED>
<!ATTLIST AssetGroupSummary description CDATA #IMPLIED>
<!ATTLIST AssetGroupSummary riskscore CDATA #IMPLIED>
]>"""

AssetGroup_DTD = """
<!DOCTYPE AssetGroup [
<!ELEMENT AssetGroup (Devices)>
<!-- Use id="-1" to create a new Asset Group -->
<!ATTLIST AssetGroup id CDATA #REQUIRED>
<!ATTLIST AssetGroup name CDATA #REQUIRED>
<!ATTLIST AssetGroup description CDATA #IMPLIED>
<!ATTLIST AssetGroup riskscore CDATA #IMPLIED>
<!ELEMENT Devices (device+)>
<!-- See the device DTD for more details -->
<!ELEMENT Users (user+)>
<!ELEMENT user EMPTY>
<!-- the ID of a non-admin user who has access to this site -->
<!ATTLIST user id CDATA #REQUIRED>
<!ELEMENT Tags (Tag+) >
<!ELEMENT Tag (param+) >
<!-- Use id="-1" to create a new tag -->
<!ATTLIST Tag id CDATA #REQUIRED>
<!-- the name of the tag. -->
<!ATTLIST Tag name CDATA #REQUIRED>
<!-- the type of the tag. -->
<!ATTLIST Tag type CDATA #REQUIRED
(general|location|owner|criticality)>
<!ELEMENT Param>
<!ATTLIST Param name CDATA #REQUIRED(source|color)>
<!ATTLIST Param value CDATA #REQUIRED>
]>"""

EngineSummary_DTD = """
Prior to the release dated October 15, 2008, EngineSummaryResponse always returned
“unknown” for EngineStatus values. As of October 15, 2008, the EngineSummaryResponse may
return a value other than “unknown.”
<!DOCTYPE EngineSummary [
<!ELEMENT EngineSummary EMPTY>
<!ATTLIST EngineSummary id CDATA #REQUIRED>
<!ATTLIST EngineSummary name CDATA #REQUIRED>
<!ATTLIST EngineSummary address CDATA #REQUIRED>
<!ATTLIST EngineSummary port CDATA #REQUIRED>
<!-- current status of the Scan Engine -->
<!ATTLIST EngineSummary status (Active|Pnding-auth|Incompatible|
Not-responding|Unknown) #REQUIRED>
<!-- the visibility (scope) of the Scan Engine -->
<!ATTLIST ReportTemplateSummary scope (global|silo) #IMPLIED>
]>"""

ScanConfig_DTD = """
<!DOCTYPE ScanConfig [
<!ELEMENT ScanConfig (Schedules?)>
<!ATTLIST ScanConfig configID CDATA>
<!ATTLIST ScanConfig name CDATA>
<!-- Specify the scan template to use when starting a scan job -->
<!ATTLIST ScanConfig templateID CDATA #REQUIRED>
<!-- the Scan Engine to use. Omit to use the default engine -->
<!ATTLIST ScanConfig engineID CDATA #IMPLIED>
<!ATTLIST ScanConfig configVersion (3) "3">
<!ELEMENT Schedules (Schedule*)>
<!-- To use multiple scan schedules in a site, include a Schedule
element for each desired schedule. Make sure not to schedule
overlapping scans with the same scan template. This will cause an
error. You can overlap scans with different templates.-->
<!ELEMENT Schedule EMPTY>
<!ATTLIST Schedule enabled (0|1) "0">
<!ATTLIST Schedule type (daily|hourly|monthly-date|monthlyday|
weekly) #IMPLIED>
<!ATTLIST Schedule interval CDATA>
<!-- the earliest date to run the scan on in the following format,
YYYYMMDDTHHMMSSsss, such as: 19981231T00000000 -->
<!ATTLIST Schedule start CDATA #REQUIRED>
<!-- the amount of time, in minutes, to allow execution before
stopping -->
<!ATTLIST Schedule maxDuration CDATA #IMPLIED>
<!-- the date after which the schedule is disabled in the following
format,
YYYYMMDDTHHMMSSsss, such as: 19981231T00000000 -->
<!ATTLIST Schedule notValidAfter CDATA #IMPLIED>
<!-- Apply a specific scan template to a schedule. If you do not
specify a template for a given schedule, the schedule will use the
template specified for the site. -->
<!ATTLIST Schedule template CDATA #IMPLIED>
<!-- Set a schedule to be in effect as of the next applicable day
or date as indicated in the following attributes. This makes it
unnecessary to indicate a specific start date for a schedule. -->
<!ATTLIST Schedule is-extended (false|true) #IMPLIED>
<!-- The hour of the day that the schedule starts. If you do not
specify an hour, the schedule will start at the top of the next
hour. This attribute is only valid if the is-extended attribute is
set to true. -->
<!ATTLIST Schedule hour
(1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|21|22|23)
#IMPLIED -->
<!-- The minute of the hour that the schedule starts. If you do not
specify a minute, the schedule will start at the top of the hour.
This attribute is only valid if the is-extended attribute is set to
true. -->
<!ATTLIST Schedule minute
(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|
21|22|23|24|25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|
41|42|43|44|45|46|47|48|49|50|51|52|53|54|55|56|57|58|59) #IMPLIED>
<!-- The date of the month that the schedule starts. Only valid if
used with monthly-date and if the is-extended attribute is set to
true. Required for monthly-date. If you do not include the date in
the current or specified month, the request will return an error. -
->
<!ATTLIST Schedule date
(1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|
21|22|23|24|25|26|27|28|29|30|31|last) #IMPLIED>
<!-- The day of the week that the schedule starts. Only valid if
used with monthly-day or weekly and if the is-extended attribute is
set to true. Required for monthly-day and weekly. -->
<!ATTLIST Schedule day
(monday|mon|tuesday|tue|wednesday|wed|thursday|thur
friday|fri|saturday|sat|sunday|sun) #IMPLIED>
<!-- The ordinal date of the month, such as third Saturday, that
the schedule starts. Only valid if used with monthly-day and if the
is-extended attribute is set to true. Required for monthly-day. -->
<!ATTLIST Schedule occurrence (1|2|3|4|last) #IMPLIED>
<!-- The month that the schedule starts. Only valid if used with
monthly-date or monthly-day and if the is-extended attribute is set
to true. -->
<!ATTLIST Schedule start-month
(january|jan|february|feb|march|mar|april|apr|may|june|jun|july|
jul|august|aug|september|sep|october|oct|november|nov|december|
dec) #IMPLIED>
<!-- Examples of a scan schedules
The following schedule runs at 1:35 a.m. on the second Wednesday of every month, starting on
the following April. If the scan exceeds the maximum duration of 60 minutes, it restarts from the
beginning.
<Schedule enabled='1' is-extended='true' type='monthly-day' start_
month='April' occurrence='2' day='wednesday' hour='1' minute='35'
interval='10' maxDuration='60' repeaterType='restart' />
The following schedule runs weekly on Mondays, starting at 8 p.m.
<Schedule is-extended="true" interval="1" type="weekly" day="monday"
hour="20" interval='10' maxDuration='60' repeaterType='restart'/>
The following schedule starts at 8 p.m. on the 18th day of the current month.
<Schedule is-extended="true" interval="1" type="monthly-date" date="18"
hour="20"/>-->
]>"""

ScanSummary_DTD = """
<!DOCTYPE ScanSummary [
<!ELEMENT ScanSummary (message?, tasks?, nodes?, vulnerabilities*)>
<!ATTLIST ScanSummary scan-id CDATA #REQUIRED>
<!-- the site that was scanned -->
<!ATTLIST ScanSummary site-id CDATA #REQUIRED>
<!-- the engine the scan was dispatched to -->
<!ATTLIST ScanSummary engine-id CDATA #REQUIRED>
<!ATTLIST ScanSummary name CDATA #REQUIRED>
<!-- the scan start date and time in ISO 8601 format,
YYYYMMDDTHHMMSSsss, such as: 19981231T00000000 -->
<!ATTLIST ScanSummary startTime CDATA #REQUIRED>
<!-- the scan completion date and time in ISO 8601 format,
YYYYMMDDTHHMMSSsss, such as: 19981231T00000000 -->
<!ATTLIST ScanSummary endTime CDATA #IMPLIED>
<!ATTLIST ScanSummary status (running|finished|stopped|error|
dispatched|paused|aborted|unknown) #REQUIRED>
<!ELEMENT message (#PCDATA)>
<!ELEMENT tasks EMPTY>
<!ATTLIST tasks pending CDATA #REQUIRED>
<!ATTLIST tasks active CDATA #REQUIRED>
<!ATTLIST tasks completed CDATA #REQUIRED>
<!ELEMENT nodes EMPTY>
<!ATTLIST nodes live CDATA #REQUIRED>
<!ATTLIST nodes dead CDATA #REQUIRED>
<!ATTLIST nodes filtered CDATA #REQUIRED>
<!ATTLIST nodes unresolved CDATA #REQUIRED>
<!ATTLIST nodes other CDATA #REQUIRED>
<!ELEMENT vulnerabilities EMPTY>
<!ATTLIST vulnerabilities status (vuln-exploit|vuln-version|
vuln-potential| not-vuln-exploit| not-vuln-version|
error|disabled|other)
#REQUIRED>
<!-- vulnerability severity (1-10, only provided with vuln-exploit
and vuln-version status) -->
<!ATTLIST vulnerabilities severity CDATA #IMPLIED>
<!-- the number of vulnerabilities with the specified status and
severity -->
<!ATTLIST vulnerabilities count CDATA #REQUIRED>
]>"""

ReportTemplateSummary_DTD = """
<!DOCTYPE ReportTemplateSummary [
<!ELEMENT ReportTemplateSummary (description?)>
<!-- the id of the report template -->
<!ATTLIST ReportTemplateSummary id CDATA #REQUIRED>
<!-- the name of the report template -->
<!ATTLIST ReportTemplateSummary name CDATA #REQUIRED>
<!-- the visibility (scope) of the report template -->
<!ATTLIST ReportTemplateSummary scope (global|silo) #IMPLIED>
<!-- With a data template, you can export comma-separated value
(CSV) files with vulnerability- based data. With a document
template, you can create PDF, RTF, HTML, or XML reports with assetbased
information. -->
<!ATTLIST ReportTemplateSummary type (data|document) #REQUIRED>
<!-- whether the report template is built-in, and therefore cannot
be modified (0=false,
1=true) -->
<!ATTLIST ReportTemplateSummary builtin (0|1) #REQUIRED
<!ELEMENT description (#PCDATA)>
]>"""

ReportTemplate_DTD = """
<!DOCTYPE ReportTemplate [
<!ELEMENT ReportTemplate (description?,ReportSections?,Settings)>
<!-- the id of the report template -->
<!ATTLIST ReportTemplate id CDATA #REQUIRED>
<!-- the name of the report template -->
<!ATTLIST ReportTemplate name CDATA #REQUIRED>
<!-- the visibility (scope) of the report template -->
<!ATTLIST ReportTemplate scope (global|silo) #IMPLIED>
<!-- With a data template, you can export comma-separated value
(CSV) files with vulnerability- based data. With a document
template, you can create PDF, RTF, HTML, or XML reports with assetbased
information. When you retrieve a report template, the type
will always be visible even though type is implied. When
ReportTemplate
is sent as a request, and the type attribute is not provided, the
type attribute defaults to doc- ument, allowing for backward
compatibility with existing API
clients. -->
<!ATTLIST ReportTemplateSummary type (data|document) #IMPLIED>
<!-- the report template is built-in, and cannot be modified
(0=false, 1=true) -->
<!ATTLIST ReportTemplate builtin (0|1) #REQUIRED
<!ELEMENT description (#PCDATA)>
<!ELEMENT ReportSections (ReportSection+,property*)>
<!ELEMENT property (#PCDATA)>
<!-- the name of the property -->
<!ATTLIST property name CDATA #REQUIRED>
<!ELEMENT ReportSection (property*)>
<!ATTLIST ReportSection name CDATA #REQUIRED>
<!-- section specific content to include -->
<!ELEMENT property (#PCDATA)>
<!-- the name of the property -->
<!ATTLIST property name CDATA #REQUIRED>
<!ELEMENT Settings(showDeviceNames)>
<!ELEMENT showDeviceNames EMPTY>
<!ATTLIST showDeviceNames enabled (0|1) "0">
]>"""

ReportConfigSummary_DTD = """
<!DOCTYPE ReportConfigSummary [
<!ELEMENT ReportConfigSummary EMPTY>
<!-- the id of the report template -->
<!ATTLIST ReportConfigSummary template-id CDATA #REQUIRED>
<!-- the report definition (config) id -->
<!ATTLIST ReportConfigSummary cfg-id CDATA #REQUIRED>
<!-- the current status of the report -->
<!ATTLIST ReportConfigSummary status
(Started|Generated|Failed|Aborted|Unknown) #REQUIRED>
<!-- the date and time the report was generated, in ISO 8601
format, YYYYMMDDTHHMMSSsss, such as: 19981231T00000000 -->
<!ATTLIST ReportConfigSummary generated-on CDATA #REQUIRED>
<!-- the URL to use to access the report (not set for database
exports) -->
<!ATTLIST ReportConfigSummary report-URI CDATA #IMPLIED>
<!ATTLIST ReportConfigSummary scope (global|silo) #IMPLIED>
]>"""

ReportConfig_DTD = """
<!DOCTYPE ReportConfig [
<!ELEMENT ReportConfig (description?, Filters, Users, Baseline?,
Generate, Delivery, DBExport?)>
<!-- the id of the report definition (config) -->
<!ATTLIST ReportConfig id CDATA #REQUIRED>
<!-- the unique name assigned to the report definition -->
<!ATTLIST ReportConfig name CDATA #REQUIRED>
<!-- With the site, device, and group filters you determine which
assets to include in the report. With the vuln-severity and vulnstatus
filters you control which vulnerabilities to include in the
report. -->
<!ELEMENT AdhocReportConfig (Filters, Baseline?) >
<!-- the id of the report template used -->
<!ATTLIST ReportConfig template-id CDATA #REQUIRED>
<!ATTLIST ReportConfig format (pdf|html|rtf|xml|text|
csv|db|raw-xml|raw-xml-v2|ns-xml|qualys-xml) #REQUIRED>
<!ATTLIST ReportConfig owner CDATA #REQUIRED>
<!ATTLIST ReportConfig timezone CDATA #REQUIRED>
<!ELEMENT description (#PCDATA)>
<!-- The configuration must include at least one of device (asset),
site, group (asset group) or scan filter to define the scope of
report. The vuln-status filter can be used only with raw report
formats: csv or raw_xml. If the vuln-status filter is not included
in the configuration, all the vulnerability test results (including
invulnerable instances) are exported by default in csv and raw_xml
reports. -->
<!ELEMENT Filters (filter+)>
<!ELEMENT filter EMPTY> <!ATTLIST filter type
(site|group|device|scan|vuln-categories|
vuln-severity|vuln-status|cyberscope-component|cyberscopebureau|
cyberscope-enclave|tag)
#REQUIRED>
<!-- the ID of a specific site, group, device or scan.
For scan, this can also be "last" for the most recently run scan.
For vuln-status, the ID can have one of the following values:
1) vulnerable-exploited (The check was positive. An exploit
verified the vulnerability.)
2) vulnerable-version (The check was positive. The version of the
scanned service or software is associated with known
vulnerabilities.)
3) potential (The check for a potential vulnerability was
positive.) These values are supported for CSV and XML formats.
-->
<!ATTLIST filter id CDATA #REQUIRED>
<!-- For vuln-categories, the required format is include/exclude:
[category_from_approved_list]
Examples:
include:Adobe,Microsoft
exclude:Windows,Oracle -->
<!ELEMENT Users (user+)>
<!ELEMENT user EMPTY>
<!-- the ID of a non-admin user who has access to this site -->
<!ATTLIST user id CDATA #REQUIRED>
<!ELEMENT Baseline EMPTY>
<!-- the date to use as the baseline scan in ISO 8601 format,
YYYYMMDDTHHMMSSsss, such as:
19981231T00000000. Additionally,"first" can be used for the first
run scan, or "previous" for the most recently run scan prior to the
current scan. The Baseline compareTo attribute is optional unless
you are creating a Baseline Comparison, Executive Overview, or
custom report that incorpo- rates the Baseline Comparison section,
in which case the attribute is required.-->
<!ATTLIST Baseline compareTo CDATA #IMPLIED>
<!ELEMENT Generate (Schedule?)>
<!-- will the report be generated after a scan completes (1), or is
it ad-hoc/scheduled (0) -->
<!ATTLIST Generate after-scan (0|1) "0">
<!ATTLIST Generate schedule CDATA #IMPLIED>
<!ELEMENT Schedule EMPTY>
<!ATTLIST Schedule enabled (0|1) "1">
<!ATTLIST Schedule type (daily|hourly|monthly-date|monthlyday|
weekly) #REQUIRED>
<!ATTLIST Schedule interval CDATA #REQUIRED>
<!-- the earliest date to generate the report on in ISO 8601
format, YYYYMMDDTHHMMSSsss, such as: 19981231T00000000 -->
<!ATTLIST Schedule start CDATA #REQUIRED>
<!-- the date after which the schedule is disabled in ISO 8601
format, YYYYMMDDTHHMMSSsss, such as: 19981231T00000000 -->
<!ATTLIST Schedule notValidAfter CDATA #IMPLIED>
<!ELEMENT Delivery (Storage, Email?)>
<!—- See the Email DTD for more details -->
<!ELEMENT Storage (location?)>
<!-- whether to store report on server -->
<!ATTLIST Storage storeOnServer (0|1) "1">
<!-- Directory location to store report in (for non-default storage) --
>
<!ELEMENT location (#PCDATA)>
<!ELEMENT DBExport (credentials?, param*)>
<!-- the db type to export to -->
<!ATTLIST DBExport type CDATA #REQUIRED>
<!ATTLIST DBExport type CDATA #REQUIRED>
<!ELEMENT credentials (#PCDATA)>
<!-- the userid, password and realm attributes should ONLY be used
if a security blob cannot be generated and the data is being
transmitted/stored using external encryption (eg, HTTPS) -->
<!ATTLIST credentials USERID CDATA #IMPLIED>
<!ATTLIST credentials PASSWORD CDATA #IMPLIED>
<!-- DB specific, usually the database name -->
<!ATTLIST credentials realm CDATA #IMPLIED>
<!ELEMENT param (#PCDATA)>
<!-- the name of the parameter -->
<!ATTLIST param name CDATA #REQUIRED>
]>"""

Email_DTD = """
<!--
The sendAs and sendToAclAs attributes are optional, but one of them is required for sending
reports via e-mail. The sendAs attribute is required for sending e-mails to users who are not on
the report access list. The sendToAcl attribute is required for sending e-mails to report access list
members.
E-mails and attachments are sent via the Internet in cleartext and are not encrypted. If you do not
set a valid value for either attribute, the application will save the report but not send it via e-mail. If
you set a valid value for the sendAs attribute but not for the sendToAclAs attribute, the application
will send the report via e-mail to non-access-list members only. If you set a valid value for the
sendToAclAs attribute, the application will send the report via e-mail to access-list members only.
If you set a valid value for both attributes, the application will send reports via e-mail to access-list
members and non-members.
-->
<!DOCTYPE Email [
<!ELEMENT Email (Recipients?, SmtpRelayServer?, Sender?)>
<!-- send as file attachment or zipped file to individuals who are not members of the report access list -->
<!ATTLIST Email sendAs (file|zip) #IMPLIED>
<!-- send to all the authorized users of sites, groups and devices -->
<!ATTLIST Email toAllAuthorized (0|1) "0">
<!-- send to users on the report access listd file or the url -->
<!ATTLIST Email sendToAclAs (file|zip|url) #IMPLIED>
<!ELEMENT Recipients (Recipient*)>
<!ELEMENT Recipient (#PCDATA)>
<!ELEMENT SmtpRelayServer (#PCDATA)>
<!ELEMENT Sender (#PCDATA)>
]>"""

ReportSummary_DTD = """
<!DOCTYPE ReportSummary [
<!ELEMENT ReportSummary EMPTY>
<!-- the id of the generated report -->
<!ATTLIST ReportSummary id CDATA #IMPLIED>
<!-- the report definition (config) id -->
<!ATTLIST ReportSummary cfg-id CDATA #REQUIRED>
<!-- the current status of the report -->
<!ATTLIST ReportSummary status
(Started|Generated|Failed|Aborted|Unknown) #REQUIRED>
<!-- the date and time the report was generated, in ISO 8601
format, YYYYMMDDTHHMMSSsss, such as: 19981231T00000000 -->
<!ATTLIST ReportSummary generated-on CDATA #IMPLIED>
<!-- the URL to use to access the report (not set for database
exports) -->
<!ATTLIST ReportSummary report-URI CDATA #IMPLIED>
]>"""

UserConfig_DTD = """
The current version of the API does not support creating user accounts with custom roles. You
can only create user accounts with preset roles.
If values for allSites and allGroups are false or not specified, you can specify sites and groups
using nested site and group elements.
You cannot change the user name after you create an account.
<!DOCTYPE UserConfig [
<!ELEMENT UserConfig (UserSite|UserGroup)*>
<!-- the id of the user, set to -1 to create a new user -->
<!ATTLIST UserConfig id CDATA #REQUIRED>
<!-- the role of the user -->
<!ATTLIST UserConfig role-name (global-admin|security-manager|siteadmin|
system-admin|user|custom) #REQUIRED>
<!-- the id of the autentication source for the user -->
<!ATTLIST UserConfig authsrcid CDATA #REQUIRED>
<!-- the login name of the user -->
<!ATTLIST UserConfig name CDATA #REQUIRED>
<!-- the full name of the user -->
<!ATTLIST UserConfig fullname CDATA #REQUIRED>
<!-- the email address of the user -->
<!ATTLIST UserConfig email CDATA #IMPLIED>
<!-- new password -->
<!ATTLIST UserConfig password CDATA #IMPLIED>
<!-- 1 to enable this user, 0 to disable -->
<!ATTLIST UserConfig enabled (0|1) #IMPLIED>
<!-- true if the user has access to all sites, false otherwise -->
<!ATTLIST UserConfig allSites (true|false) #IMPLIED>
<!-- true if the user has access to all groups, false otherwise -->
<!ATTLIST UserConfig allGroups (true|false) #IMPLIED>
<!-- See the UserSite DTD for more details -->
<!-- See the UserGroup DTD for more details -->
]>"""

UserSite_DTD = """
<!DOCTYPE Site [
<!-- the id of the site the user is associated with -->
<!ATTLIST Site id CDATA #REQUIRED>
]>"""

UserGroup_DTD = """
<!DOCTYPE Group [
<!-- the id of the group the user is associated with -->
<!ATTLIST Group id CDATA #REQUIRED>
]>"""

UserSummary_DTD = """
<!DOCTYPE UserSummary [
<!-- the id of the user -->
<!ATTLIST UserSummary id CDATA #REQUIRED>
<!-- the source used to authenticate this user -->
<!ATTLIST UserSummary authSource CDATA #REQUIRED>
<!-- the module used to authenticated this user -->
<!ATTLIST UserSummary authModule CDATA #REQUIRED>
<!-- the login name of the user -->
<!ATTLIST UserSummary userName CDATA #REQUIRED>
<!-- the actual name of the user -->
<!ATTLIST UserSummary fullname CDATA #REQUIRED>
<!-- the email address of the user (may be empty) -->
<!ATTLIST UserSummary email CDATA #REQUIRED>
<!-- true if this user is an administrator, false otherwise -->
<!ATTLIST UserSummary administrator (1|0) #REQUIRED>
<!-- true if this user is disabled, false otherwise -->
<!ATTLIST UserSummary disabled (1|0) #REQUIRED>
<!-- true if this user is locked, false otherwise -->
<!ATTLIST UserSummary locked (1|0) #REQUIRED>
<!-- the number of sites this user is allowed to access -->
<!ATTLIST UserSummary siteCount CDATA #REQUIRED>
<!-- the number of groups this user belongs to -->
<!ATTLIST UserSummary groupCount CDATA #REQUIRED>
]>"""

AuthenticatorSummary_DTD = """
<!DOCTYPE AuthenticatorSummary [
<!ELEMENT AuthenticatorSummary EMPTY>
<!-- the id of the authenticator -->
<!ATTLIST AuthenticatorSummary id CDATA #REQUIRED>
<!-- true if this authenticator authenticates using an external
source,
false otherwise -->
<!ATTLIST AuthenticatorSummary external (0|1) #REQUIRED>
<!-- the name of the authenticator source -->
<!ATTLIST AuthenticatorSummary authSource CDATA #REQUIRED>
<!-- the name of the authenticator module -->
<!ATTLIST AuthenticatorSummary authModule CDATA #REQUIRED>
]>"""

XMLResponse_DTD = """
<!DOCTYPE XMLResponse [
<!-- This element makes sure that valid XML is returned when an error
occurs. -->
<!ELEMENT XMLResponse (Failure)>
<!-- This attribute will always return 0 since it represents some
kind of failure in the request or the response. -->
<!ATTLIST XMLResponse success "0">
]>"""

Failure_DTD = """
<!DOCTYPE Failure [
<!-- The failure description, consisting of one or more message and/or
exception -->
<!ELEMENT Failure ((message|Exception)*)>
<!-- the message describing the failure -->
<!ELEMENT message (#PCDATA)>
<!-- the source of the message, such as the module that caused the
error -->
<!ATTLIST message source CDATA #IMPLIED>
<!-- the source specific message code -->
<!ATTLIST message code CDATA #IMPLIED>
<!-- the exception causing the failure -->
<!ELEMENT Exception (message, stacktrace?)>
<!-- the name of the Exception class (for Java or C++ exceptions) -
->
<!ATTLIST Exception name CDATA #IMPLIED>
<!ELEMENT stacktrace (#PCDATA)>
]>"""
