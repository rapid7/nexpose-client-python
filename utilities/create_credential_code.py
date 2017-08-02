# Future Imports for py2 backwards compatibility
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from os import path

# Mapping of Common Service Ports.
DEFAULT_SERVICE_PORTS = {
	'cvs': 2401,
	'ftp': 21,
	'http': 80,
	'as400': 449,
	'notes': 1352,
	'tds': 1433,
	'sybase': 5000,
	'cifs': 445,
	'cifshash': 445,
	'oracle': 1521,
	'pop': 110,
	'postgresql': 5432,
	'remote execution': 512,
	'snmp': 161,
	'snmpv3': 161,
	'ssh': 22,
	'ssh-key': 22,
	'telnet': 23,
	'mysql': 3306,
	'db2': 50000,
}

# TODO: require a session to extract this information from a live server
data = """
{
	"nexpose": {
		"descriptor": [{
			"name": "privilegeelevationpassword",
			"properties": ["SECRET"]
		},
		{
			"name": "ntlmhash",
			"properties": ["SECRET"]
		},
		{
			"name": "password",
			"properties": ["SECRET"]
		},
		{
			"name": "snmpv3privpassword",
			"properties": ["SECRET"]
		},
		{
			"name": "snmpv3privtype",
			"properties": []
		},
		{
			"name": "domain",
			"properties": []
		},
		{
			"name": "username",
			"properties": []
		},
		{
			"name": "privilegeelevationusername",
			"properties": []
		},
		{
			"name": "pemkey",
			"properties": ["SECRET"]
		},
		{
			"name": "snmpv3authtype",
			"properties": []
		},
		{
			"name": "privilegeelevationtype",
			"properties": []
		},
		{
			"name": "database",
			"properties": []
		}],
		"propertydescriptor": ["USEWINDOWSAUTH"],
		"services": {
			"cvs": {
				"fields": [{
					"key": "username",
					"name": "User name",
					"tooltip": "Enter a user name for the account to be authenticated on this service during a scan."
				},
				{
					"key": "password",
					"name": "Password",
					"tooltip": "Enter a password for the account to be authenticated on this service during a scan.",
					"confirm": "Confirm password",
					"confirmTooltip": "Re-enter the password to confirm it."
				}]
			},
			"ftp": {
				"fields": [{
					"key": "username",
					"name": "User name",
					"tooltip": "Enter a user name for the account to be authenticated on this service during a scan."
				},
				{
					"key": "password",
					"name": "Password",
					"tooltip": "Enter a password for the account to be authenticated on this service during a scan.",
					"confirm": "Confirm password",
					"confirmTooltip": "Re-enter the password to confirm it."
				}]
			},
			"http": {
				"fields": [{
					"key": "username",
					"name": "User name",
					"tooltip": "Enter a user name for the account to be authenticated on this service during a scan."
				},
				{
					"key": "password",
					"name": "Password",
					"tooltip": "Enter a password for the account to be authenticated on this service during a scan.",
					"confirm": "Confirm password",
					"confirmTooltip": "Re-enter the password to confirm it."
				},
				{
					"key": "domain",
					"name": "Realm",
					"tooltip": "Enter the name of the domain in which these credentials are valid."
				}]
			},
			"as400": {
				"fields": [{
					"key": "username",
					"name": "User name",
					"tooltip": "Enter a user name for the account to be authenticated on this service during a scan."
				},
				{
					"key": "password",
					"name": "Password",
					"tooltip": "Enter a password for the account to be authenticated on this service during a scan.",
					"confirm": "Confirm password",
					"confirmTooltip": "Re-enter the password to confirm it."
				},
				{
					"key": "domain",
					"name": "Domain",
					"tooltip": "Enter the name of the domain in which these credentials are valid."
				}]
			},
			"notes": {
				"fields": [{
					"key": "password",
					"name": "Notes ID password",
					"tooltip": "Enter the password for the Notes ID to be authenticated on this service during a scan.",
					"confirm": "Confirm Notes ID password",
					"confirmTooltip": "Re-enter the password to confirm it."
				}]
			},
			"tds": {
				"properties": ["USEWINDOWSAUTH"],
				"fields": [{
					"key": "username",
					"name": "User name",
					"tooltip": "Enter a user name for the account to be authenticated on this service during a scan."
				},
				{
					"key": "password",
					"name": "Password",
					"tooltip": "Enter a password for the account to be authenticated on this service during a scan.",
					"confirm": "Confirm password",
					"confirmTooltip": "Re-enter the password to confirm it."
				},
				{
					"key": "domain",
					"name": "Domain",
					"tooltip": "Enter the name of the domain in which these credentials are valid."
				},
				{
					"key": "database",
					"name": "Database",
					"tooltip": "Enter the name of the database on which these credentials are valid."
				}]
			},
			"sybase": {
				"properties": ["USEWINDOWSAUTH"],
				"fields": [{
					"key": "username",
					"name": "User name",
					"tooltip": "Enter a user name for the account to be authenticated on this service during a scan."
				},
				{
					"key": "password",
					"name": "Password",
					"tooltip": "Enter a password for the account to be authenticated on this service during a scan.",
					"confirm": "Confirm password",
					"confirmTooltip": "Re-enter the password to confirm it."
				},
				{
					"key": "domain",
					"name": "Domain",
					"tooltip": "Enter the name of the domain in which these credentials are valid."
				},
				{
					"key": "database",
					"name": "Database",
					"tooltip": "Enter the name of the database on which these credentials are valid."
				}]
			},
			"cifs": {
				"fields": [{
					"key": "username",
					"name": "User name",
					"tooltip": "Enter a user name for the account to be authenticated on this service during a scan."
				},
				{
					"key": "password",
					"name": "Password",
					"tooltip": "Enter a password for the account to be authenticated on this service during a scan.",
					"confirm": "Confirm password",
					"confirmTooltip": "Re-enter the password to confirm it."
				},
				{
					"key": "domain",
					"name": "Domain",
					"tooltip": "Enter the name of the domain in which these credentials are valid."
				}]
			},
			"cifshash": {
				"fields": [{
					"key": "username",
					"name": "User name",
					"tooltip": "Enter a user name for the account to be authenticated on this service during a scan."
				},
				{
					"key": "domain",
					"name": "Domain",
					"tooltip": "Enter the name of the domain in which these credentials are valid."
				},
				{
					"key": "ntlmhash",
					"name": "NTLM hash",
					"tooltip": "Enter an NTLM hash of the form XXX or an LM and NTLM hash separated by a colon (:) in in the form XXX:XXX. In both cases, XXX is a 32-character, hexidecimal hash.",
					"confirm": "Confirm NTLM hash",
					"confirmTooltip": "Re-enter the NTLM hash or LM and NTLM hash for confirmation."
				}]
			},
			"oracle": {
				"fields": [{
					"key": "username",
					"name": "User name",
					"tooltip": "Enter a user name for the account to be authenticated on this service during a scan."
				},
				{
					"key": "password",
					"name": "Password",
					"tooltip": "Enter a password for the account to be authenticated on this service during a scan.",
					"confirm": "Confirm password",
					"confirmTooltip": "Re-enter the password to confirm it."
				},
				{
					"key": "database",
					"name": "SID",
					"tooltip": "Enter the Oracle System ID for the database to be authenticated on during a scan."
				}]
			},
			"pop": {
				"fields": [{
					"key": "username",
					"name": "User name",
					"tooltip": "Enter a user name for the account to be authenticated on this service during a scan."
				},
				{
					"key": "password",
					"name": "Password",
					"tooltip": "Enter a password for the account to be authenticated on this service during a scan.",
					"confirm": "Confirm password",
					"confirmTooltip": "Re-enter the password to confirm it."
				}]
			},
			"postgresql": {
				"fields": [{
					"key": "username",
					"name": "User name",
					"tooltip": "Enter a user name for the account to be authenticated on this service during a scan."
				},
				{
					"key": "password",
					"name": "Password",
					"tooltip": "Enter a password for the account to be authenticated on this service during a scan.",
					"confirm": "Confirm password",
					"confirmTooltip": "Re-enter the password to confirm it."
				},
				{
					"key": "database",
					"name": "Database",
					"tooltip": "Enter the name of the database on which these credentials are valid."
				}]
			},
			"remote execution": {
				"fields": [{
					"key": "username",
					"name": "User name",
					"tooltip": "Enter a user name for the account to be authenticated on this service during a scan."
				},
				{
					"key": "password",
					"name": "Password",
					"tooltip": "Enter a password for the account to be authenticated on this service during a scan.",
					"confirm": "Confirm password",
					"confirmTooltip": "Re-enter the password to confirm it."
				}]
			},
			"snmp": {
				"fields": [{
					"key": "password",
					"name": "Community name",
					"tooltip": "Enter the community name required for authentication on the SNMP server.",
					"confirm": "Confirm community name",
					"confirmTooltip": "Re-enter the community name to confirm it."
				}]
			},
			"snmpv3": {
				"fields": [{
					"key": "username",
					"name": "User name",
					"tooltip": "Enter a user name for the account to be authenticated on this service during a scan."
				},
				{
					"key": "password",
					"name": "Password",
					"tooltip": "Enter the password required for authentication on the SNMP server.",
					"confirm": "Confirm password",
					"confirmTooltip": "Re-enter the password to confirm it."
				},
				{
					"key": "snmpv3authtype",
					"name": "Authentication Type",
					"tooltip": "Select the type of authentication SNMPv3 is using"
				},
				{
					"key": "snmpv3privtype",
					"name": "Privacy Type",
					"tooltip": "Privacy Type"
				},
				{
					"key": "snmpv3privpassword",
					"name": "Privacy password",
					"tooltip": "Enter the privacy password required for authentication on the SNMP server.",
					"confirm": "Confirm privacy password",
					"confirmTooltip": "Re-enter the privacy password to confirm it."
				}]
			},
			"ssh": {
				"privilegeelevationtypes": [{
					"NONE": "none"
				},
				{
					"SUDO": "sudo"
				},
				{
					"SUDOSU": "sudo+su"
				},
				{
					"SU": "su"
				},
				{
					"PBRUN": "pbrun"
				}],
				"fields": [{
					"key": "username",
					"name": "User name",
					"tooltip": "Enter a user name for the account to be authenticated on this service during a scan."
				},
				{
					"key": "password",
					"name": "Password",
					"tooltip": "Enter a password for the account to be authenticated on this service during a scan.",
					"confirm": "Confirm password",
					"confirmTooltip": "Re-enter the password to confirm it."
				},
				{
					"key": "privilegeelevationusername",
					"name": "Permission elevation user name",
					"tooltip": "After being authenticated on the asset, the application will use this user name to obtain elevated access."
				},
				{
					"key": "privilegeelevationpassword",
					"name": "Permission elevation password",
					"tooltip": "After being authenticated on the asset, the application will use this password to obtain elevated access.",
					"confirm": "Confirm permission elevation password",
					"confirmTooltip": "Re-enter the permission elevation password to confirm it."
				},
				{
					"key": "privilegeelevationtype",
					"name": "Permission elevation type",
					"tooltip": "The permission elevation authentication type for the designated scan."
				}]
			},
			"ssh-key": {
				"privilegeelevationtypes": [{
					"NONE": "none"
				},
				{
					"SUDO": "sudo"
				},
				{
					"SUDOSU": "sudo+su"
				},
				{
					"SU": "su"
				},
				{
					"PBRUN": "pbrun"
				}],
				"fields": [{
					"key": "username",
					"name": "User name",
					"tooltip": "Enter a user name for the account to be authenticated on this service during a scan."
				},
				{
					"key": "password",
					"name": "Private key password",
					"tooltip": "Enter the private key password.",
					"confirm": "Confirm private key password",
					"confirmTooltip": "Re-enter the private key password to confirm it."
				},
				{
					"key": "pemkey",
					"name": "PEM-format private key",
					"tooltip": "Enter the PEM-format key for the account to be authenticated on this service during a scan.",
					"confirm": "",
					"confirmTooltip": ""
				},
				{
					"key": "privilegeelevationusername",
					"name": "Permission elevation user name",
					"tooltip": "After being authenticated on the asset, the application will use this user name to obtain elevated access."
				},
				{
					"key": "privilegeelevationpassword",
					"name": "Permission elevation password",
					"tooltip": "After being authenticated on the asset, the application will use this password to obtain elevated access.",
					"confirm": "Confirm permission elevation password",
					"confirmTooltip": "Re-enter the permission elevation password to confirm it."
				},
				{
					"key": "privilegeelevationtype",
					"name": "Permission elevation type",
					"tooltip": "You can select a method to elevate permissions to root or administrator."
				}]
			},
			"telnet": {
				"fields": [{
					"key": "username",
					"name": "User name",
					"tooltip": "Enter a user name for the account to be authenticated on this service during a scan."
				},
				{
					"key": "password",
					"name": "Password",
					"tooltip": "Enter a password for the account to be authenticated on this service during a scan.",
					"confirm": "Confirm password",
					"confirmTooltip": "Re-enter the password to confirm it."
				}]
			},
			"mysql": {
				"fields": [{
					"key": "username",
					"name": "User name",
					"tooltip": "Enter a user name for the account to be authenticated on this service during a scan."
				},
				{
					"key": "password",
					"name": "Password",
					"tooltip": "Enter a password for the account to be authenticated on this service during a scan.",
					"confirm": "Confirm password",
					"confirmTooltip": "Re-enter the password to confirm it."
				},
				{
					"key": "database",
					"name": "Database",
					"tooltip": "Enter the name of the database on which these credentials are valid."
				}]
			},
			"db2": {
				"fields": [{
					"key": "username",
					"name": "User name",
					"tooltip": "Enter a user name for the account to be authenticated on this service during a scan."
				},
				{
					"key": "password",
					"name": "Password",
					"tooltip": "Enter a password for the account to be authenticated on this service during a scan.",
					"confirm": "Confirm password",
					"confirmTooltip": "Re-enter the password to confirm it."
				},
				{
					"key": "database",
					"name": "Database",
					"tooltip": "Enter the name of the database on which these credentials are valid."
				}]
			}
		}
	}
}
"""

import json
data = json.loads(data)

def Capitalize(word):
    word = word.replace('-', '_')    
    if GetLetterType(word[0]) == GetLetterType(word[1]):
        return word.upper()
    if word in ['pop', 'cifs', 'as400']: 
        return word.upper()
    if word == 'remote execution':
        return 'RemoteExecution'
    if word == 'cifshash':
        return 'CIFS_Hash'
    return word.capitalize().replace('sql', 'SQL')

def GetLetterType(letter):
    return letter in ['a', 'e', 'i', 'o', 'u', 'y']

def KeyToName(key):
    key = key.replace('privilegeelevation', 'privilege_elevation_')
    key = key.replace('snmpv3priv', 'snmpv3_private_')
    key = key.replace('snmpv3authtype', 'snmpv3_authentication_type')
    key = key.replace('ntlm', 'ntlm_')
    return key

services = data['nexpose']['services']

print "# Auto-created by '{0}'".format(path.basename(__file__))
print "from xml_utils import create_element, get_content_of"
print "from python_utils import is_subclass_of"
print "import sys"
print
print "def GetSupportedCredentials():"
print "    this_module = sys.modules[__name__]"
print "    credentials = [this_module.__dict__[name] for name in dir(this_module) if is_subclass_of(this_module.__dict__[name], Credential)]"
print "    for credential in credentials:"
print "        if credential.SERVICE_TYPE:"
print "            yield credential"
print
print "class Credential:"
print "    SERVICE_TYPE = None"
print "    DEFAULT_PORT = 0"
print ""
print "    # NOTE: factory method in a base class (not so-clean)"
print "    @staticmethod"
print "    def CreateFromXML(xml, service_type):"
print "        for credential in GetSupportedCredentials():"
print "            if service_type == credential.SERVICE_TYPE:"
print "                return credential.CreateFromXML(xml)"
print "        return None # TODO: raise exception"
print ""
print "    @staticmethod"
print "    def CreateFromType(service_type):"
print "        for credential in GetSupportedCredentials():"
print "            if service_type == credential.SERVICE_TYPE:"
print "                return credential.Create()"
print "        return None # TODO: raise exception"

print

print "def _create_field(key, value):"
print "    field = create_element('Field', {'name': key})"
print "    field.text = value"
print "    return field"

print

print "def _create_field_and_append(xml, key, value):"
print "    xml.append(_create_field(key, value))"

print

ssh_type = None
for service in services:
    print "class Credential_{0}(Credential):".format(Capitalize(service))
    print "    SERVICE_TYPE = '{0}'".format(service)
    print "    DEFAULT_PORT = {0}".format(DEFAULT_SERVICE_PORTS.get(service, 0))
    print ""
    print "    @staticmethod"
    print "    def CreateFromXML(xml):"
    print "        credential = Credential_{0}()".format(Capitalize(service))
    for field in services[service]['fields']:
        key = field['key']
        name = KeyToName(key)
        print "        credential.{0} = get_content_of(xml, \"Field/[@name='{1}']\", credential.{0})".format(name, key)
    print "        return credential"
    print ""
    print "    @staticmethod"
    print "    def Create():"
    print "        credential = Credential_{0}()".format(Capitalize(service))
    print "        credential.id = -1"
    print "        return credential"
    print ""
    print "    def __init__(self):"
    for field in services[service]['fields']:
        key = field['key']
        name = KeyToName(key)
        default_value = "PrivilegeElevationType.NONE" if name == 'privilege_elevation_type' else "''" 
        print "        self.{0} = {1}".format(name, default_value)
    print ""
    print "    def AsXML(self):"
    print "        xml = create_element('Account', {'type': 'nexpose'})"
    for field in services[service]['fields']:
        key = field['key']
        name = KeyToName(key)
        print "        _create_field_and_append(xml, '{0}', self.{1})".format(key, name)
    print "        return xml"
    if not ssh_type:
        ssh_type = services[service].get('privilegeelevationtypes', None)
    print

if ssh_type:
    print "class PrivilegeElevationType:"
    for key_text_pair in ssh_type:
        key, text = key_text_pair.popitem()
        print "    {0} = '{1}' # {2}".format(key, key, text)
