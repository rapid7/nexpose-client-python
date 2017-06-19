# Auto-created by 'create_credential_code.py'
from xml_utils import create_element, get_content_of
from python_utils import is_subclass_of
import sys

def GetSupportedCredentials():
    this_module = sys.modules[__name__]
    credentials = [this_module.__dict__[name] for name in dir(this_module) if is_subclass_of(this_module.__dict__[name], Credential)]
    for credential in credentials:
        if credential.SERVICE_TYPE:
            yield credential

class Credential:
    SERVICE_TYPE = None
    DEFAULT_PORT = 0

    # NOTE: factory method in a base class (not so-clean)
    @staticmethod
    def CreateFromXML(xml, service_type):
        for credential in GetSupportedCredentials():
            if service_type == credential.SERVICE_TYPE:
                return credential.CreateFromXML(xml)
        return None # TODO: raise exception

    @staticmethod
    def CreateFromType(service_type):
        for credential in GetSupportedCredentials():
            if service_type == credential.SERVICE_TYPE:
                return credential.Create()
        return None # TODO: raise exception

def _create_field(key, value):
    field = create_element('Field', {'name': key})
    field.text = value
    return field

def _create_field_and_append(xml, key, value):
    xml.append(_create_field(key, value))

class Credential_RemoteExecution(Credential):
    SERVICE_TYPE = 'remote execution'
    DEFAULT_PORT = 512

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_RemoteExecution()
        credential.username = get_content_of(xml, "Field/[@name='username']", credential.username)
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        return credential

    @staticmethod
    def Create():
        credential = Credential_RemoteExecution()
        credential.id = -1
        return credential

    def __init__(self):
        self.username = ''
        self.password = ''

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'username', self.username)
        _create_field_and_append(xml, 'password', self.password)
        return xml

class Credential_FTP(Credential):
    SERVICE_TYPE = 'ftp'
    DEFAULT_PORT = 21

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_FTP()
        credential.username = get_content_of(xml, "Field/[@name='username']", credential.username)
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        return credential

    @staticmethod
    def Create():
        credential = Credential_FTP()
        credential.id = -1
        return credential

    def __init__(self):
        self.username = ''
        self.password = ''

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'username', self.username)
        _create_field_and_append(xml, 'password', self.password)
        return xml

class Credential_SSH_KEY(Credential):
    SERVICE_TYPE = 'ssh-key'
    DEFAULT_PORT = 22

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_SSH_KEY()
        credential.username = get_content_of(xml, "Field/[@name='username']", credential.username)
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        credential.pemkey = get_content_of(xml, "Field/[@name='pemkey']", credential.pemkey)
        credential.privilege_elevation_username = get_content_of(xml, "Field/[@name='privilegeelevationusername']", credential.privilege_elevation_username)
        credential.privilege_elevation_password = get_content_of(xml, "Field/[@name='privilegeelevationpassword']", credential.privilege_elevation_password)
        credential.privilege_elevation_type = get_content_of(xml, "Field/[@name='privilegeelevationtype']", credential.privilege_elevation_type)
        return credential

    @staticmethod
    def Create():
        credential = Credential_SSH_KEY()
        credential.id = -1
        return credential

    def __init__(self):
        self.username = ''
        self.password = ''
        self.pemkey = ''
        self.privilege_elevation_username = ''
        self.privilege_elevation_password = ''
        self.privilege_elevation_type = PrivilegeElevationType.NONE

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'username', self.username)
        _create_field_and_append(xml, 'password', self.password)
        _create_field_and_append(xml, 'pemkey', self.pemkey)
        _create_field_and_append(xml, 'privilegeelevationusername', self.privilege_elevation_username)
        _create_field_and_append(xml, 'privilegeelevationpassword', self.privilege_elevation_password)
        _create_field_and_append(xml, 'privilegeelevationtype', self.privilege_elevation_type)
        return xml

class Credential_HTTP(Credential):
    SERVICE_TYPE = 'http'
    DEFAULT_PORT = 80

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_HTTP()
        credential.username = get_content_of(xml, "Field/[@name='username']", credential.username)
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        credential.domain = get_content_of(xml, "Field/[@name='domain']", credential.domain)
        return credential

    @staticmethod
    def Create():
        credential = Credential_HTTP()
        credential.id = -1
        return credential

    def __init__(self):
        self.username = ''
        self.password = ''
        self.domain = ''

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'username', self.username)
        _create_field_and_append(xml, 'password', self.password)
        _create_field_and_append(xml, 'domain', self.domain)
        return xml

class Credential_CIFS(Credential):
    SERVICE_TYPE = 'cifs'
    DEFAULT_PORT = 445

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_CIFS()
        credential.username = get_content_of(xml, "Field/[@name='username']", credential.username)
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        credential.domain = get_content_of(xml, "Field/[@name='domain']", credential.domain)
        return credential

    @staticmethod
    def Create():
        credential = Credential_CIFS()
        credential.id = -1
        return credential

    def __init__(self):
        self.username = ''
        self.password = ''
        self.domain = ''

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'username', self.username)
        _create_field_and_append(xml, 'password', self.password)
        _create_field_and_append(xml, 'domain', self.domain)
        return xml

class Credential_AS400(Credential):
    SERVICE_TYPE = 'as400'
    DEFAULT_PORT = 449

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_AS400()
        credential.username = get_content_of(xml, "Field/[@name='username']", credential.username)
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        credential.domain = get_content_of(xml, "Field/[@name='domain']", credential.domain)
        return credential

    @staticmethod
    def Create():
        credential = Credential_AS400()
        credential.id = -1
        return credential

    def __init__(self):
        self.username = ''
        self.password = ''
        self.domain = ''

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'username', self.username)
        _create_field_and_append(xml, 'password', self.password)
        _create_field_and_append(xml, 'domain', self.domain)
        return xml

class Credential_Notes(Credential):
    SERVICE_TYPE = 'notes'
    DEFAULT_PORT = 1352

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_Notes()
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        return credential

    @staticmethod
    def Create():
        credential = Credential_Notes()
        credential.id = -1
        return credential

    def __init__(self):
        self.password = ''

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'password', self.password)
        return xml

class Credential_SNMP(Credential):
    SERVICE_TYPE = 'snmp'
    DEFAULT_PORT = 161

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_SNMP()
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        return credential

    @staticmethod
    def Create():
        credential = Credential_SNMP()
        credential.id = -1
        return credential

    def __init__(self):
        self.password = ''

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'password', self.password)
        return xml

class Credential_CVS(Credential):
    SERVICE_TYPE = 'cvs'
    DEFAULT_PORT = 2401

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_CVS()
        credential.username = get_content_of(xml, "Field/[@name='username']", credential.username)
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        return credential

    @staticmethod
    def Create():
        credential = Credential_CVS()
        credential.id = -1
        return credential

    def __init__(self):
        self.username = ''
        self.password = ''

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'username', self.username)
        _create_field_and_append(xml, 'password', self.password)
        return xml

class Credential_POP(Credential):
    SERVICE_TYPE = 'pop'
    DEFAULT_PORT = 110

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_POP()
        credential.username = get_content_of(xml, "Field/[@name='username']", credential.username)
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        return credential

    @staticmethod
    def Create():
        credential = Credential_POP()
        credential.id = -1
        return credential

    def __init__(self):
        self.username = ''
        self.password = ''

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'username', self.username)
        _create_field_and_append(xml, 'password', self.password)
        return xml

class Credential_Sybase(Credential):
    SERVICE_TYPE = 'sybase'
    DEFAULT_PORT = 5000

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_Sybase()
        credential.username = get_content_of(xml, "Field/[@name='username']", credential.username)
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        credential.domain = get_content_of(xml, "Field/[@name='domain']", credential.domain)
        credential.database = get_content_of(xml, "Field/[@name='database']", credential.database)
        return credential

    @staticmethod
    def Create():
        credential = Credential_Sybase()
        credential.id = -1
        return credential

    def __init__(self):
        self.username = ''
        self.password = ''
        self.domain = ''
        self.database = ''

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'username', self.username)
        _create_field_and_append(xml, 'password', self.password)
        _create_field_and_append(xml, 'domain', self.domain)
        _create_field_and_append(xml, 'database', self.database)
        return xml

class Credential_DB2(Credential):
    SERVICE_TYPE = 'db2'
    DEFAULT_PORT = 50000

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_DB2()
        credential.username = get_content_of(xml, "Field/[@name='username']", credential.username)
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        credential.database = get_content_of(xml, "Field/[@name='database']", credential.database)
        return credential

    @staticmethod
    def Create():
        credential = Credential_DB2()
        credential.id = -1
        return credential

    def __init__(self):
        self.username = ''
        self.password = ''
        self.database = ''

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'username', self.username)
        _create_field_and_append(xml, 'password', self.password)
        _create_field_and_append(xml, 'database', self.database)
        return xml

class Credential_Telnet(Credential):
    SERVICE_TYPE = 'telnet'
    DEFAULT_PORT = 23

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_Telnet()
        credential.username = get_content_of(xml, "Field/[@name='username']", credential.username)
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        return credential

    @staticmethod
    def Create():
        credential = Credential_Telnet()
        credential.id = -1
        return credential

    def __init__(self):
        self.username = ''
        self.password = ''

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'username', self.username)
        _create_field_and_append(xml, 'password', self.password)
        return xml

class Credential_Oracle(Credential):
    SERVICE_TYPE = 'oracle'
    DEFAULT_PORT = 1521

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_Oracle()
        credential.username = get_content_of(xml, "Field/[@name='username']", credential.username)
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        credential.database = get_content_of(xml, "Field/[@name='database']", credential.database)
        return credential

    @staticmethod
    def Create():
        credential = Credential_Oracle()
        credential.id = -1
        return credential

    def __init__(self):
        self.username = ''
        self.password = ''
        self.database = ''

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'username', self.username)
        _create_field_and_append(xml, 'password', self.password)
        _create_field_and_append(xml, 'database', self.database)
        return xml

class Credential_MySQL(Credential):
    SERVICE_TYPE = 'mysql'
    DEFAULT_PORT = 3306

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_MySQL()
        credential.username = get_content_of(xml, "Field/[@name='username']", credential.username)
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        credential.database = get_content_of(xml, "Field/[@name='database']", credential.database)
        return credential

    @staticmethod
    def Create():
        credential = Credential_MySQL()
        credential.id = -1
        return credential

    def __init__(self):
        self.username = ''
        self.password = ''
        self.database = ''

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'username', self.username)
        _create_field_and_append(xml, 'password', self.password)
        _create_field_and_append(xml, 'database', self.database)
        return xml

class Credential_TDS(Credential):
    SERVICE_TYPE = 'tds'
    DEFAULT_PORT = 1433

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_TDS()
        credential.username = get_content_of(xml, "Field/[@name='username']", credential.username)
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        credential.domain = get_content_of(xml, "Field/[@name='domain']", credential.domain)
        credential.database = get_content_of(xml, "Field/[@name='database']", credential.database)
        return credential

    @staticmethod
    def Create():
        credential = Credential_TDS()
        credential.id = -1
        return credential

    def __init__(self):
        self.username = ''
        self.password = ''
        self.domain = ''
        self.database = ''

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'username', self.username)
        _create_field_and_append(xml, 'password', self.password)
        _create_field_and_append(xml, 'domain', self.domain)
        _create_field_and_append(xml, 'database', self.database)
        return xml

class Credential_CIFS_Hash(Credential):
    SERVICE_TYPE = 'cifshash'
    DEFAULT_PORT = 445

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_CIFS_Hash()
        credential.username = get_content_of(xml, "Field/[@name='username']", credential.username)
        credential.domain = get_content_of(xml, "Field/[@name='domain']", credential.domain)
        credential.ntlm_hash = get_content_of(xml, "Field/[@name='ntlmhash']", credential.ntlm_hash)
        return credential

    @staticmethod
    def Create():
        credential = Credential_CIFS_Hash()
        credential.id = -1
        return credential

    def __init__(self):
        self.username = ''
        self.domain = ''
        self.ntlm_hash = ''

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'username', self.username)
        _create_field_and_append(xml, 'domain', self.domain)
        _create_field_and_append(xml, 'ntlmhash', self.ntlm_hash)
        return xml

class Credential_PostgreSQL(Credential):
    SERVICE_TYPE = 'postgresql'
    DEFAULT_PORT = 5432

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_PostgreSQL()
        credential.username = get_content_of(xml, "Field/[@name='username']", credential.username)
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        credential.database = get_content_of(xml, "Field/[@name='database']", credential.database)
        return credential

    @staticmethod
    def Create():
        credential = Credential_PostgreSQL()
        credential.id = -1
        return credential

    def __init__(self):
        self.username = ''
        self.password = ''
        self.database = ''

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'username', self.username)
        _create_field_and_append(xml, 'password', self.password)
        _create_field_and_append(xml, 'database', self.database)
        return xml

class Credential_SSH(Credential):
    SERVICE_TYPE = 'ssh'
    DEFAULT_PORT = 22

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_SSH()
        credential.username = get_content_of(xml, "Field/[@name='username']", credential.username)
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        credential.privilege_elevation_username = get_content_of(xml, "Field/[@name='privilegeelevationusername']", credential.privilege_elevation_username)
        credential.privilege_elevation_password = get_content_of(xml, "Field/[@name='privilegeelevationpassword']", credential.privilege_elevation_password)
        credential.privilege_elevation_type = get_content_of(xml, "Field/[@name='privilegeelevationtype']", credential.privilege_elevation_type)
        return credential

    @staticmethod
    def Create():
        credential = Credential_SSH()
        credential.id = -1
        return credential

    def __init__(self):
        self.username = ''
        self.password = ''
        self.privilege_elevation_username = ''
        self.privilege_elevation_password = ''
        self.privilege_elevation_type = PrivilegeElevationType.NONE

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'username', self.username)
        _create_field_and_append(xml, 'password', self.password)
        _create_field_and_append(xml, 'privilegeelevationusername', self.privilege_elevation_username)
        _create_field_and_append(xml, 'privilegeelevationpassword', self.privilege_elevation_password)
        _create_field_and_append(xml, 'privilegeelevationtype', self.privilege_elevation_type)
        return xml

class Credential_SNMPV3(Credential):
    SERVICE_TYPE = 'snmpv3'
    DEFAULT_PORT = 161

    @staticmethod
    def CreateFromXML(xml):
        credential = Credential_SNMPV3()
        credential.username = get_content_of(xml, "Field/[@name='username']", credential.username)
        credential.password = get_content_of(xml, "Field/[@name='password']", credential.password)
        credential.snmpv3_authentication_type = get_content_of(xml, "Field/[@name='snmpv3authtype']", credential.snmpv3_authentication_type)
        credential.snmpv3_private_type = get_content_of(xml, "Field/[@name='snmpv3privtype']", credential.snmpv3_private_type)
        credential.snmpv3_private_password = get_content_of(xml, "Field/[@name='snmpv3privpassword']", credential.snmpv3_private_password)
        return credential

    @staticmethod
    def Create():
        credential = Credential_SNMPV3()
        credential.id = -1
        return credential

    def __init__(self):
        self.username = ''
        self.password = ''
        self.snmpv3_authentication_type = ''
        self.snmpv3_private_type = ''
        self.snmpv3_private_password = ''

    def AsXML(self):
        xml = create_element('Account', {'type': 'nexpose'})
        _create_field_and_append(xml, 'username', self.username)
        _create_field_and_append(xml, 'password', self.password)
        _create_field_and_append(xml, 'snmpv3authtype', self.snmpv3_authentication_type)
        _create_field_and_append(xml, 'snmpv3privtype', self.snmpv3_private_type)
        _create_field_and_append(xml, 'snmpv3privpassword', self.snmpv3_private_password)
        return xml

class PrivilegeElevationType:
    NONE = 'NONE' # none
    SUDO = 'SUDO' # sudo
    SUDOSU = 'SUDOSU' # sudo+su
    SU = 'SU' # su
    PBRUN = 'PBRUN' # pbrun
