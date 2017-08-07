# TODO: decide wether or not to use this class (currently unused)
class NexposeXmlFixtures:
	LoginRequest = '<LoginRequest user-id="nxadmin" password="nxadmin" />'
	LoginResponse = '<LoginResponse success="1" sessionid="0DA2FE1D69917350BC15B43A60A2F217D77CF523" />'
	LogoutRequest = '<LogoutRequest session-id="0DA2FE1D69917350BC15B43A60A2F217D77CF523" />
	LogoutResponse = '<LogoutResponse success="1" />'