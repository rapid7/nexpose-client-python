# Future Imports for py2 backwards compatibility
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from .context import nexpose
from nexpose import NexposeSession, NexposeConnectionException, as_xml


class NexposeSessionSpy(NexposeSession):
    def __init__(self, host, port, username, password):
        NexposeSession.__init__(self, host, port, username, password)
        self.XmlStringToReturnOnExecute = None

    def GetURI_APIv1d1(self):
        return self._URI_APIv1d1

    def GetLoginRequest(self):
        return self._login_request

    def GetSessionID(self):
        return self._session_id

    def SetSessionID(self, session_id):
        self._session_id = session_id

    def _Execute_Fake(self, request):
        try:
            if self.XmlStringToReturnOnExecute:
                return as_xml(self.XmlStringToReturnOnExecute)
            return request  # return the request as an answer
        except Exception as ex:
            raise NexposeConnectionException("Unable to execute the fake request: {0}!".format(ex), ex)

    def _Execute_APIv1d1(self, request):
        return self._Execute_Fake(request)

    def _Execute_APIv1d2(self, request):  # TODO: write tests that use this function ? TDD ?
        return self._Execute_Fake(request)


class SpyFactory:
    @staticmethod
    def CreateEmpty():
        return NexposeSessionSpy(host="", port=0, username="", password="")

    @staticmethod
    def CreateWithDefaultLogin(host, port=3780):
        return NexposeSessionSpy(host, port, "nxadmin", "nxpassword")

    @staticmethod
    def CreateOpenSession(session_id):
        session = SpyFactory.CreateEmpty()
        session.SetSessionID(session_id)
        return session
