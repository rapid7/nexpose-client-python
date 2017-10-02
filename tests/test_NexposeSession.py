# Future Imports for py2/3 backwards compat.
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from .load_unittest import unittest
from nexpose.nexpose import NexposeFailureException, NexposeException, SessionIsNotClosedException
from nexpose.xml_utils import as_string, as_xml
from .NexposeSessionSpy import NexposeSessionSpy, SpyFactory
from future import standard_library
standard_library.install_aliases()

FAKE_SESSIONID = "B33R"
FAKE_SITEID = 201

# hackish
SpyFactory_CreateOpenSession = SpyFactory.CreateOpenSession
SpyFactory.CreateOpenSession = staticmethod(lambda: SpyFactory_CreateOpenSession(FAKE_SESSIONID))


class NexposeSessionTestCase(unittest.TestCase):
    def assertEqualXml(self, xml_object, xml_string):
        self.assertEqual(as_string(xml_object), as_string(as_xml(xml_string)))

    def testDefaultConstructionOfURI_APIv1d1(self):
        expected_uri = "https://localhost:3780/api/1.1/xml"
        session = SpyFactory.CreateEmpty()
        self.assertEqual(session.GetURI_APIv1d1(), expected_uri)

    def testConstructionOfURI_APIv1d1(self):
        expected_uri = "https://nexpose.davansilabs.local:666/api/1.1/xml"
        session = SpyFactory.CreateWithDefaultLogin("nexpose.davansilabs.local", 666)
        self.assertEqual(session.GetURI_APIv1d1(), expected_uri)

    def testConstructionOfLoginRequest(self):
        expected_request = [b'<LoginRequest user-id="nxadmin" password="nxpassword"/>', b'<LoginRequest password="nxpassword" user-id="nxadmin"/>']
        session = SpyFactory.CreateWithDefaultLogin("server")
        self.assertIn(as_string(session.GetLoginRequest()), expected_request)

    def testCorrectLogin(self):
        session = SpyFactory.CreateWithDefaultLogin('*')
        session.XmlStringToReturnOnExecute = '<LoginResponse success="1" session-id="{0}" />'.format(FAKE_SESSIONID)
        session.Open()
        self.assertEqual(session.GetSessionID(), FAKE_SESSIONID)

    def testIncorrectLogin(self):
        session = SpyFactory.CreateWithDefaultLogin('*')
        session.XmlStringToReturnOnExecute = '<LoginResponse success="0" session-id="{0}" />'.format(FAKE_SESSIONID)
        self.assertEqual(session.GetSessionID(), None)
        self.assertRaises(NexposeFailureException, session.Open)
        self.assertNotEqual(session.GetSessionID(), FAKE_SESSIONID)

    def testLoginWithInvalidHtmlReply(self):
        session = SpyFactory.CreateWithDefaultLogin('*')
        session.XmlStringToReturnOnExecute = '<html><!-- Example: <div class="MainContent"><h1>An error was encountered processing your request.</h1><p><b>Source page:</b>api/1.1/xml</p><p><b>Error code:</b> 403</p><p><b>Error message:</b> The API is not supported by this product edition.</p></div></html>'.format(FAKE_SESSIONID)
        self.assertRaises(NexposeException, session.Open)

    def testShouldNotLoginIfSessionIsOpen(self):
        session = SpyFactory.CreateOpenSession()
        self.assertRaises(SessionIsNotClosedException, session.Open)

    def testRequestSiteListing(self):
        expected_request = '<SiteListingRequest session-id="{0}" />'.format(FAKE_SESSIONID)
        session = SpyFactory.CreateOpenSession()
        self.assertEqualXml(session.RequestSiteListing(), expected_request)

    def testRequestSiteDeviceListing(self):
        expected_request = '<SiteDeviceListingRequest site-id="{1}" session-id="{0}" />'.format(FAKE_SESSIONID, FAKE_SITEID)
        session = SpyFactory.CreateOpenSession()
        self.assertEqualXml(session.RequestSiteDeviceListing(FAKE_SITEID), expected_request)

    def testRequestSiteScanHistory(self):
        expected_request = '<SiteScanHistoryRequest site-id="{1}" session-id="{0}" />'.format(FAKE_SESSIONID, FAKE_SITEID)
        session = SpyFactory.CreateOpenSession()
        self.assertEqualXml(session.RequestSiteScanHistory(FAKE_SITEID), expected_request)

    def testRequestSystemInformation(self):
        expected_request = '<SystemInformationRequest session-id="{0}" />'.format(FAKE_SESSIONID)
        session = SpyFactory.CreateOpenSession()
        self.assertEqualXml(session.RequestSystemInformation(), expected_request)
