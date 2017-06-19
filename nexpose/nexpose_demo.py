from nexpose import OpenNexposeSession, NexposeTag, as_string
import json

def output(response):
	print as_string(response)
	
import httplib
httplib.HTTPConnection._http_vsn = 10
httplib.HTTPConnection._http_vsn_str = 'HTTP/1.0'


host = "localhost"
port = 0
username = "nxadmin"
password = "nxpassword"

session = OpenNexposeSession(host, port, username, password)

tags = session.RequestTagListing()[-1:]
for tag in tags:
	l_id = tag.id
	print tag.id, tag.name.encode('ascii', 'xmlcharrefreplace')
	for attr in tag.attributes:
		print "  ", attr.id, attr.name, attr.value
	assert tag.name == u"ÇçĞğİıÖöŞşÜü"

sites = session.RequestSiteListing()
#output(sites)
for site_id in range(1,1+1): # sites.xpath("/SiteListingResponse/SiteSummary/@id"):
	#output(session.RequestSiteDeviceListing(site_id))
	#output(session.RequestSiteScanHistory(site_id))
	#json_as_dict = json.loads(session.RequestTags())
	#tag = NexposeTag()
	#tag.id = 0
	#tag.type = "CUSTOM"
	#tag.name += "?"
	#tag.id = None
	#print tag.as_json()
	print session.RemoveTagFromSite(l_id, site_id)
	print session.AddTagToSite(l_id, site_id)
#output(session.RequestSystemInformation())

for tag in session.RequestAssetTagListing(2):
	print tag.id, tag.name.encode('ascii', 'xmlcharrefreplace')
