from json_utils import JSON
from nexpose_criteria import Criteria, Criterion
from nexpose_asset import AssetBase
import json

class FilteredAsset(AssetBase, JSON):
	@staticmethod
	def CreateFromJSON(json_dict):
		asset = FilteredAsset()
		asset.id = json_dict['assetID']
		asset.risk_score = json_dict['riskScore']
		
		asset.assessed = json_dict['assessed']
		asset.malware_count = json_dict['malwareCount']
		asset.vulnerability_count = json_dict['vulnCount']
		asset.exploit_count = json_dict['exploitCount']
		asset.asset_name = json_dict['assetName'] # TODO: could be 'host' from AssetSummary ?
		asset.os_id = json_dict['assetOSID']
		
		# see also AssetSummary
		asset.site_id = json_dict['sitePermissions'][0]['siteID']
		
		# see also AssetDetails
		asset.os_name = json_dict['assetOSName']
		asset.ip_address = json_dict['assetIP']
		asset.lastScanDate = json_dict['lastScanDate'] # TODO: convert to Date object ?
		
		# Replace JSON-nulls by empty strings
		if asset.os_name == None: asset.os_name = ''
		if asset.asset_name == None: asset.asset_name = ''
		
		return asset
	
	def __init__(self):
		AssetBase.__init__(self)

		self.assessed = False
		self.malware_count = 0
		self.vulnerability_count = 0
		self.exploit_count = 0
		self.asset_name = '' # TODO: could be 'host' from AssetSummary ?
		self.os_id = 0
		
		# see also AssetSummary
		self.site_id = 0
		
		# see also AssetDetails		
		self.os_name = None
		self.ip_address = ''
		self.last_scan_date = ''

class AssetFilter(JSON):
	def __init__(self, criteria_or_criterion):
		if isinstance(criteria_or_criterion, Criterion):
			criteria_or_criterion = Criteria.Create(criteria_or_criterion)
		assert isinstance(criteria_or_criterion, Criteria)
		self.criteria = criteria_or_criterion
	
	def as_json(self):
		js = dict()
		js['dir'] = 'ASC'
		js['sort'] = 'assetIP' # why can't we sort on ID?
		js['table-id'] = 'assetfilter'
		js['searchCriteria'] = json.dumps(self.criteria.as_json(), separators=(',', ':'))
		return js
