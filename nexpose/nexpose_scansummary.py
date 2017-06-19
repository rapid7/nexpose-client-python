from xml_utils import get_attribute, get_element, get_content_of

class VulnerabilityStatus:
	vuln_exploit = 'vuln-exploit'
	vuln_version = 'vuln-version'
	vuln_potential = 'vuln-potential'
	not_vuln_exploit = 'not-vuln-exploit'
	not_vuln_version = 'not-vuln-version'
	error = 'error'
	disabled = 'disabled'
	other = 'other'


class ScanSummaryVulnerability:
	@staticmethod
	def CreateFromXML(xml_data):
		vulnerability = ScanSummaryVulnerability()
		vulnerability.status = get_attribute(xml_data, 'status', vulnerability.status)
		vulnerability.severity = int(get_attribute(xml_data, 'severity', vulnerability.severity))
		vulnerability.count = int(get_attribute(xml_data, 'count', vulnerability.count))
		return vulnerability
	
	def __init__(self):
		self.status = ''
		self.severity = 0
		self.count = 0		


class ScanSummaryTaskCounts:
	@staticmethod
	def CreateFromXML(xml_data):
		task_counts = ScanSummaryTaskCounts()
		task_counts.pending = int(get_attribute(xml_data, 'pending', task_counts.pending))
		task_counts.active = int(get_attribute(xml_data, 'active', task_counts.active))
		task_counts.completed = int(get_attribute(xml_data, 'completed', task_counts.completed))
		return task_counts
	
	def __init__(self):
		self.pending = 0
		self.active = 0
		self.completed = 0		


class ScanSummaryNodeCounts:
	@staticmethod
	def CreateFromXML(xml_data):
		node_counts = ScanSummaryNodeCounts()
		node_counts.live = int(get_attribute(xml_data, 'live', '0'))
		node_counts.dead = int(get_attribute(xml_data, 'dead', '0'))
		node_counts.filtered = int(get_attribute(xml_data, 'filtered', '0'))
		node_counts.unresolved = int(get_attribute(xml_data, 'unresolved', '0'))
		node_counts.other = int(get_attribute(xml_data, 'other', '0'))
		return node_counts
	
	def __init__(self):
		self.live = 0
		self.dead = 0
		self.filtered = 0
		self.unresolved = 0
		self.other = 0


class ScanStatus:
	Running = 'running'
	Finished = 'finished'
	Stopped = 'stopped'
	Error = 'error'
	Dispatched = 'dispatched'
	Paused = 'paused'
	Aborted = 'aborted'
	Unknown = 'unknown'


class ScanSummary:
	@staticmethod
	def CreateFromXML(xml_data):
		summary = ScanSummary()
		summary.id = int(get_attribute(xml_data, 'scan-id', summary.id))
		summary.site_id = int(get_attribute(xml_data, 'site-id', summary.site_id))
		summary.engine_id = int(get_attribute(xml_data, 'engine-id', summary.engine_id))
		summary.scan_status = get_attribute(xml_data, 'status', summary.scan_status)
		summary.start_time = get_attribute(xml_data, 'startTime', summary.start_time)
		summary.end_time = get_attribute(xml_data, 'endTime', summary.end_time)
		summary.name = get_attribute(xml_data, 'name', summary.name)
		if get_content_of(xml_data, 'message') is not None:
			summary.message = get_content_of(xml_data, 'message', summary.message)
		else:
			summary.message = get_content_of(xml_data, 'Message', summary.message)
		if get_element(xml_data, 'tasks') is not None:
			summary.task_counts = ScanSummaryTaskCounts.CreateFromXML(get_element(xml_data, 'tasks', summary.task_counts))
		else:
			summary.task_counts = ScanSummaryTaskCounts.CreateFromXML(get_element(xml_data, 'TaskSummary', summary.task_counts))
		if get_element(xml_data, 'nodes') is not None:
			summary.node_counts = ScanSummaryNodeCounts.CreateFromXML(get_element(xml_data, 'nodes', summary.node_counts))
		else:
			summary.node_counts = ScanSummaryNodeCounts.CreateFromXML(get_element(xml_data, 'NodeSummary', summary.node_counts))
		if get_element(xml_data, 'vulnerabilities') is not None:
			summary.vulnerabilities = map(ScanSummaryVulnerability.CreateFromXML, xml_data.findall('vulnerabilities'))
		else:
			summary.vulnerabilities = map(ScanSummaryVulnerability.CreateFromXML, xml_data.findall('VulnerabilitySummary'))
		return summary

	def __init__(self):
		self.id = 0
		self.site_id = 0
		self.engine_id = 0
		self.scan_status = ''
		self.start_time = ''
		self.end_time = ''
		self.name = ''
		self.message = ''
		self.task_counts = None
		self.node_counts = None
		self.vulnerabilities = []
