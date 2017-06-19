from nexpose_criteria_operators import *
from nexpose_criteria_constants import *

def xrange_inclusive(start, included_stop):
	return xrange(start, included_stop + 1)

class NexposeCriteriaField:
	_Code = None
	ValidOperators = [] # Note: this list shouldn't be empty
	ValidValues = None  # None indicates that any value is accepted
	
	class __metaclass__(type):
		@property
		def Code(cls):
			return cls._Code if cls._Code else cls.Name
		
		@property
		def Name(cls):
			return cls.__name__
		
		def __str__(cls):
			return cls.Name

class ASSET(NexposeCriteriaField):
	ValidOperators = (IS, IS_NOT, STARTS_WITH, ENDS_WITH, CONTAINS, NOT_CONTAINS)

class CVE_ID(NexposeCriteriaField):
	ValidOperators = (IS, IS_NOT, CONTAINS, NOT_CONTAINS)

class CVSS_ACCESS_COMPLEXITY(NexposeCriteriaField):
	ValidOperators = (IS, IS_NOT)
	ValidValues = ('LOW', 'MEDIUM', 'HIGH') # See Value::AccessComplexity?

class CVSS_ACCESS_VECTOR(NexposeCriteriaField):
	ValidOperators = (IS, IS_NOT)
	ValidValues = ('LOCAL', 'ADJACENT', 'NETWORK') # See Value::AccessVector?

class CVSS_AUTHENTICATION_REQUIRED(NexposeCriteriaField):
	ValidOperators = (IS, IS_NOT)
	ValidValues = ('NONE', 'SINGLE', 'MULTIPLE') # See Value::AuthenticationRequired?

class CVSS_AVAILABILITY_IMPACT(NexposeCriteriaField):
	ValidOperators = (IS, IS_NOT)
	ValidValues = ('NONE', 'PARTIAL', 'COMPLETE') # See Value::CVSSImpact?

# TODO: duplication with CVSS_AVAILABILITY_IMPACT
class CVSS_CONFIDENTIALITY_IMPACT(NexposeCriteriaField):
	ValidOperators = (IS, IS_NOT)
	ValidValues = ('NONE', 'PARTIAL', 'COMPLETE') # See Value::CVSSImpact?

# TODO: duplication with CVSS_AVAILABILITY_IMPACT
class CVSS_INTEGRITY_IMPACT(NexposeCriteriaField):
	ValidOperators = (IS, IS_NOT)
	ValidValues = ('NONE', 'PARTIAL', 'COMPLETE') # See Value::CVSSImpact?

class CVSS_SCORE(NexposeCriteriaField):
	ValidOperators = (IS, IS_NOT, IN_RANGE, GREATER_THAN, LESS_THAN)
	ValidValues = xrange_inclusive(0, 10) # TODO: are integers accepted or must they really be floats ? 

class CVSS_SCORE(NexposeCriteriaField):
	ValidOperators = (IN, NOT_IN)
	ValidValues = ('UNKNOWN', 'VIRTUAL', 'HYPERVISOR', 'BARE_METAL') # See Value::HostType?

class IP_ADDRESS_TYPE(NexposeCriteriaField):
	ValidOperators = (IN, NOT_IN)
	ValidValues = ('IPv4', 'IPv6') # See Value::IPType?

# TODO: duplication with IP_ADDRESS_TYPE
class IP_ALT_ADDRESS_TYPE(NexposeCriteriaField):
	ValidOperators = (IN, NOT_IN)
	ValidValues = ('IPv4', 'IPv6') # See Value::IPType?

class IP_RANGE(NexposeCriteriaField):
	ValidOperators = (IS, IS_NOT, IN, NOT_IN)

class OPEN_PORT(NexposeCriteriaField):
	ValidOperators = (IS, IS_NOT, IN_RANGE)
	ValidValues = xrange_inclusive(1, 65535)

class OS(NexposeCriteriaField):
	ValidOperators = (CONTAINS, NOT_CONTAINS, IS_EMPTY, IS_NOT_EMPTY)

class PCI_COMPLIANCE_STATUS(NexposeCriteriaField):
	ValidOperators = (IS,)
	ValidValues = ('PASS', 'FAIL')

class RISK_SCORE(NexposeCriteriaField):
	ValidOperators = (IS, IS_NOT, IN_RANGE, GREATER_THAN, LESS_THAN)

class SCAN_DATE(NexposeCriteriaField):
	ValidOperators = (ON_OR_BEFORE, ON_OR_AFTER, BETWEEN, EARLIER_THAN, WITHIN_THE_LAST)
	#ValueValues = FixNum for day arguments && Value::ScanDate::FORMAT for date arguments

class SERVICE(NexposeCriteriaField):
	ValidOperators = (CONTAINS, NOT_CONTAINS)

class SITE_ID(NexposeCriteriaField):
	_Code = 'SITE_NAME' # Note that underlying search uses Site ID, despite 'site name' value.
	ValidOperators = (IN, NOT_IN)

class SOFTWARE(NexposeCriteriaField):
	ValidOperators = (CONTAINS, NOT_CONTAINS)

class TAG_CRITICALITY(NexposeCriteriaField):
	ValidOperators = (IS, IS_NOT, GREATER_THAN, LESS_THAN, IS_APPLIED,	IS_NOT_APPLIED)
	ValidValues = ('Very High', 'High', 'Medium', 'Low', 'Very Low')

class USER_ADDED_CRITICALITY_LEVEL(TAG_CRITICALITY): # Added to be compatible with Rapid7's Nexpose Ruby API
	_Code = 'TAG_CRITICALITY'

class TAG(NexposeCriteriaField):
	ValidOperators = (IS, IS_NOT, STARTS_WITH, ENDS_WITH, IS_APPLIED, IS_NOT_APPLIED, CONTAINS, NOT_CONTAINS)

class USER_ADDED_CUSTOM_TAG(TAG): # Added to be compatible with Rapid7's Nexpose Ruby API
	_Code = 'TAG'

class TAG_LOCATION(NexposeCriteriaField):
	ValidOperators = (IS, IS_NOT, STARTS_WITH, ENDS_WITH, IS_APPLIED, IS_NOT_APPLIED, CONTAINS, NOT_CONTAINS)

class USER_ADDED_TAG_LOCATION(TAG_LOCATION): # Added to be compatible with Rapid7's Nexpose Ruby API
	_Code = 'TAG_LOCATION'

class TAG_OWNER(NexposeCriteriaField):
	ValidOperators = (IS, IS_NOT, STARTS_WITH, ENDS_WITH, IS_APPLIED, IS_NOT_APPLIED, CONTAINS, NOT_CONTAINS)

class USER_ADDED_TAG_OWNER(TAG_OWNER): # Added to be compatible with Rapid7's Nexpose Ruby API
	_Code = 'TAG_OWNER'

class VULNERABILITY_VALIDATED_STATUS(NexposeCriteriaField):
	ValidOperators = (ARE,)
	ValidValues = ('PRESENT', 'NOT_PRESENT')

class VALIDATED_VULNERABILITIES(VULNERABILITY_VALIDATED_STATUS): # Added to be compatible with Rapid7's Nexpose Ruby API
	_Code = 'VULNERABILITY_VALIDATED_STATUS'

class VULNERABILITY(NexposeCriteriaField):
	ValidOperators = (CONTAINS, NOT_CONTAINS)

class VULNERABILITY_EXPOSURES(NexposeCriteriaField):
	ValidOperators = (INCLUDE, DO_NOT_INCLUDE)
	ValidValues = ('MALWARE', 'METASPLOIT', 'DATABASE') # See Value::VulnerabilityExposure?

class VULN_CATEGORY(NexposeCriteriaField):
	ValidOperators = (IS, IS_NOT, CONTAINS, NOT_CONTAINS, STARTS_WITH,	ENDS_WITH)

class VULNERABILITY_CATEGORY(VULN_CATEGORY): # Added to be compatible with Rapid7's Nexpose Ruby API
	_Code = 'VULN_CATEGORY'
