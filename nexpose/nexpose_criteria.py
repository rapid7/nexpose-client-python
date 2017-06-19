import sys
_current_module = sys.modules[__name__]

from json_utils import JSON
from nexpose_criteria_fields import * # this will also import the operators and the constants
_all_uppercase_names = [name for name in dir(_current_module) if name.isupper()]

from python_utils import is_iterable, is_subclass_of

def _get_by_name(name):
	return _current_module.__dict__[name]

def _get_filtered_classes(required_class):
	_all_uppercase_variables = map(lambda name: _get_by_name(name), _all_uppercase_names)
	return filter(lambda variable: is_subclass_of(variable, required_class), _all_uppercase_variables)

def GetFields():
	"""Returns a list of supported field by Nexpose Criteria"""
	return _get_filtered_classes(NexposeCriteriaField)

def GetFieldNames():
	"""Returns a list of supported field names by Nexpose Criteria"""
	return map(lambda field: field.Name, _get_filtered_classes(NexposeCriteriaField))

def GetFieldByName(name):
	"""Gets a field (object) by name.
	   Raises a LookupError if no field with the specified name exists."""
	if not name in GetFieldNames():
		raise LookupError("Criteria Field with name {0} not found!".format(name))
	return _get_by_name(name)

def GetOperators():
	"""Returns a list of supported operators by Nexpose Criteria"""
	return _get_filtered_classes(NexposeCriteriaOperator)
	
def GetOperatorCodes():
	"""Returns a list of supported operator codes by Nexpose Criteria"""
	return map(lambda operator: operator.Code, _get_filtered_classes(NexposeCriteriaOperator))

def GetOperatorByCode(code):
	"""Gets a operator (object) by code.
	   Raises a LookupError if no field with the specified code exists."""
	if not code in GetOperatorCodes():
		raise LookupError("Criteria Operator with code {0} not found!".format(code))
	return _get_by_name(name)

def GetConstants():
	"""Returns a list of all available constant values used by some Nexpose Criteria"""
	return _get_filtered_classes(NexposeCriteriaConstant)

def GetConstantNames():
	"""Returns a list of supported constant names by Nexpose Criteria"""
	return map(lambda constant: constant.Name, _get_filtered_classes(NexposeCriteriaConstant))

def GetConstantByName(name):
	"""Gets a constant (object) by name.
	   Raises a LookupError if no constant with the specified name exists."""
	if not name in GetConstantNames():
		raise LookupError("Criteria Constant with name {0} not found!".format(name))
	return _get_by_name(name)

class Criterion(JSON):
	@staticmethod
	def Create(field, operator, value=None):
		return Criterion(field, operator, value)
	
	def __init__(self, field, operator, value=None):
		assert is_subclass_of(field, NexposeCriteriaField)
		assert is_subclass_of(operator, NexposeCriteriaOperator)
		assert operator in field.ValidOperators
		if is_subclass_of(value, NexposeCriteriaConstant):
			value = NexposeCriteriaConstant.Value
		self.field    = field
		self.operator = operator
		self.value    = value if value != None else ''

	def as_json(self):
		json_data = dict()
		json_data['metadata'] = dict()
		json_data['metadata']['fieldName'] = self.field.Code
		json_data['operator'] = self.operator.Code
		json_data['values'] = list(self.value) if is_iterable(self.value) else [self.value]
		return json_data

class Criteria:
	@staticmethod
	def Create(criteria=None, operator=None):
		return Criteria(criteria, operator)
	
	def _as_operator(self, operator_or_code, default_operator):
		if operator_or_code == None:
			return default_operator
		if not is_subclass_of(operator_or_code, NexposeCriteriaOperator):
			operator_or_code = GetOperatorByCode(operator_or_code)
		assert is_subclass_of(operator_or_code, AND) or is_subclass_of(operator_or_code, OR)
		return operator_or_code
	
	def __init__(self, criteria=None, operator_or_code=None):
		if criteria == None:
			criteria = []
		self.operator = self._as_operator(operator_or_code, AND)
		self.criteria = list(criteria) if is_iterable(criteria) else [criteria]
	
	def as_json(self):
		json_data = dict()
		json_data['operator'] = self.operator.Code
		json_data['criteria'] = map(lambda criterion: criterion.as_json(), self.criteria)
		return json_data

# shortcut:
def Create(criteria=None, operator=None):
	return Criteria.Create(criteria, operator)
