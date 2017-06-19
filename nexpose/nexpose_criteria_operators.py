class NexposeCriteriaOperator:
	class __metaclass__(type):
		@property
		def Code(cls):
			return cls.__name__
		
		def __str__(cls):
			return cls.Code

class AND(NexposeCriteriaOperator):
	pass

class OR(NexposeCriteriaOperator):
	pass

class ARE(NexposeCriteriaOperator):
	pass

class IS(NexposeCriteriaOperator):
	pass

class IS_NOT(NexposeCriteriaOperator):
	pass

class STARTS_WITH(NexposeCriteriaOperator):
	pass

class ENDS_WITH(NexposeCriteriaOperator):
	pass

class IS_EMPTY(NexposeCriteriaOperator):
	pass

class IS_NOT_EMPTY(NexposeCriteriaOperator):
	pass

class IS_APPLIED(NexposeCriteriaOperator):
	pass

class IS_NOT_APPLIED(NexposeCriteriaOperator):
	pass

class CONTAINS(NexposeCriteriaOperator):
	pass

class NOT_CONTAINS(NexposeCriteriaOperator):
	pass

class INCLUDE(NexposeCriteriaOperator):
	pass

class DO_NOT_INCLUDE(NexposeCriteriaOperator):
	pass

class IN(NexposeCriteriaOperator):
	pass

class NOT_IN(NexposeCriteriaOperator):
	pass

class IN_RANGE(NexposeCriteriaOperator):
	pass

class LESS_THAN(NexposeCriteriaOperator):
	pass

class GREATER_THAN(NexposeCriteriaOperator):
	pass

class ON_OR_BEFORE(NexposeCriteriaOperator):
	pass

class ON_OR_AFTER(NexposeCriteriaOperator):
	pass

class BETWEEN(NexposeCriteriaOperator):
	pass

class EARLIER_THAN(NexposeCriteriaOperator):
	pass

class WITHIN_THE_LAST(NexposeCriteriaOperator):
	pass
