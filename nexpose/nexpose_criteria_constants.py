class NexposeCriteriaConstant:
	class __metaclass__(type):
		@property
		def Name(cls):
			return cls.__name__
		
		def __str__(cls):
			return cls.Name
