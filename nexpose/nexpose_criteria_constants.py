# Future Imports for py2 backwards compatibility
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
class NexposeCriteriaConstant:
	class __metaclass__(type):
		@property
		def Name(cls):
			return cls.__name__
		
		def __str__(cls):
			return cls.Name
