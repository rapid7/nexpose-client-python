# Future Imports for py2/3 backwards compat.
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from builtins import object
from future import standard_library
standard_library.install_aliases()


class NexposeCriteriaConstant(object):
    class __metaclass__(type):
        @property
        def Name(cls):
            return cls.__name__

        def __str__(cls):
            return cls.Name
