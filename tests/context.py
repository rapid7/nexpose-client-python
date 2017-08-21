# -*- coding: utf-8 -*-
# Future Imports for py2/3 backwards compat.
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
import sys
import os
from future import standard_library
standard_library.install_aliases()

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../nexpose')))
import nexpose
