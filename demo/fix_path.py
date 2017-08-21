# Future Imports for py2/3 backwards compat.
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

import sys
from os import path
from future import standard_library
standard_library.install_aliases()

def make_dlnexpose_importable():
    script_path = path.dirname(path.abspath(__file__))
    tests_path = path.join(script_path, "../nexpose")
    sys.path.insert(0, tests_path)
