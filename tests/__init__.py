# Future Imports for py2/3 backwards compat.
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from os import path
from .load_unittest import *
from future import standard_library
standard_library.install_aliases()

NexposeTestSuite = unittest.TestLoader().discover(path.dirname(__file__), "test_*.py")


def main():
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(NexposeTestSuite)
