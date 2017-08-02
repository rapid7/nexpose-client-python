# Future Imports for py2 backwards compatibility
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

from os import path
from load_unittest import *

NexposeTestSuite = unittest.TestLoader().discover(path.dirname(__file__), "test_*.py")

def main():
	runner = unittest.TextTestRunner(verbosity=2)
	runner.run(NexposeTestSuite)
