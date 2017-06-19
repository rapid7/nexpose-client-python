from os import path
from load_unittest import *

NexposeTestSuite = unittest.TestLoader().discover(path.dirname(__file__), "test_*.py")

def main():
	runner = unittest.TextTestRunner(verbosity=2)
	runner.run(NexposeTestSuite)
