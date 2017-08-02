# Future Imports for py2 backwards compatibility
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from load_unittest import unittest
from LoadFixture import LoadFixture

class LoadFixtureTestCase(unittest.TestCase):
	def testThatOurFixturesWillLoadCorrectly(self):
		fixture = LoadFixture("default_tags.json")
		self.assertEqual(5, fixture["total_available"])
		self.assertEqual(5, len(fixture["resources"]))

	def testThatLoadingNonExistingFixtureResultsInAnException(self):
		self.assertRaises(Exception, lambda: LoadFixture("should_not_exist.json"))

	def testThatLoadingInvalidFixtureTypeResultsInAnException(self):
		self.assertRaises(ValueError, lambda: LoadFixture("xml_fixtures.py"))
