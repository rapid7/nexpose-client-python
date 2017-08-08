# Future Imports for py2/3 backwards compat.
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from .load_unittest import unittest
from .LoadFixture import LoadFixture
from future import standard_library
standard_library.install_aliases()


class LoadFixtureTestCase(unittest.TestCase):
    def testThatOurFixturesWillLoadCorrectly(self):
        fixture = LoadFixture("default_tags.json")
        self.assertEqual(5, fixture["total_available"])
        self.assertEqual(5, len(fixture["resources"]))

    def testThatLoadingNonExistingFixtureResultsInAnException(self):
        self.assertRaises(Exception, lambda: LoadFixture("should_not_exist.json"))

    def testThatLoadingInvalidFixtureTypeResultsInAnException(self):
        self.assertRaises(ValueError, lambda: LoadFixture("xml_fixtures.py"))
