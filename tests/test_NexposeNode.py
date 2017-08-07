# Future Imports for py2 backwards compatibility
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from load_unittest import unittest
from LoadFixture import LoadFixture, JSON
from .context import nexpose
from nexpose import Node


class NexposeNodeTestCase(unittest.TestCase):
    def testCreateFromJSON(self):
        fixture = LoadFixture('data-scan_complete-assets_Nexpose6.json')
        records = fixture['records']
        self.assertEqual(len(records), 3)

        record_empty = Node.CreateFromJSON(records[2])
