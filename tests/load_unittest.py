import sys

def _assertIsInstance(self, obj, class_or_type_or_tuple):
	self.assertTrue(isinstance(obj, class_or_type_or_tuple))

if sys.version_info[0] == 2 and sys.version_info[1] <= 6:
	try:
		import unittest2 as unittest
	except ImportError:
		import unittest
		unittest.TestCase.assertIsInstance = _assertIsInstance
else:
	import unittest
