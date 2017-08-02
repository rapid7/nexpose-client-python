# Future Imports for py2 backwards compatibility
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from load_unittest import unittest
from LoadFixture import LoadFixture
from .context import nexpose
from nexpose import Tag, TagAttribute, TagConfiguration, TagColors, DEFAULT_SOURCENAME, DEFAULT_TAGCOLOR

def LoadAllDefaultTags():
	json = LoadFixture("default_tags.json")
	return map(Tag.CreateFromJSON, json["resources"])

def LoadTag(fixture_name):
	json = LoadFixture(fixture_name + ".json")
	return Tag.CreateFromJSON(json)

class NexposeTagAttributeTestCase(unittest.TestCase):
	def testCreate(self):
		name = "a_name"

		attr = TagAttribute.Create(name)
		self.assertEquals(name, attr.name)
		self.assertEquals(None, attr.value)

		attr = TagAttribute.Create(name, "a_value")
		self.assertEquals(name, attr.name)
		self.assertEquals("a_value", attr.value)

class NexposeTagTestCase(unittest.TestCase):
	def assertTagAttributeValue(self, tag, name, expected_value):
		source_attribute = filter(lambda attr: attr.name == name, tag.attributes)[0]
		self.assertEqual(expected_value, source_attribute.value)

	def assertCreation(self, tag, expected_name, expected_type, expected_source_name):
		self.assertIsInstance(tag, Tag)

		self.assertEquals(0, tag.id)
		self.assertEquals(expected_name, tag.name)
		self.assertEquals(expected_type, tag.type)
		self.assertIsInstance(tag.config, TagConfiguration)
		self.assertEquals([], tag.config.assetgroup_ids)
		self.assertEquals([], tag.config.site_ids)
		self.assertEquals([], tag.config.associated_asset_ids)
		self.assertEquals(None, tag.config.search_criteria)
		self.assertEquals([], tag.asset_ids)

		self.assertTagAttributeValue(tag, "SOURCE", expected_source_name)

	def assertCustomCreation(self, tag, expected_name, expected_type, expected_source_name, expected_color):
		self.assertCreation(tag, expected_name, expected_type, expected_source_name)
		self.assertTagAttributeValue(tag, "COLOR", expected_color)

	def testCreateFromJSON(self):
		# test the creation from JSON by loading the default tags and checking only a few values
		tags = LoadAllDefaultTags()

		for i, tag in enumerate(tags):
			id  = i + 1

			self.assertIsInstance(tag, Tag)

			self.assertEquals(id, tag.id)
			self.assertEquals(None, tag.config)
			self.assertEquals([], tag.asset_ids)
			self.assertTagAttributeValue(tag, "SOURCE", "Built-in")

	def testCreate(self):
		name = "test"

		creator = lambda: Tag.Create(name, None)
		self.assertCreation(creator(), name, None, DEFAULT_SOURCENAME)

		creator = lambda: Tag.Create(name, "my_type")
		self.assertCreation(creator(), name, "my_type", DEFAULT_SOURCENAME)

		creator = lambda: Tag.Create(name, None, "my_source")
		self.assertCreation(creator(), name, None, "my_source")

	def testCreateCustom(self):
		name = "test"

		creator = lambda: Tag.CreateCustom(name)
		self.assertCustomCreation(creator(), name, "CUSTOM", DEFAULT_SOURCENAME, DEFAULT_TAGCOLOR)
		self.assertCustomCreation(creator(), name, "CUSTOM", DEFAULT_SOURCENAME, TagColors.DEFAULT)

		creator = lambda: Tag.CreateCustom(name, TagColors.GREEN)
		self.assertCustomCreation(creator(), name, "CUSTOM", DEFAULT_SOURCENAME, TagColors.GREEN)

		creator = lambda: Tag.CreateCustom(name, TagColors.RED, "my_source")
		self.assertCustomCreation(creator(), name, "CUSTOM", "my_source", TagColors.RED)

	def testCustomTagWithAttributes(self):
		tag = LoadTag("custom_tag_example")

		self.assertNotEquals(0, tag.id)
		self.assertEquals("example", tag.name)
		self.assertEquals("CUSTOM", tag.type)
		self.assertIsInstance(tag.config, TagConfiguration)
		self.assertEquals([2, 3], tag.config.assetgroup_ids)
		self.assertEquals([4, 5], tag.config.site_ids)
		self.assertEquals([6, 7], tag.config.associated_asset_ids)
		self.assertEquals(None, tag.config.search_criteria)
		self.assertEquals([1], tag.asset_ids)

		self.assertTagAttributeValue(tag, "SOURCE", "Nexpose")
		self.assertTagAttributeValue(tag, "COLOR", TagColors.ORANGE)