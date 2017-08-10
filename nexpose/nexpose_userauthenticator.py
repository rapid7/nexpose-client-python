# Future Imports for py2/3 backwards compat.
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from builtins import object
from xml_utils import get_attribute
from future import standard_library
standard_library.install_aliases()


class UserAuthenticatorSummary(object):
    @staticmethod
    def CreateFromXML(xml_data):
        summary = UserAuthenticatorSummary()
        summary.id = int(get_attribute(xml_data, 'id', summary.id))
        summary.source = get_attribute(xml_data, 'authSource', summary.source)
        summary.module = get_attribute(xml_data, 'authModule', summary.module)
        summary.is_external = get_attribute(xml_data, 'external') == '1'
        return summary

    def __init__(self):
        self.id = 0
        self.source = ''
        self.module = ''
        self.is_external = False

    def AsXML(self):
        raise NotImplementedError(__func__) # noqa F821
