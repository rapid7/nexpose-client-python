# Future Imports for py2/3 backwards compat.
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from builtins import object
from future import standard_library
standard_library.install_aliases()


class NexposeStatus(object):
    STARTING = 'starting'
    NORMAL_MODE = 'normal_mode'
    MAINTENANCE_MODE = 'maintenance_mode'
    UNKNOWN = 'unknown'

    # To be compatible with older Nexpose versions; do not remove items from the list below, only add!
    _URL_TO_STATUS = {
        'starting.html': STARTING,
        'login.html': NORMAL_MODE,
        'login.jsp': NORMAL_MODE,
        'maintenance-login.html': MAINTENANCE_MODE,
    }

    @staticmethod
    def GetStatusFromURL(url):
        path = url.split('/')[-1]  # get the last part of the URL
        status = NexposeStatus._URL_TO_STATUS.get(path, NexposeStatus.UNKNOWN)
        return status
