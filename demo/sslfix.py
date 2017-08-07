from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
# SOURCE: http://stackoverflow.com/questions/11772847/error-urlopen-error-errno-8-ssl-c504-eof-occurred-in-violation-of-protoco
from future import standard_library
standard_library.install_aliases()
from builtins import *
import ssl
from functools import wraps


def sslwrap(func):
    @wraps(func)
    def bar(*args, **kw):
        kw['ssl_version'] = ssl.PROTOCOL_TLSv1
        return func(*args, **kw)
    return bar


def patch():
    if hasattr(ssl, '_create_unverified_context'):
        # Python >=2.7.9
        ssl._create_default_https_context = ssl._create_unverified_context
    else:
        # Python <2.7.9
        ssl.wrap_socket = sslwrap(ssl.wrap_socket)
