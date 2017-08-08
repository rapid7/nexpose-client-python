# Future Imports for py2/3 backwards compat.
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)

# SOURCE: http://stackoverflow.com/questions/11772847/error-urlopen-error-errno-8-ssl-c504-eof-occurred-in-violation-of-protoco
import ssl
from functools import wraps
from future import standard_library
standard_library.install_aliases()


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
