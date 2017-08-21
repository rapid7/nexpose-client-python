# Future Imports for py2/3 backwards compat.
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
import inspect
from future import standard_library
standard_library.install_aliases()


def is_subclass_of(variable, required_class):
    return inspect.isclass(variable) and issubclass(variable, required_class)


def is_iterable(variable):
    return hasattr(variable, '__iter__')


def remove_front_slash(uri):
    if uri.startswith('/'):
        uri = uri[1:]
    return uri


# based on : http://stackoverflow.com/questions/6480723/urllib-urlencode-doesnt-like-unicode-values-how-about-this-workaround
def utf8_encoded(data):
    if isinstance(data, str):
        return data.encode('utf8')

    if isinstance(data, str):
        # ensure now it can be decoded aka 'is valid UTF-8?'
        data.decode('utf8')
        return data

    if isinstance(data, dict):
        return dict(zip(iter(data.keys()), map(utf8_encoded, iter(data.values()))))

    if is_iterable(data):
        return list(map(utf8_encoded, data))

    # not sure how to handle this data type, return as-is
    return data
