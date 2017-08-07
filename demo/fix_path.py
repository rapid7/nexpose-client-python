from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
from future import standard_library
standard_library.install_aliases()
from builtins import *
import sys
from os import path


def make_dlnexpose_importable():
    script_path = path.dirname(path.abspath(__file__))
    tests_path = path.join(script_path, "../nexpose")
    sys.path.insert(0, tests_path)
