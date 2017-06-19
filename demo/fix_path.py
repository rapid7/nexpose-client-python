import sys
from os import path

def make_dlnexpose_importable():
	script_path = path.dirname(path.abspath(__file__))
	tests_path = path.join(script_path, "../nexpose")
	sys.path.insert(0, tests_path)
