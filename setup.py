#!/usr/bin/env python
from setuptools import setup

def readme():
    with open('README.rst', 'r') as f:
        readme = f.read()

packages = [
    'nexpose',
]

requires = [
    'lxml',
]

setup(
    name = 'nexpose',
    packages = packages,
    package_data={'': ['LICENSE']},
    package_dir={'nexpose': 'nexpose'},
    include_package_data=True,
    version = '0.1.1',
    license = 'BSD',
    description = 'The official Python Nexpose API client library',
    long_description = readme(),
    install_requires = requires,
    author = 'Davinsi Labs',
    url = 'https://github.com/rapid7/nexpose-client-python',
    download_url = 'https://github.com/rapid7/nexpose-client-python/releases',
    keywords = ['nexpose'],
    classifiers = (
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7'
    ),
)
