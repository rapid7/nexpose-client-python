DEPRECATED
==========

The `RESTful API for the Nexpose/InsightVM Security
Console <https://help.rapid7.com/insightvm/en-us/api/index.html>`__ has
rendered this library obsolete. If you require a Python library for that
API you can use a `generated
client <https://github.com/rapid7/vm-console-client-python>`__. Clients
for other languages can be generated from the Swagger specification.
Note that generated clients are not officially supported or maintained
by Rapid7.

This project will not receive new changes from Rapid7, though pull
requests may still be accepted and new releases published on request.

nexpose-client-python
=====================

|No Maintenance Intended| |Travis| |PyPI Version| |PyPI Status| |GitHub
license| |PyPI Pythons|

This is the official Python package for the Python Nexpose API client
library.

For assistance with using the library or to discuss different
approaches, please open an issue. To share or discuss scripts which use
the library head over to the `Nexpose
Resources <https://github.com/rapid7/nexpose-resources>`__ project.

Check out the
`wiki <https://github.com/rapid7/nexpose-client-python/wiki>`__ for
walk-throughs and other documentation. Submit bugs and feature requests
on the
`issues <https://github.com/rapid7/nexpose-client-python/issues>`__
page.

This library provides calls to the Nexpose XML APIs version 1.1 and 1.2.

nexpose-client-python uses `Semantic Versioning <http://semver.org/>`__.
This allows for confident use of `version
pinning <https://www.python.org/dev/peps/pep-0440/#version-specifiers>`__
in your requirements file.

Install the library using pip: ``pip install nexpose``

Release Notes
-------------

Release notes are available on the
`Releases <https://github.com/rapid7/nexpose-client-python/releases>`__
page.

Contributions
-------------

We welcome contributions to this package. Please see
`CONTRIBUTING <https://github.com/rapid7/nexpose-client-python/blob/master/.github/CONTRIBUTING.md>`__ for details.

Full usage examples or task-oriented scripts should be submitted to the
`Nexpose Resources <https://github.com/rapid7/nexpose-resources>`__
project. Smaller examples can be added to the
`wiki <https://github.com/rapid7/nexpose-client-python/wiki>`__.

License
-------

The nexpose-client-python library is provided under the 3-Clause BSD
License. See `LICENSE <https://github.com/rapid7/nexpose-client-python/blob/master/LICENSE>`__ for details.

Credits
-------

| Davinsi Labs
| Rapid7, Inc.

See `contributors <https://github.com/rapid7/nexpose-client-python/blob/master/contributors.md>`__ for more info.

.. |No Maintenance Intended| image:: http://unmaintained.tech/badge.svg
   :target: http://unmaintained.tech/
.. |Travis| image:: https://img.shields.io/travis/rapid7/nexpose-client-python.svg
   :target: https://travis-ci.org/rapid7/nexpose-client-python
.. |PyPI Version| image:: https://img.shields.io/pypi/v/nexpose.svg
   :target: https://pypi.python.org/pypi/nexpose
.. |PyPI Status| image:: https://img.shields.io/pypi/status/nexpose.svg
.. |GitHub license| image:: https://img.shields.io/badge/license-BSD-blue.svg
   :target: https://raw.githubusercontent.com/rapid7/nexpose-client-python/master/LICENSE
.. |PyPI Pythons| image:: https://img.shields.io/pypi/pyversions/nexpose.svg
