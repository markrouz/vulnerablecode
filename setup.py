#!/usr/bin/env python
# -*- encoding: utf-8 -*-

# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
#
# SPDX-License-Identifier: Apache-2.0 AND CC-BY-4.0
#
# VulnerableCode software is licensed under the Apache License version 2.0.
# VulnerableCode data is licensed collectively under CC-BY-4.0.
#
# See https://www.apache.org/licenses/LICENSE-2.0 for the Apache-2.0 license text.
# See https://creativecommons.org/licenses/by/4.0/legalcode for the CC-BY-4.0 license text.
#
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projectsfrom pathlib import Path


from setuptools import find_packages
from setuptools import setup

requirements = [
    r.strip() for r in open("requirements.txt") if r.strip() and not r.strip().startswith("#")
]

desc = "Software package vulnerabilities database."

setup(
    name="vulnerablecode",
    version="20.10",
    license="Apache-2.0 AND CC-BY-4.0",
    description=desc,
    long_description=desc,
    author="nexB Inc. and others",
    author_email="info@aboutcode.org",
    url="https://github.com/nexB/vulnerablecode",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        # complete classifier list: http://pypi.python.org/pypi?%3Aaction=list_classifiers
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Utilities",
    ],
    keywords=[
        "open source",
        "vulnerability",
        "security",
        "package",
    ],
    install_requires=requirements,
)
