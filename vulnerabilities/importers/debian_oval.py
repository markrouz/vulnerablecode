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


import asyncio
import dataclasses
import xml.etree.ElementTree as ET

import requests

from vulnerabilities.helpers import create_etag
from vulnerabilities.importer import OvalImporter
from vulnerabilities.package_managers import DebianVersionAPI


class DebianOvalImporter(OvalImporter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # we could avoid setting translations, and have it
        # set by default in the OvalParser, but we don't yet know
        # whether all OVAL providers use the same format
        self.translations = {"less than": "<"}
        self.pkg_manager_api = DebianVersionAPI()

    def _fetch(self):
        releases = self.config.releases
        for release in releases:
            file_url = f"https://www.debian.org/security/oval/oval-definitions-{release}.xml"
            if not create_etag(data_src=self, url=file_url, etag_key="ETag"):
                continue

            resp = requests.get(file_url).content
            yield (
                {"type": "deb", "namespace": "debian", "qualifiers": {"distro": release}},
                ET.ElementTree(ET.fromstring(resp.decode("utf-8"))),
            )
        return []

    def set_api(self, packages):
        asyncio.run(self.pkg_manager_api.load_api(packages))
