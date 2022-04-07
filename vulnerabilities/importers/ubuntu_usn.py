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

import bz2
import dataclasses
import json

import requests
from packageurl import PackageURL

from vulnerabilities.helpers import create_etag
from vulnerabilities.helpers import is_cve
from vulnerabilities.importer import Advisory
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference


class UbuntuUSNImporter(Importer):
    def updated_advisories(self):
        advisories = []
        if create_etag(data_src=self, url=self.config.db_url, etag_key="etag"):
            advisories.extend(self.to_advisories(fetch(self.config.db_url)))

        return self.batch_advisories(advisories)

    def create_etag(self, url):
        etag = requests.head(url).headers.get("etag")
        if not etag:
            return True

        elif url in self.config.etags:
            if self.config.etags[url] == etag:
                return False

        self.config.etags[url] = etag
        return True

    @staticmethod
    def to_advisories(usn_db):
        advisories = []
        for usn in usn_db:
            reference = get_usn_references(usn_db[usn]["id"])
            for cve in usn_db[usn].get("cves", [""]):
                # The db sometimes contains entries like
                # {'cves': ['python-pgsql vulnerabilities', 'CVE-2006-2313', 'CVE-2006-2314']}
                # This `if` filters entries like 'python-pgsql vulnerabilities'
                if not is_cve(cve):
                    cve = ""

                advisories.append(
                    Advisory(
                        vulnerability_id=cve,
                        summary="",
                        references=[reference],
                    )
                )

        return advisories


def get_usn_references(usn_id):
    return Reference(reference_id="USN-" + usn_id, url="https://usn.ubuntu.com/{}/".format(usn_id))


def fetch(url):
    response = requests.get(url).content
    raw_data = bz2.decompress(response)

    return json.loads(raw_data)
