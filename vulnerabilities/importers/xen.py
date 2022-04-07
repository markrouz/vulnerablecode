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


class XenImporter(Importer):
    CONFIG_CLASS = XenDBConfiguration

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
    def to_advisories(xen_db):
        advisories = []
        for xsa in xen_db[0]["xsas"]:
            reference = get_xen_references(xsa["xsa"])
            title = xsa.get("title", [""])
            for cve in xsa.get("cve", [""]):
                if not is_cve(cve):
                    cve = ""

                advisories.append(
                    Advisory(
                        vulnerability_id=cve,
                        summary=title,
                        references=[reference],
                    )
                )
        return advisories


def get_xen_references(xsa_id):
    return Reference(
        reference_id="XSA-" + xsa_id,
        url="https://xenbits.xen.org/xsa/advisory-{}.html".format(xsa_id),
    )


def fetch(url):
    response = requests.get(url).content
    return json.loads(response)
