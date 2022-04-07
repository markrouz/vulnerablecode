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

import dataclasses
import re
import xml.etree.ElementTree as ET
from typing import Set

import requests
from packageurl import PackageURL

from vulnerabilities.helpers import create_etag
from vulnerabilities.helpers import nearest_patched_package
from vulnerabilities.importer import Advisory
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference


class OpenSSLImporter(Importer):

    url = "https://www.openssl.org/news/vulnerabilities.xml"

    def updated_advisories(self) -> Set[Advisory]:
        # Etags are like hashes of web responses. We maintain
        # (url, etag) mappings in the DB. `create_etag`  creates
        # (url, etag) pair. If a (url, etag) already exists then the code
        # skips processing the response further to avoid duplicate work
        if create_etag(data_src=self, url=self.url, etag_key="ETag"):
            raw_data = self.fetch()
            advisories = self.to_advisories(raw_data)
            return self.batch_advisories(advisories)

        return []

    def fetch(self):
        return requests.get(self.url).content

    @staticmethod
    def to_advisories(xml_response: str) -> Set[Advisory]:
        advisories = []
        pkg_name = "openssl"
        pkg_type = "generic"
        root = ET.fromstring(xml_response)
        for element in root:
            if element.tag == "issue":
                cve_id = ""
                summary = ""
                safe_pkg_versions = []
                vuln_pkg_versions = []
                ref_urls = []
                for info in element:

                    if info.tag == "cve":
                        if info.attrib.get("name"):
                            cve_id = "CVE-" + info.attrib.get("name")

                        else:
                            continue

                    if cve_id == "CVE-2007-5502":
                        # This CVE has weird version "fips-1.1.2".This is
                        # probably a submodule. Skip this for now.
                        continue

                    if info.tag == "affects":
                        # Vulnerable package versions
                        vuln_pkg_versions.append(info.attrib.get("version"))

                    if info.tag == "fixed":
                        # Fixed package versions
                        safe_pkg_versions.append(info.attrib.get("version"))

                        if info:
                            commit_hash = info[0].attrib["hash"]
                            ref_urls.append(
                                Reference(
                                    url="https://github.com/openssl/openssl/commit/" + commit_hash
                                )
                            )
                    if info.tag == "description":
                        # Description
                        summary = re.sub(r"\s+", " ", info.text).strip()

                safe_purls = [
                    PackageURL(name=pkg_name, type=pkg_type, version=version)
                    for version in safe_pkg_versions
                ]
                vuln_purls = [
                    PackageURL(name=pkg_name, type=pkg_type, version=version)
                    for version in vuln_pkg_versions
                ]

                advisory = Advisory(
                    vulnerability_id=cve_id,
                    summary=summary,
                    affected_packages=nearest_patched_package(vuln_purls, safe_purls),
                    references=ref_urls,
                )
                advisories.append(advisory)

        return advisories
