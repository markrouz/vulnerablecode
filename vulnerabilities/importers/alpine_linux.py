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

from typing import Any
from typing import List
from typing import Mapping
from typing import Set

import requests
import saneyaml
from bs4 import BeautifulSoup

from vulnerabilities.helpers import is_cve
from vulnerabilities.importer import Advisory
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference

BASE_URL = "https://secdb.alpinelinux.org/"


class AlpineImporter(Importer):
    @staticmethod
    def fetch_advisory_links():
        index_page = BeautifulSoup(requests.get(BASE_URL).content, features="lxml")

        alpine_versions = [
            link.text for link in index_page.find_all("a") if link.text.startswith("v")
        ]

        advisory_directory_links = [f"{BASE_URL}{version}" for version in alpine_versions]

        advisory_links = []
        for advisory_directory_link in advisory_directory_links:
            advisory_directory_page = requests.get(advisory_directory_link).content
            advisory_directory_page = BeautifulSoup(advisory_directory_page, features="lxml")
            advisory_links.extend(
                [
                    f"{advisory_directory_link}{anchore_tag.text}"
                    for anchore_tag in advisory_directory_page.find_all("a")
                    if anchore_tag.text.endswith("yaml")
                ]
            )

        return advisory_links

    def updated_advisories(self) -> Set[Advisory]:
        advisories = []
        advisory_links = self.fetch_advisory_links()
        for link in advisory_links:
            advisories.extend(self._process_link(link))

        return self.batch_advisories(advisories)

    def _process_link(self, link) -> List[Advisory]:
        advisories = []
        yaml_response = requests.get(link).content
        record = saneyaml.load(yaml_response)

        if record["packages"] is None:
            return advisories

        for p in record["packages"]:
            advisories.extend(
                self._load_advisories(
                    p["pkg"],
                )
            )

        return advisories

    @staticmethod
    def _load_advisories(
        pkg_infos: Mapping[str, Any],
    ) -> List[Advisory]:

        advisories = []

        for fixed_vulns in pkg_infos["secfixes"].values():

            if fixed_vulns is None:
                continue

            for vuln_ids in fixed_vulns:
                vuln_ids = vuln_ids.split()
                references = []
                for reference_id in vuln_ids[1:]:

                    if reference_id.startswith("XSA"):
                        xsa_id = reference_id.split("-")[-1]
                        references.append(
                            Reference(
                                reference_id=reference_id,
                                url="https://xenbits.xen.org/xsa/advisory-{}.html".format(xsa_id),
                            )
                        )

                    elif reference_id.startswith("ZBX"):
                        references.append(
                            Reference(
                                reference_id=reference_id,
                                url="https://support.zabbix.com/browse/{}".format(reference_id),
                            )
                        )

                    elif reference_id.startswith("wnpa-sec"):
                        references.append(
                            Reference(
                                reference_id=reference_id,
                                url="https://www.wireshark.org/security/{}.html".format(
                                    reference_id
                                ),
                            )
                        )

                # TODO: Handle the CVE-????-????? case
                advisories.append(
                    Advisory(
                        summary="",
                        references=references,
                        vulnerability_id=vuln_ids[0] if is_cve(vuln_ids[0]) else "",
                    )
                )

        return advisories
