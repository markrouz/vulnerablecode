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
from typing import Any
from typing import List
from typing import Mapping
from typing import Set

import requests
from dateutil import parser as dateparser
from packageurl import PackageURL

from vulnerabilities.helpers import nearest_patched_package
from vulnerabilities.importer import Advisory
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference


class DebianImporter(Importer):
    def __enter__(self):
        if self.response_is_new():
            self._api_response = self._fetch()

        else:
            self._api_response = {}

    def updated_advisories(self) -> Set[Advisory]:
        advisories = []

        for pkg_name, records in self._api_response.items():
            advisories.extend(self._parse(pkg_name, records))

        return self.batch_advisories(advisories)

    def _fetch(self) -> Mapping[str, Any]:
        return requests.get(self.config.debian_tracker_url).json()

    def _parse(self, pkg_name: str, records: Mapping[str, Any]) -> List[Advisory]:
        advisories = []
        ignored_versions = {"3.8.20-4."}

        for cve_id, record in records.items():
            impacted_purls, resolved_purls = [], []
            if not cve_id.startswith("CVE"):
                continue

            # vulnerabilities starting with something else may not be public yet
            # see for instance https://web.archive.org/web/20201215213725/https://security-tracker.debian.org/tracker/TEMP-0000000-A2EB44
            # TODO: this would need to be revisited though to ensure we are not missing out on anything

            for release_name, release_record in record["releases"].items():
                if not release_record.get("repositories", {}).get(release_name):
                    continue

                version = release_record["repositories"][release_name]

                if version in ignored_versions:
                    continue

                purl = PackageURL(
                    name=pkg_name,
                    type="deb",
                    namespace="debian",
                    version=version,
                    qualifiers={"distro": release_name},
                )

                if release_record.get("status", "") == "resolved":
                    resolved_purls.append(purl)
                else:
                    impacted_purls.append(purl)

                if (
                    "fixed_version" in release_record
                    and release_record["fixed_version"] not in ignored_versions
                ):
                    resolved_purls.append(
                        PackageURL(
                            name=pkg_name,
                            type="deb",
                            namespace="debian",
                            version=release_record["fixed_version"],
                            qualifiers={"distro": release_name},
                        )
                    )

            references = []
            debianbug = record.get("debianbug")
            if debianbug:
                bug_url = f"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug={debianbug}"
                references.append(Reference(url=bug_url, reference_id=debianbug))
            advisories.append(
                Advisory(
                    vulnerability_id=cve_id,
                    affected_packages=nearest_patched_package(impacted_purls, resolved_purls),
                    summary=record.get("description", ""),
                    references=references,
                )
            )

        return advisories

    def response_is_new(self):
        """
        Return True if a request response is for new data likely changed or
        updated since we last checked.
        """
        head = requests.head(self.config.debian_tracker_url)
        date_str = head.headers.get("last-modified")
        last_modified_date = dateparser.parse(date_str)
        if self.config.last_run_date:
            return self.config.last_run_date < last_modified_date

        return True
