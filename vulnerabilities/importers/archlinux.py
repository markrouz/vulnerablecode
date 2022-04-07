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
import json
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Set
from urllib.request import urlopen

from packageurl import PackageURL

from vulnerabilities.helpers import nearest_patched_package
from vulnerabilities.importer import Advisory
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import scoring_systems


class ArchlinuxImporter(Importer):
    def __enter__(self):
        self._api_response = self._fetch()

    def updated_advisories(self) -> Set[Advisory]:
        advisories = []

        for record in self._api_response:
            advisories.extend(self._parse(record))

        return self.batch_advisories(advisories)

    def _fetch(self) -> Iterable[Mapping]:
        with urlopen(self.config.archlinux_tracker_url) as response:
            return json.load(response)

    def _parse(self, record) -> List[Advisory]:
        advisories = []

        for cve_id in record["issues"]:
            affected_packages = []
            for name in record["packages"]:
                impacted_purls, resolved_purls = [], []
                impacted_purls.append(
                    PackageURL(
                        name=name,
                        type="pacman",
                        namespace="archlinux",
                        version=record["affected"],
                    )
                )

                if record["fixed"]:
                    resolved_purls.append(
                        PackageURL(
                            name=name,
                            type="pacman",
                            namespace="archlinux",
                            version=record["fixed"],
                        )
                    )
                affected_packages.extend(nearest_patched_package(impacted_purls, resolved_purls))

            references = []
            references.append(
                Reference(
                    reference_id=record["name"],
                    url="https://security.archlinux.org/{}".format(record["name"]),
                    severities=[
                        VulnerabilitySeverity(
                            system=scoring_systems["avgs"], value=record["severity"]
                        )
                    ],
                )
            )

            for ref in record["advisories"]:
                references.append(
                    Reference(
                        reference_id=ref,
                        url="https://security.archlinux.org/{}".format(ref),
                    )
                )

            advisories.append(
                Advisory(
                    vulnerability_id=cve_id,
                    summary="",
                    affected_packages=affected_packages,
                    references=references,
                )
            )

        return advisories
