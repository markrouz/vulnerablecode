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

import json
import re
from typing import List
from typing import Set

from packageurl import PackageURL

from vulnerabilities.helpers import AffectedPackage
from vulnerabilities.importer import Advisory
from vulnerabilities.importer import GitImporter
from vulnerabilities.importer import Reference


class RetireDotnetImporter(GitImporter):
    def __enter__(self):
        super(RetireDotnetImporter, self).__enter__()

        if not getattr(self, "_added_files", None):
            self._added_files, self._updated_files = self.file_changes(
                recursive=True, file_ext="json", subdir="./Content"
            )

    def updated_advisories(self) -> Set[Advisory]:
        files = self._updated_files.union(self._added_files)
        advisories = []
        for f in files:
            processed_data = self.process_file(f)
            if processed_data:
                advisories.append(processed_data)
        return self.batch_advisories(advisories)

    @staticmethod
    def vuln_id_from_desc(desc):
        cve_regex = re.compile(r"CVE-\d+-\d+")
        res = cve_regex.search(desc)
        if res:
            return desc[res.start() : res.end()]
        else:
            return None

    def process_file(self, path) -> List[Advisory]:
        with open(path) as f:
            json_doc = json.load(f)
            if self.vuln_id_from_desc(json_doc["description"]):
                vuln_id = self.vuln_id_from_desc(json_doc["description"])
            else:
                return

            affected_packages = []
            for pkg in json_doc["packages"]:
                affected_packages.append(
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            name=pkg["id"], version=pkg["affected"], type="nuget"
                        ),
                        patched_package=PackageURL(
                            name=pkg["id"], version=pkg["fix"], type="nuget"
                        ),
                    )
                )

            vuln_reference = [
                Reference(
                    url=json_doc["link"],
                )
            ]

            return Advisory(
                vulnerability_id=vuln_id,
                summary=json_doc["description"],
                affected_packages=affected_packages,
                references=vuln_reference,
            )
