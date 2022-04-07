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

from vulnerabilities.helpers import fetch_yaml
from vulnerabilities.importer import Advisory
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import scoring_systems

URL = "https://ftp.suse.com/pub/projects/security/yaml/suse-cvss-scores.yaml"


class SUSESeverityScoreImporter(Importer):
    def updated_advisories(self):
        advisories = []
        score_data = fetch_yaml(URL)
        advisories.append(self.to_advisory(score_data))
        return advisories

    @staticmethod
    def to_advisory(score_data):
        advisories = []
        for cve_id in score_data:
            severities = []
            for cvss_score in score_data[cve_id]["cvss"]:
                score = None
                vector = None
                if cvss_score["version"] == "2.0":
                    score = VulnerabilitySeverity(
                        system=scoring_systems["cvssv2"], value=str(cvss_score["score"])
                    )
                    vector = VulnerabilitySeverity(
                        system=scoring_systems["cvssv2_vector"], value=str(cvss_score["vector"])
                    )

                elif cvss_score["version"] == "3":
                    score = VulnerabilitySeverity(
                        system=scoring_systems["cvssv3"], value=str(cvss_score["score"])
                    )
                    vector = VulnerabilitySeverity(
                        system=scoring_systems["cvssv3_vector"], value=str(cvss_score["vector"])
                    )

                elif cvss_score["version"] == "3.1":
                    score = VulnerabilitySeverity(
                        system=scoring_systems["cvssv3.1"], value=str(cvss_score["score"])
                    )
                    vector = VulnerabilitySeverity(
                        system=scoring_systems["cvssv3.1_vector"], value=str(cvss_score["vector"])
                    )

                severities.extend([score, vector])

            advisories.append(
                Advisory(
                    vulnerability_id=cve_id,
                    summary="",
                    references=[Reference(url=URL, severities=severities)],
                )
            )
        return advisories
