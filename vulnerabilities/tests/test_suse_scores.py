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

import os
from unittest import TestCase

from vulnerabilities.helpers import load_yaml
from vulnerabilities.importer import Advisory
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.importers.suse_scores import SUSESeverityScoreImporter
from vulnerabilities.severity_systems import ScoringSystem

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/suse_scores", "suse-cvss-scores.yaml")


class TestSUSESeverityScoreImporter(TestCase):
    def test_to_advisory(self):
        raw_data = load_yaml(TEST_DATA)
        expected_data = [
            Advisory(
                summary="",
                references=[
                    Reference(
                        reference_id="",
                        url="https://ftp.suse.com/pub/projects/security/yaml/suse-cvss-scores.yaml",
                        severities=[
                            VulnerabilitySeverity(
                                system=ScoringSystem(
                                    identifier="cvssv2",
                                    name="CVSSv2 Base Score",
                                    url="https://www.first.org/cvss/v2/",
                                    notes="cvssv2 base score",
                                ),
                                value="4.3",
                            ),
                            VulnerabilitySeverity(
                                system=ScoringSystem(
                                    identifier="cvssv2_vector",
                                    name="CVSSv2 Vector",
                                    url="https://www.first.org/cvss/v2/",
                                    notes="cvssv2 vector, used to get additional info about nature and severity of vulnerability",  # nopep8
                                ),
                                value="AV:N/AC:M/Au:N/C:N/I:N/A:P",
                            ),
                            VulnerabilitySeverity(
                                system=ScoringSystem(
                                    identifier="cvssv3.1",
                                    name="CVSSv3.1 Base Score",
                                    url="https://www.first.org/cvss/v3-1/",
                                    notes="cvssv3.1 base score",
                                ),
                                value="3.7",
                            ),
                            VulnerabilitySeverity(
                                system=ScoringSystem(
                                    identifier="cvssv3.1_vector",
                                    name="CVSSv3.1 Vector",
                                    url="https://www.first.org/cvss/v3-1/",
                                    notes="cvssv3.1 vector, used to get additional info about nature and severity of vulnerability",  # nopep8
                                ),
                                value="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
                            ),
                        ],
                    )
                ],
                vulnerability_id="CVE-2004-0230",
            ),
            Advisory(
                summary="",
                references=[
                    Reference(
                        reference_id="",
                        url="https://ftp.suse.com/pub/projects/security/yaml/suse-cvss-scores.yaml",
                        severities=[
                            VulnerabilitySeverity(
                                system=ScoringSystem(
                                    identifier="cvssv3",
                                    name="CVSSv3 Base Score",
                                    url="https://www.first.org/cvss/v3-0/",
                                    notes="cvssv3 base score",
                                ),
                                value="8.6",
                            ),
                            VulnerabilitySeverity(
                                system=ScoringSystem(
                                    identifier="cvssv3_vector",
                                    name="CVSSv3 Vector",
                                    url="https://www.first.org/cvss/v3-0/",
                                    notes="cvssv3 vector, used to get additional info about nature and severity of vulnerability",  # nopep8
                                ),
                                value="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                            ),
                        ],
                    )
                ],
                vulnerability_id="CVE-2003-1605",
            ),
        ]

        found_data = SUSESeverityScoreImporter.to_advisory(raw_data)
        found_advisories = list(map(Advisory.normalized, found_data))
        expected_advisories = list(map(Advisory.normalized, expected_data))
        assert sorted(found_advisories) == sorted(expected_advisories)
