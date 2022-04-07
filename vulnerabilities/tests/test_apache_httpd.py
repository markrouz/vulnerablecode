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
import os
from unittest import TestCase

from packageurl import PackageURL
from univers.version_specifier import VersionSpecifier

from vulnerabilities.helpers import AffectedPackage
from vulnerabilities.importer import Advisory
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.importers.apache_httpd import ApacheHTTPDImporter
from vulnerabilities.package_managers import GitHubTagsAPI
from vulnerabilities.package_managers import Version
from vulnerabilities.severity_systems import scoring_systems

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "apache_httpd", "CVE-1999-1199.json")


class TestApacheHTTPDImporter(TestCase):
    @classmethod
    def setUpClass(cls):
        data_source_cfg = {"etags": {}}
        cls.data_src = ApacheHTTPDImporter(1, config=data_source_cfg)
        known_versions = [Version("1.3.2"), Version("1.3.1"), Version("1.3.0")]
        cls.data_src.version_api = GitHubTagsAPI(cache={"apache/httpd": known_versions})
        with open(TEST_DATA) as f:
            cls.data = json.load(f)

    def test_to_version_ranges(self):
        data = [
            {
                "version_affected": "?=",
                "version_value": "1.3.0",
            },
            {
                "version_affected": "=",
                "version_value": "1.3.1",
            },
            {
                "version_affected": "<",
                "version_value": "1.3.2",
            },
        ]
        fixed_version_ranges, affected_version_ranges = self.data_src.to_version_ranges(data)

        # Check fixed packages
        assert [
            VersionSpecifier.from_scheme_version_spec_string("semver", ">=1.3.2")
        ] == fixed_version_ranges

        # Check vulnerable packages
        assert [
            VersionSpecifier.from_scheme_version_spec_string("semver", "==1.3.0"),
            VersionSpecifier.from_scheme_version_spec_string("semver", "==1.3.1"),
        ] == affected_version_ranges

    def test_to_advisory(self):
        expected_advisories = [
            Advisory(
                summary="A serious problem exists when a client sends a large number of "
                "headers with the same header name. Apache uses up memory faster than the "
                "amount of memory required to simply store the received data itself. That "
                "is, memory use increases faster and faster as more headers are received, "
                "rather than increasing at a constant rate. This makes a denial of service "
                "attack based on this method more effective than methods which cause Apache"
                " to use memory at a constant rate, since the attacker has to send less data.",
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="apache",
                            name="httpd",
                            version="1.3.0",
                        ),
                    ),
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="apache",
                            name="httpd",
                            version="1.3.1",
                        ),
                    ),
                ],
                references=[
                    Reference(
                        url="https://httpd.apache.org/security/json/CVE-1999-1199.json",
                        severities=[
                            VulnerabilitySeverity(
                                system=scoring_systems["apache_httpd"],
                                value="important",
                            ),
                        ],
                        reference_id="CVE-1999-1199",
                    ),
                ],
                vulnerability_id="CVE-1999-1199",
            )
        ]
        found_advisories = [self.data_src.to_advisory(self.data)]
        found_advisories = list(map(Advisory.normalized, found_advisories))
        expected_advisories = list(map(Advisory.normalized, expected_advisories))
        assert sorted(found_advisories) == sorted(expected_advisories)
