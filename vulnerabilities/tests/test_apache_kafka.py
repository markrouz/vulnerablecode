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

from packageurl import PackageURL
from univers.version_specifier import VersionSpecifier

from vulnerabilities.helpers import AffectedPackage
from vulnerabilities.importer import Advisory
from vulnerabilities.importer import Reference
from vulnerabilities.importers.apache_kafka import ApacheKafkaImporter
from vulnerabilities.importers.apache_kafka import to_version_ranges
from vulnerabilities.package_managers import GitHubTagsAPI
from vulnerabilities.package_managers import Version

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "apache_kafka", "cve-list.html")


class TestApacheKafkaImporter(TestCase):
    def test_to_version_ranges(self):
        # Check single version
        assert [
            VersionSpecifier.from_scheme_version_spec_string("maven", "=3.2.2")
        ] == to_version_ranges("3.2.2")

        # Check range with lower and upper bounds
        assert [
            VersionSpecifier.from_scheme_version_spec_string("maven", ">=3.2.2, <=3.2.3")
        ] == to_version_ranges("3.2.2 to 3.2.3")

        # Check range with "and later"
        assert [
            VersionSpecifier.from_scheme_version_spec_string("maven", ">=3.2.2")
        ] == to_version_ranges("3.2.2 and later")

        # Check combination of above cases
        assert [
            VersionSpecifier.from_scheme_version_spec_string("maven", ">=3.2.2"),
            VersionSpecifier.from_scheme_version_spec_string("maven", ">=3.2.2, <=3.2.3"),
            VersionSpecifier.from_scheme_version_spec_string("maven", "==3.2.2"),
        ] == to_version_ranges("3.2.2 and later, 3.2.2 to 3.2.3, 3.2.2")

    def test_to_advisory(self):
        data_source = ApacheKafkaImporter(batch_size=1)
        data_source.version_api = GitHubTagsAPI(
            cache={"apache/kafka": [Version("2.1.2"), Version("0.10.2.2")]}
        )
        expected_advisories = [
            Advisory(
                summary="In Apache Kafka versions between 0.11.0.0 and 2.1.0, it is possible to manually\n    craft a Produce request which bypasses transaction/idempotent ACL validation.\n    Only authenticated clients with Write permission on the respective topics are\n    able to exploit this vulnerability. Users should upgrade to 2.1.1 or later\n    where this vulnerability has been fixed.",
                vulnerability_id="CVE-2018-17196",
                affected_packages=[
                    AffectedPackage(
                        vulnerable_package=PackageURL(
                            type="apache",
                            namespace=None,
                            name="kafka",
                            version="0.10.2.2",
                            qualifiers={},
                            subpath=None,
                        ),
                        patched_package=PackageURL(
                            type="apache",
                            namespace=None,
                            name="kafka",
                            version="2.1.2",
                            qualifiers={},
                            subpath=None,
                        ),
                    )
                ],
                references=[
                    Reference(
                        reference_id="", url="https://kafka.apache.org/cve-list", severities=[]
                    ),
                    Reference(
                        reference_id="CVE-2018-17196",
                        url="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17196",
                        severities=[],
                    ),
                ],
            )
        ]
        with open(TEST_DATA) as f:
            found_advisories = data_source.to_advisory(f)

        found_advisories = list(map(Advisory.normalized, found_advisories))
        expected_advisories = list(map(Advisory.normalized, expected_advisories))
        assert sorted(found_advisories) == sorted(expected_advisories)
