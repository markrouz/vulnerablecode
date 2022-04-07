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
from unittest.mock import MagicMock
from unittest.mock import patch

from vulnerabilities.importer import Advisory
from vulnerabilities.importer import Reference
from vulnerabilities.importers.alpine_linux import AlpineImporter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "alpine", "v3.11")


class AlpineImportTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_source = AlpineImporter(batch_size=1)

    def test__process_link(self):
        expected_advisories = [
            Advisory(
                summary="",
                references=[],
                vulnerability_id="CVE-2019-14904",
            ),
            Advisory(
                summary="",
                references=[],
                vulnerability_id="CVE-2019-14905",
            ),
            Advisory(
                summary="",
                references=[],
                vulnerability_id="CVE-2019-14846",
            ),
            Advisory(
                summary="",
                references=[],
                vulnerability_id="CVE-2019-14856",
            ),
            Advisory(
                summary="",
                references=[],
                vulnerability_id="CVE-2019-14858",
            ),
            Advisory(
                summary="",
                references=[
                    Reference(
                        url="https://xenbits.xen.org/xsa/advisory-295.html", reference_id="XSA-295"
                    )
                ],
                vulnerability_id="",
            ),
        ]
        mock_requests = MagicMock()
        mock_content = MagicMock()
        with open(os.path.join(TEST_DATA, "main.yaml")) as f:
            mock_requests.get = lambda x: mock_content
            mock_content.content = f
            with patch("vulnerabilities.importers.alpine_linux.requests", new=mock_requests):
                found_advisories = self.data_source._process_link("does not matter")

                found_advisories = list(map(Advisory.normalized, found_advisories))
                expected_advisories = list(map(Advisory.normalized, expected_advisories))
                assert sorted(found_advisories) == sorted(expected_advisories)
