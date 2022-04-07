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

import subprocess
import sys
import unittest
from os.path import dirname
from os.path import join

root_dir = dirname(dirname(dirname(__file__)))
bin_dir = dirname(sys.executable)


class BaseTests(unittest.TestCase):
    def test_codestyle(self):
        args = join(bin_dir, "black --check -l 100 .")
        try:
            subprocess.check_output(args.split(), cwd=root_dir)
        except Exception as e:
            raise Exception(
                "Black style check failed, please format the code using black -l 100 . "
                "Alternatively, run ``make valid``"
            ) from e

        args = join(bin_dir, "isort --check-only .")
        try:
            subprocess.check_output(args.split(), cwd=root_dir)
        except Exception as e:
            raise Exception(
                "Unsorted imports, please sort your imports using isort. "
                "Alternatively, run ``make valid``"
            ) from e
