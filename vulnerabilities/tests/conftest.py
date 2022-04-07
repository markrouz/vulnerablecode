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

import pytest


@pytest.fixture
def no_mkdir(monkeypatch):
    monkeypatch.delattr("os.mkdir")


@pytest.fixture
def no_rmtree(monkeypatch):
    monkeypatch.delattr("shutil.rmtree")


# TODO: Ignore these tests for now but we need to migrate each one of them to the new struture.
# Step 1: Fix importer_yielder: https://github.com/nexB/vulnerablecode/issues/501
# Step 2: Run test for importer only if it is activated (pytestmark = pytest.mark.skipif(...))
# Step 3: Migrate all the tests
collect_ignore = [
    "test_models.py",
    "test_msr2019.py",
    "test_nginx.py",
    "test_apache_httpd.py",
    "test_npm.py",
    "test_apache_kafka.py",
    "test_nvd.py",
    "test_apache_tomcat.py",
    "test_openssl.py",
    "test_api.py",
    "test_package_managers.py",
    "test_archlinux.py",
    "test_postgresql.py",
    "test_redhat_importer.py",
    "test_data_source.py",
    "test_retiredotnet.py",
    "test_debian.py",
    "test_ruby.py",
    "test_debian_oval.py",
    "test_rust.py",
    "test_elixir_security.py",
    "test_safety_db.py",
    "test_gentoo.py",
    "test_suse.py",
    "test_suse_backports.py",
    "test_suse_scores.py",
    "test_ubuntu.py",
    "test_ubuntu_usn.py",
    "test_importer_yielder.py",
    "test_upstream.py",
    "test_istio.py",
    "test_mozilla.py",
]
