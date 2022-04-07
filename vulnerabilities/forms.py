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

from django import forms

from vulnerabilities.models import Package
from vulnerabilities.models import PackageRelatedVulnerability
from vulnerabilities.models import Vulnerability


def get_package_types():
    pkg_types = [(i.type, i.type) for i in Package.objects.distinct("type").all()]
    pkg_types.append((None, "Any type"))
    return pkg_types


def get_package_namespaces():
    pkg_namespaces = [
        (i.namespace, i.namespace)
        for i in Package.objects.distinct("namespace").all()
        if i.namespace
    ]
    pkg_namespaces.append((None, "package namespace"))
    return pkg_namespaces


class PackageForm(forms.Form):

    type = forms.ChoiceField(choices=get_package_types)
    name = forms.CharField(
        required=False, widget=forms.TextInput(attrs={"placeholder": "package name"})
    )


class CVEForm(forms.Form):

    vuln_id = forms.CharField(widget=forms.TextInput(attrs={"placeholder": "vulnerability id"}))
