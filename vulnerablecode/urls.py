#
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

from django.contrib import admin
from django.urls import include
from django.urls import path
from rest_framework.routers import DefaultRouter

from vulnerabilities.api import PackageViewSet
from vulnerabilities.api import VulnerabilityViewSet
from vulnerabilities.views import HomePage
from vulnerabilities.views import PackageCreate
from vulnerabilities.views import PackageRelatedVulnerablityCreate
from vulnerabilities.views import PackageRelatedVulnerablityDelete
from vulnerabilities.views import PackageSearchView
from vulnerabilities.views import PackageUpdate
from vulnerabilities.views import VulnerabilityCreate
from vulnerabilities.views import VulnerabilityDetails
from vulnerabilities.views import VulnerabilityReferenceCreate
from vulnerabilities.views import VulnerabilitySearchView
from vulnerabilities.views import schema_view
from vulnerablecode.settings import ENABLE_CURATION


# See the comment at https://stackoverflow.com/a/46163870.
class OptionalSlashRouter(DefaultRouter):
    def __init__(self, *args, **kwargs):
        super(DefaultRouter, self).__init__(*args, **kwargs)
        self.trailing_slash = "/?"


api_router = OptionalSlashRouter()
api_router.register(r"packages", PackageViewSet)
# `DefaultRouter` requires `basename` when registering viewsets which don't
# define a queryset.
api_router.register(r"vulnerabilities", VulnerabilityViewSet, basename="vulnerability")

curation_views = [
    path("vulnerabilities/create", VulnerabilityCreate.as_view(), name="vulnerability_create"),
    path("packages/create", PackageCreate.as_view(), name="package_create"),
    path(
        "relations/resolved/<int:pid>/<int:vid>",
        PackageRelatedVulnerablityDelete.as_view(),
        name="resolved_package_delete",
    ),
    path(
        "relations/impacted/<int:pid>/<int:vid>",
        PackageRelatedVulnerablityDelete.as_view(),
        name="impacted_package_delete",
    ),
    path(
        "relations/impacted/<int:pid>/create",
        PackageRelatedVulnerablityCreate.as_view(),
        name="impacted_package_create",
    ),
    path(
        "relations/resolved/<int:pid>/create",
        PackageRelatedVulnerablityCreate.as_view(),
        name="resolved_package_create",
    ),
    path(
        "relations/reference/<int:vid>/create",
        VulnerabilityReferenceCreate.as_view(),
        name="vulnerability_reference_create",
    ),
]
urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/docs", schema_view, name="redoc"),
    path("packages/search", PackageSearchView.as_view(), name="package_search"),
    path("packages/<int:pk>", PackageUpdate.as_view(), name="package_view"),
    path("vulnerabilities/<int:pk>", VulnerabilityDetails.as_view(), name="vulnerability_view"),
    path("vulnerabilities/search", VulnerabilitySearchView.as_view(), name="vulnerability_search"),
    path("", HomePage.as_view(), name="home"),
    path(r"api/", include(api_router.urls)),
]

if ENABLE_CURATION:
    urlpatterns.extend(curation_views)
