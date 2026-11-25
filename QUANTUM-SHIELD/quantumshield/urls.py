from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api-auth/", include("rest_framework.urls")),
    path("api/accounts/", include("accounts.urls")),
    path("api/inventory/", include("inventory.urls")),
    path("api/pq/", include("pq_lab.urls")),
    path("api/comparison/", include("comparison.urls")),
    path("api/scanner/", include("scanner.urls")),
    path("api/benchmarks/", include("benchmarks.urls")),
    path("api/migration/", include("migration.urls")),
    path("api/reports/", include("reports.urls")),
    path("", include("dashboard.urls")),
]
