from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    AlgorithmProfileViewSet,
    AuditLogViewSet,
    CryptographicAssetViewSet,
    OrganizationViewSet,
)

router = DefaultRouter()
router.register("organizations", OrganizationViewSet, basename="organization")
router.register("assets", CryptographicAssetViewSet, basename="asset")
router.register("algorithm-profiles", AlgorithmProfileViewSet, basename="algorithm-profile")
router.register("audit-logs", AuditLogViewSet, basename="audit-log")

urlpatterns = [
    path("", include(router.urls)),
]
