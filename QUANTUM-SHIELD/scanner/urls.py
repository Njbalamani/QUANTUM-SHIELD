from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import ScanFindingViewSet, ScanPatternViewSet, ScanViewSet

router = DefaultRouter()
router.register("scans", ScanViewSet, basename="scan")
router.register("findings", ScanFindingViewSet, basename="scan-finding")
router.register("patterns", ScanPatternViewSet, basename="scan-pattern")

urlpatterns = [
    path("", include(router.urls)),
]
