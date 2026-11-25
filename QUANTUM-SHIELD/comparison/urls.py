from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import ComparisonRunViewSet

router = DefaultRouter()
router.register("runs", ComparisonRunViewSet, basename="comparison-run")

urlpatterns = [
    path("", include(router.urls)),
]
