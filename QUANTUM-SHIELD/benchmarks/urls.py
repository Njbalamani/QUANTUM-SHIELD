from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import BenchmarkRunViewSet

router = DefaultRouter()
router.register("runs", BenchmarkRunViewSet, basename="benchmark-run")

urlpatterns = [
    path("", include(router.urls)),
]
