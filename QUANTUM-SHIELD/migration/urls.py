from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import MigrationPlanViewSet, MigrationTaskViewSet

router = DefaultRouter()
router.register("plans", MigrationPlanViewSet, basename="migration-plan")
router.register("tasks", MigrationTaskViewSet, basename="migration-task")

urlpatterns = [
    path("", include(router.urls)),
]
