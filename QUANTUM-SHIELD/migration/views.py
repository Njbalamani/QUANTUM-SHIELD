from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import SAFE_METHODS
from rest_framework.response import Response

from core.audit import record_audit
from core.permissions import IsAnalystOrAdmin, IsViewerOrHigher

from .models import MigrationPlan, MigrationTask, TaskStatus
from .serializers import (
    MigrationPlanCreateSerializer,
    MigrationPlanSerializer,
    MigrationTaskSerializer,
    MigrationTaskUpdateSerializer,
)
from .services import generate_tasks_for_plan, plan_summary, update_task_status


class MigrationPlanViewSet(viewsets.ModelViewSet):
    queryset = MigrationPlan.objects.prefetch_related("tasks").select_related("organization", "created_by").all()
    serializer_class = MigrationPlanSerializer
    filter_backends = (filters.OrderingFilter,)
    ordering_fields = ("name", "status", "created_at")
    ordering = ("-created_at",)

    def get_serializer_class(self):
        if self.action == "create":
            return MigrationPlanCreateSerializer
        return MigrationPlanSerializer

    def get_permissions(self):
        if self.request.method in SAFE_METHODS:
            return [IsViewerOrHigher()]
        return [IsAnalystOrAdmin()]

    def perform_create(self, serializer):
        instance = serializer.save(created_by=self.request.user)
        record_audit(
            self.request,
            "migration.plan.create",
            obj=instance,
            details={"name": instance.name, "status": instance.status},
        )

    def perform_update(self, serializer):
        instance = serializer.save()
        record_audit(
            self.request,
            "migration.plan.update",
            obj=instance,
            details={"fields": sorted(serializer.validated_data)},
        )

    def perform_destroy(self, instance):
        record_audit(self.request, "migration.plan.delete", obj=instance)
        instance.delete()

    @action(detail=True, methods=["post"], url_path="generate-tasks", permission_classes=[IsAnalystOrAdmin])
    def generate_tasks(self, request, pk=None):
        plan = self.get_object()
        created = generate_tasks_for_plan(plan, request=request)
        data = MigrationPlanSerializer(plan, context=self.get_serializer_context()).data
        data["created"] = created
        return Response(data)

    @action(detail=True, methods=["get"])
    def summary(self, request, pk=None):
        plan = self.get_object()
        return Response(plan_summary(plan))


class MigrationTaskViewSet(viewsets.ModelViewSet):
    queryset = MigrationTask.objects.select_related("plan", "asset").all()
    serializer_class = MigrationTaskSerializer
    filter_backends = (filters.OrderingFilter,)
    ordering_fields = ("status", "priority", "due_date", "created_at")
    ordering = ("id",)

    def get_serializer_class(self):
        if self.action in {"update", "partial_update"}:
            return MigrationTaskUpdateSerializer
        return MigrationTaskSerializer

    def get_permissions(self):
        if self.request.method in SAFE_METHODS:
            return [IsViewerOrHigher()]
        return [IsAnalystOrAdmin()]

    def get_queryset(self):
        queryset = super().get_queryset()
        plan = self.request.query_params.get("plan")
        if plan:
            if plan.isdigit():
                queryset = queryset.filter(plan_id=plan)
            else:
                queryset = queryset.none()
        return queryset

    def perform_create(self, serializer):
        instance = serializer.save()
        record_audit(
            self.request,
            "migration.task.create",
            obj=instance,
            details={"plan_id": instance.plan_id, "status": instance.status},
        )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        status_value = data.get("status")

        if "priority" in data:
            instance.priority = data["priority"]
        if "due_date" in data:
            instance.due_date = data["due_date"]

        if status_value is not None:
            update_task_status(
                instance,
                status_value,
                notes=data.get("notes"),
                request=request,
                user=request.user,
            )
        else:
            if "notes" in data:
                notes = data["notes"]
                instance.notes = f"{instance.notes}\n{notes}".strip() if instance.notes else notes
            instance.save()
            record_audit(
                request,
                "migration.task.update",
                obj=instance,
                details={"fields": sorted(data)},
            )

        output = MigrationTaskSerializer(instance, context=self.get_serializer_context())
        return Response(output.data)

    def perform_destroy(self, instance):
        record_audit(self.request, "migration.task.delete", obj=instance)
        instance.delete()

    @action(detail=True, methods=["post"], permission_classes=[IsAnalystOrAdmin])
    def complete(self, request, pk=None):
        task = self.get_object()
        update_task_status(
            task,
            TaskStatus.COMPLETED,
            notes=request.data.get("notes"),
            request=request,
            user=request.user,
        )
        return Response(self.get_serializer(task).data)
