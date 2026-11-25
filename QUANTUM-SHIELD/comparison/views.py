from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import SAFE_METHODS
from rest_framework.response import Response

from core.audit import record_audit
from core.models import AlgorithmProfile
from core.permissions import IsAnalystOrAdmin, IsViewerOrHigher

from .models import ComparisonRun
from .serializers import ComparisonCreateSerializer, ComparisonRunSerializer
from .services import build_comparison


class ComparisonRunViewSet(viewsets.ModelViewSet):
    queryset = ComparisonRun.objects.select_related("organization", "requested_by").all()
    serializer_class = ComparisonRunSerializer

    def get_serializer_class(self):
        if self.action == "create":
            return ComparisonCreateSerializer
        return ComparisonRunSerializer

    def get_permissions(self):
        if self.action in {"preview", "available_algorithms"}:
            return [permission() for permission in self.permission_classes]
        if self.request.method in SAFE_METHODS:
            return [IsViewerOrHigher()]
        return [IsAnalystOrAdmin()]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        data = ComparisonRunSerializer(serializer.instance, context=self.get_serializer_context()).data
        return Response(data, status=status.HTTP_201_CREATED, headers=self.get_success_headers(data))

    def perform_create(self, serializer):
        data = serializer.validated_data
        summary = build_comparison(
            data["name"],
            data["scope"],
            organization=data.get("organization"),
            algorithms=data.get("algorithms"),
        )
        instance = serializer.save(requested_by=self.request.user, summary=summary)
        record_audit(
            self.request,
            "comparison.create",
            obj=instance,
            details={"name": instance.name, "scope": instance.scope},
        )

    def perform_destroy(self, instance):
        record_audit(self.request, "comparison.delete", obj=instance)
        instance.delete()

    @action(detail=False, methods=["post"], url_path="preview", permission_classes=[IsAnalystOrAdmin])
    def preview(self, request):
        serializer = ComparisonCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        payload = build_comparison(
            data["name"],
            data["scope"],
            organization=data.get("organization"),
            algorithms=data.get("algorithms"),
        )
        return Response(payload)

    @action(
        detail=False,
        methods=["get"],
        url_path="available-algorithms",
        permission_classes=[IsViewerOrHigher],
    )
    def available_algorithms(self, request):
        rows = AlgorithmProfile.objects.values(
            "id", "name", "family", "operation", "supported", "deprecated"
        )
        return Response(list(rows))
