from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import SAFE_METHODS
from rest_framework.response import Response

from core.audit import record_audit
from core.crypto import UnsupportedAlgorithmError, capability_report
from core.permissions import IsAnalystOrAdmin, IsViewerOrHigher

from .models import BenchmarkRun
from .serializers import (
    BenchmarkCapabilitySerializer,
    BenchmarkCreateSerializer,
    BenchmarkMeasurementSerializer,
    BenchmarkRunSerializer,
)
from .services import capabilities, create_benchmark_run


class BenchmarkRunViewSet(viewsets.ModelViewSet):
    queryset = BenchmarkRun.objects.select_related("organization", "requested_by").all()
    serializer_class = BenchmarkRunSerializer

    def get_serializer_class(self):
        if self.action == "create":
            return BenchmarkCreateSerializer
        if self.action == "measurements":
            return BenchmarkMeasurementSerializer
        if self.action == "capabilities":
            return BenchmarkCapabilitySerializer
        return BenchmarkRunSerializer

    def get_permissions(self):
        if self.action == "capabilities" or self.request.method in SAFE_METHODS:
            return [IsViewerOrHigher()]
        return [IsAnalystOrAdmin()]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            run = create_benchmark_run(
                algorithm=data["algorithm"],
                operation=data["operation"],
                iterations=data.get("iterations"),
                warmup_iterations=data.get("warmup_iterations"),
                organization=data.get("organization"),
                requested_by=request.user,
                request=request,
            )
        except (UnsupportedAlgorithmError, ValueError) as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        payload = BenchmarkRunSerializer(run, context=self.get_serializer_context()).data
        return Response(payload, status=status.HTTP_201_CREATED, headers=self.get_success_headers(payload))

    def perform_update(self, serializer):
        instance = serializer.save()
        record_audit(
            self.request,
            "benchmark.update",
            obj=instance,
            details={"fields": sorted(serializer.validated_data)},
        )

    def perform_destroy(self, instance):
        record_audit(self.request, "benchmark.delete", obj=instance)
        instance.delete()

    @action(detail=True, methods=["get"], permission_classes=[IsViewerOrHigher])
    def measurements(self, request, pk=None):
        run = self.get_object()
        serializer = self.get_serializer(run.measurements.all(), many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["get"], permission_classes=[IsViewerOrHigher])
    def capabilities(self, request):
        payload = capabilities(capability_report())
        serializer = self.get_serializer(data=payload)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)
