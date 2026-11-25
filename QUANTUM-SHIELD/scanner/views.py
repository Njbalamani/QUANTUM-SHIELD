from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import SAFE_METHODS
from rest_framework.response import Response

from core.audit import record_audit
from core.permissions import IsAnalystOrAdmin, IsViewerOrHigher

from .models import Scan, ScanFinding, ScanPattern, ScanSource
from .serializers import ScanCreateSerializer, ScanFindingSerializer, ScanPatternSerializer, ScanSerializer
from .services import ensure_default_patterns, scan_text, scan_upload


class ScanViewSet(viewsets.ModelViewSet):
    queryset = Scan.objects.prefetch_related("findings").select_related("organization", "created_by").all()
    serializer_class = ScanSerializer
    filter_backends = (filters.OrderingFilter,)
    ordering_fields = ("name", "created_at", "status")
    ordering = ("-created_at",)

    def get_serializer_class(self):
        if self.action == "create":
            return ScanCreateSerializer
        return ScanSerializer

    def get_permissions(self):
        if self.request.method in SAFE_METHODS:
            return [IsViewerOrHigher()]
        return [IsAnalystOrAdmin()]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        kwargs = {
            "name": data["name"],
            "organization": data.get("organization"),
            "created_by": request.user,
            "request": request,
        }
        try:
            if data.get("file") is not None:
                scan = scan_upload(data["file"], **kwargs)
            else:
                scan = scan_text(
                    data["text"],
                    source=data.get("source", ScanSource.TEXT),
                    **kwargs,
                )
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        output = ScanSerializer(scan, context=self.get_serializer_context())
        headers = self.get_success_headers(output.data)
        return Response(output.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_destroy(self, instance):
        record_audit(self.request, "scanner.scan.delete", obj=instance)
        instance.delete()

    @action(detail=True, methods=["get"])
    def findings(self, request, pk=None):
        scan = self.get_object()
        queryset = scan.findings.select_related("pattern").all()
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = ScanFindingSerializer(page, many=True, context=self.get_serializer_context())
            return self.get_paginated_response(serializer.data)
        serializer = ScanFindingSerializer(queryset, many=True, context=self.get_serializer_context())
        return Response(serializer.data)


class ScanFindingViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ScanFinding.objects.select_related("scan", "pattern").all()
    serializer_class = ScanFindingSerializer
    permission_classes = (IsViewerOrHigher,)
    filter_backends = (filters.OrderingFilter,)
    ordering_fields = ("line_number", "column_number", "created_at")
    ordering = ("line_number", "column_number", "id")

    def get_queryset(self):
        queryset = super().get_queryset()
        scan = self.request.query_params.get("scan")
        if scan:
            if scan.isdigit():
                queryset = queryset.filter(scan_id=scan)
            else:
                queryset = queryset.none()
        return queryset


class ScanPatternViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ScanPattern.objects.all()
    serializer_class = ScanPatternSerializer
    permission_classes = (IsViewerOrHigher,)
    filter_backends = (filters.OrderingFilter,)
    ordering_fields = ("name", "category", "severity", "updated_at")

    @action(detail=False, methods=["post"], permission_classes=[IsAnalystOrAdmin])
    def seed(self, request):
        created = ensure_default_patterns()
        record_audit(request, "scanner.patterns.seed", details={"created": created})
        return Response({"created": created})
