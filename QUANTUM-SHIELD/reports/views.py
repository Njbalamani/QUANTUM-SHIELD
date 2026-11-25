from django.http import HttpResponse
from django.utils.text import slugify
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import SAFE_METHODS
from rest_framework.response import Response

from core.audit import record_audit
from core.permissions import IsAnalystOrAdmin, IsViewerOrHigher

from .models import Report, ReportFormat
from .serializers import ReportCreateSerializer, ReportSerializer
from .services import build_report, generate_report


class ReportViewSet(viewsets.ModelViewSet):
    queryset = Report.objects.select_related("organization", "generated_by").all()
    serializer_class = ReportSerializer

    def get_serializer_class(self):
        if self.action == "create":
            return ReportCreateSerializer
        return ReportSerializer

    def get_permissions(self):
        if self.action in {"preview", "download"}:
            return [permission() for permission in self.permission_classes]
        if self.request.method in SAFE_METHODS:
            return [IsViewerOrHigher()]
        return [IsAnalystOrAdmin()]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        data = ReportSerializer(serializer.instance, context=self.get_serializer_context()).data
        return Response(data, status=status.HTTP_201_CREATED, headers=self.get_success_headers(data))

    def perform_create(self, serializer):
        data = serializer.validated_data
        serializer.instance = generate_report(
            title=data["title"],
            kind=data["kind"],
            format=data["format"],
            organization=data.get("organization"),
            filters=data.get("filters", {}),
            generated_by=self.request.user,
            request=self.request,
        )

    def perform_destroy(self, instance):
        record_audit(self.request, "report.delete", obj=instance)
        instance.delete()

    @action(detail=True, methods=["get"], permission_classes=[IsViewerOrHigher])
    def download(self, request, pk=None):
        report = self.get_object()
        is_csv = report.format == ReportFormat.CSV
        content_type = "text/csv" if is_csv else "application/json"
        extension = "csv" if is_csv else "json"
        filename = "{0}.{1}".format(slugify(report.title) or "report", extension)
        response = HttpResponse(report.content, content_type=content_type)
        response["Content-Disposition"] = 'attachment; filename="{0}"'.format(filename)
        return response

    @action(detail=False, methods=["post"], permission_classes=[IsAnalystOrAdmin])
    def preview(self, request):
        serializer = ReportCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        payload = build_report(
            data["kind"],
            organization=data.get("organization"),
            filters=data.get("filters", {}),
        )
        return Response(payload)
