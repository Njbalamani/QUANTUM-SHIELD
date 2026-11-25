from django.db.models import Q
from rest_framework import filters, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import SAFE_METHODS
from rest_framework.response import Response

from core.audit import record_audit
from core.models import AlgorithmProfile, AssetStatus, AuditLog, CryptographicAsset, Organization
from core.permissions import IsAdminRole, IsAnalystOrAdmin, IsViewerOrHigher

try:
    from django_filters.rest_framework import DjangoFilterBackend
except ImportError:
    DjangoFilterBackend = None

from .serializers import (
    AlgorithmProfileSerializer,
    AuditLogSerializer,
    CryptographicAssetSerializer,
    OrganizationSerializer,
)


def _audit_details(serializer):
    return {"fields": sorted(serializer.validated_data)}


class OrganizationViewSet(viewsets.ModelViewSet):
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer

    def get_permissions(self):
        if self.request.method in SAFE_METHODS:
            return [IsViewerOrHigher()]
        return [IsAnalystOrAdmin()]

    def perform_create(self, serializer):
        instance = serializer.save()
        record_audit(self.request, "organization.create", obj=instance, details=_audit_details(serializer))

    def perform_update(self, serializer):
        instance = serializer.save()
        record_audit(self.request, "organization.update", obj=instance, details=_audit_details(serializer))

    def perform_destroy(self, instance):
        record_audit(self.request, "organization.delete", obj=instance)
        instance.delete()


class CryptographicAssetViewSet(viewsets.ModelViewSet):
    queryset = CryptographicAsset.objects.select_related("organization", "created_by").all()
    serializer_class = CryptographicAssetSerializer
    filter_backends = (filters.OrderingFilter,)
    ordering_fields = ("name", "criticality", "updated_at")

    if DjangoFilterBackend is not None:
        filter_backends = (DjangoFilterBackend, filters.OrderingFilter)
        filterset_fields = ("organization", "criticality", "status", "asset_type")

    def get_permissions(self):
        if self.request.method in SAFE_METHODS:
            return [IsViewerOrHigher()]
        return [IsAnalystOrAdmin()]

    def get_queryset(self):
        queryset = super().get_queryset()
        if DjangoFilterBackend is not None:
            return queryset

        params = self.request.query_params
        organizations = [value for value in params.getlist("organization") if value]
        if organizations:
            organization_filter = Q()
            for value in organizations:
                if value.isdigit():
                    organization_filter |= Q(organization_id=value)
                else:
                    organization_filter |= Q(organization__slug=value) | Q(organization__name=value)
            queryset = queryset.filter(organization_filter)

        for field in ("criticality", "status", "asset_type"):
            values = [value for value in params.getlist(field) if value]
            if values:
                queryset = queryset.filter(**{f"{field}__in": values})
        return queryset

    def perform_create(self, serializer):
        instance = serializer.save(created_by=self.request.user)
        record_audit(self.request, "asset.create", obj=instance, details=_audit_details(serializer))

    def perform_update(self, serializer):
        instance = serializer.save()
        record_audit(self.request, "asset.update", obj=instance, details=_audit_details(serializer))

    def perform_destroy(self, instance):
        record_audit(self.request, "asset.delete", obj=instance)
        instance.delete()

    @action(detail=True, methods=["post"], permission_classes=[IsAnalystOrAdmin])
    def mark_retired(self, request, pk=None):
        asset = self.get_object()
        previous_status = asset.status
        asset.status = AssetStatus.RETIRED
        asset.save(update_fields=["status", "updated_at"])
        record_audit(
            request,
            "asset.mark_retired",
            obj=asset,
            details={"previous_status": previous_status, "status": AssetStatus.RETIRED},
        )
        return Response(self.get_serializer(asset).data)


class AlgorithmProfileViewSet(viewsets.ModelViewSet):
    queryset = AlgorithmProfile.objects.all()
    serializer_class = AlgorithmProfileSerializer

    def get_permissions(self):
        if self.request.method in SAFE_METHODS:
            return [IsViewerOrHigher()]
        return [IsAdminRole()]

    def perform_create(self, serializer):
        instance = serializer.save()
        record_audit(self.request, "algorithm_profile.create", obj=instance, details=_audit_details(serializer))

    def perform_update(self, serializer):
        instance = serializer.save()
        record_audit(self.request, "algorithm_profile.update", obj=instance, details=_audit_details(serializer))

    def perform_destroy(self, instance):
        record_audit(self.request, "algorithm_profile.delete", obj=instance)
        instance.delete()


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AuditLog.objects.select_related("user").all()
    serializer_class = AuditLogSerializer
    permission_classes = (IsAdminRole,)
    filter_backends = (filters.OrderingFilter,)
    ordering = ("-created_at",)
    ordering_fields = ("created_at",)
