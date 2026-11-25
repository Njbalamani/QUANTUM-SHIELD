from rest_framework import serializers

from core.models import AlgorithmProfile, AuditLog, CryptographicAsset, Organization


class OrganizationSerializer(serializers.ModelSerializer):
    asset_count = serializers.IntegerField(source="assets.count", read_only=True)

    class Meta:
        model = Organization
        fields = (
            "id",
            "name",
            "slug",
            "description",
            "industry",
            "asset_count",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "created_at", "updated_at")


class CryptographicAssetSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True)
    created_by_username = serializers.CharField(source="created_by.username", read_only=True, allow_null=True)
    pq_risk = serializers.BooleanField(read_only=True)

    class Meta:
        model = CryptographicAsset
        fields = (
            "id",
            "organization",
            "organization_name",
            "name",
            "asset_type",
            "algorithm",
            "key_size",
            "protocol",
            "owner",
            "location",
            "criticality",
            "status",
            "description",
            "discovered_at",
            "created_by",
            "created_by_username",
            "pq_risk",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "created_by", "created_at", "updated_at")


class AlgorithmProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlgorithmProfile
        fields = (
            "id",
            "name",
            "family",
            "operation",
            "security_level",
            "standard",
            "public_key_size",
            "private_key_size",
            "output_size",
            "implementation_source",
            "supported",
            "deprecated",
            "notes",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "created_at", "updated_at")


class AuditLogSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True, allow_null=True)

    class Meta:
        model = AuditLog
        fields = (
            "id",
            "user",
            "username",
            "action",
            "object_type",
            "object_id",
            "details",
            "ip_address",
            "user_agent",
            "created_at",
        )
        read_only_fields = fields
