from rest_framework import serializers

from core.models import Organization

from .models import ComparisonRun, ComparisonScope


class ComparisonRunSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True, allow_null=True)
    requested_by_username = serializers.CharField(source="requested_by.username", read_only=True, allow_null=True)

    class Meta:
        model = ComparisonRun
        fields = (
            "id",
            "organization",
            "organization_name",
            "name",
            "scope",
            "algorithms",
            "summary",
            "requested_by_username",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


class ComparisonCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=200)
    scope = serializers.ChoiceField(choices=ComparisonScope.choices)
    organization = serializers.PrimaryKeyRelatedField(
        queryset=Organization.objects.all(), required=False, allow_null=True
    )
    algorithms = serializers.ListField(child=serializers.CharField(), required=False, default=list)

    def validate(self, attrs):
        if attrs.get("scope") == ComparisonScope.ALGORITHMS and not attrs.get("algorithms"):
            raise serializers.ValidationError({"algorithms": "At least one algorithm is required."})
        return attrs

    def create(self, validated_data):
        return ComparisonRun.objects.create(**validated_data)
