from rest_framework import serializers

from core.models import Organization

from .models import Report, ReportFormat, ReportKind


class ReportSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True, allow_null=True)
    generated_by_username = serializers.CharField(source="generated_by.username", read_only=True, allow_null=True)

    class Meta:
        model = Report
        fields = (
            "id",
            "organization",
            "organization_name",
            "title",
            "kind",
            "format",
            "status",
            "filters",
            "summary",
            "content",
            "error",
            "generated_by_username",
            "created_at",
            "completed_at",
        )
        read_only_fields = fields


class ReportCreateSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=200)
    kind = serializers.ChoiceField(choices=ReportKind.choices)
    format = serializers.ChoiceField(choices=ReportFormat.choices, default=ReportFormat.JSON)
    organization = serializers.PrimaryKeyRelatedField(
        queryset=Organization.objects.all(), required=False, allow_null=True
    )
    filters = serializers.DictField(required=False, default=dict)
