from rest_framework import serializers

from core.models import Organization

from .models import Scan, ScanFinding, ScanPattern, ScanSource


class ScanPatternSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanPattern
        fields = (
            "id",
            "name",
            "description",
            "pattern",
            "category",
            "severity",
            "recommendation",
            "enabled",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


class ScanFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanFinding
        fields = (
            "id",
            "scan",
            "pattern",
            "line_number",
            "column_number",
            "matched_text",
            "severity",
            "category",
            "message",
            "recommendation",
            "created_at",
        )
        read_only_fields = fields


class ScanSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True, allow_null=True)
    created_by_username = serializers.CharField(source="created_by.username", read_only=True, allow_null=True)
    finding_count = serializers.SerializerMethodField()
    high_severity_count = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = (
            "id",
            "organization",
            "organization_name",
            "name",
            "source",
            "location",
            "content_hash",
            "status",
            "summary",
            "created_by",
            "created_by_username",
            "finding_count",
            "high_severity_count",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields

    def get_finding_count(self, obj):
        return len(obj.findings.all())

    def get_high_severity_count(self, obj):
        return sum(1 for finding in obj.findings.all() if finding.severity in {"high", "critical"})


class ScanCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=200, required=False, allow_blank=True)
    organization = serializers.PrimaryKeyRelatedField(
        queryset=Organization.objects.all(), required=False, allow_null=True
    )
    text = serializers.CharField(required=False, allow_blank=False, trim_whitespace=False)
    file = serializers.FileField(required=False)
    source = serializers.ChoiceField(choices=ScanSource.choices, required=False)

    def validate(self, attrs):
        text = attrs.get("text")
        uploaded_file = attrs.get("file")
        if bool(text) == bool(uploaded_file):
            raise serializers.ValidationError("Provide exactly one of text or file.")
        if not attrs.get("name"):
            if uploaded_file is not None:
                attrs["name"] = f"File scan: {uploaded_file.name}"[:200]
            else:
                attrs["name"] = "Text scan"
        return attrs
