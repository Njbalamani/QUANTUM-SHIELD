from rest_framework import serializers

from core.models import Organization

from .models import BenchmarkMeasurement, BenchmarkOperation, BenchmarkRun


class BenchmarkRunSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True, allow_null=True)
    requested_by_username = serializers.CharField(source="requested_by.username", read_only=True, allow_null=True)
    measurement_count = serializers.IntegerField(source="measurements.count", read_only=True)

    class Meta:
        model = BenchmarkRun
        fields = (
            "id",
            "organization",
            "organization_name",
            "algorithm",
            "operation",
            "iterations",
            "warmup_iterations",
            "status",
            "task_id",
            "summary",
            "error",
            "requested_by_username",
            "measurement_count",
            "created_at",
            "started_at",
            "completed_at",
        )
        read_only_fields = fields


class BenchmarkMeasurementSerializer(serializers.ModelSerializer):
    class Meta:
        model = BenchmarkMeasurement
        fields = ("id", "run", "iteration", "phase", "duration_ms", "success", "detail")
        read_only_fields = fields


class BenchmarkCreateSerializer(serializers.Serializer):
    algorithm = serializers.CharField(max_length=128)
    operation = serializers.ChoiceField(choices=BenchmarkOperation.choices)
    iterations = serializers.IntegerField(required=False, min_value=1)
    warmup_iterations = serializers.IntegerField(required=False, min_value=0)
    organization = serializers.PrimaryKeyRelatedField(
        queryset=Organization.objects.all(), required=False, allow_null=True
    )


class BenchmarkCapabilitySerializer(serializers.Serializer):
    oqs_available = serializers.BooleanField()
    oqs_version = serializers.CharField(allow_null=True, required=False)
    enabled_kems = serializers.ListField(child=serializers.CharField(), required=False)
    enabled_signatures = serializers.ListField(child=serializers.CharField(), required=False)
    default_iterations = serializers.IntegerField()
    max_iterations = serializers.IntegerField()
    async_enabled = serializers.BooleanField()
