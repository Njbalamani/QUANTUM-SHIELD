from rest_framework import serializers

from .models import MigrationPlan, MigrationTask, TaskPriority, TaskStatus


class MigrationPlanSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source="organization.name", read_only=True, allow_null=True)
    created_by_username = serializers.CharField(source="created_by.username", read_only=True, allow_null=True)
    task_count = serializers.IntegerField(source="tasks.count", read_only=True)
    progress = serializers.DictField(read_only=True)

    class Meta:
        model = MigrationPlan
        fields = (
            "id",
            "organization",
            "organization_name",
            "name",
            "description",
            "target_algorithm",
            "target_family",
            "status",
            "owner",
            "created_by",
            "created_by_username",
            "task_count",
            "progress",
            "created_at",
            "updated_at",
            "completed_at",
        )
        read_only_fields = fields


class MigrationPlanCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = MigrationPlan
        fields = (
            "name",
            "description",
            "organization",
            "target_algorithm",
            "target_family",
            "owner",
            "status",
        )
        extra_kwargs = {
            "description": {"required": False, "allow_blank": True},
            "organization": {"required": False, "allow_null": True},
            "target_family": {"required": False},
            "owner": {"required": False, "allow_blank": True},
            "status": {"required": False},
        }


class MigrationTaskSerializer(serializers.ModelSerializer):
    asset_name = serializers.CharField(source="asset.name", read_only=True, allow_null=True)
    plan_name = serializers.CharField(source="plan.name", read_only=True)

    class Meta:
        model = MigrationTask
        fields = (
            "id",
            "plan",
            "plan_name",
            "asset",
            "asset_name",
            "from_algorithm",
            "to_algorithm",
            "status",
            "priority",
            "notes",
            "due_date",
            "completed_at",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "created_at", "updated_at")


class MigrationTaskUpdateSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=TaskStatus.choices, required=True)
    notes = serializers.CharField(required=False, allow_blank=True)
    priority = serializers.ChoiceField(choices=TaskPriority.choices, required=False)
    due_date = serializers.DateField(required=False, allow_null=True)
