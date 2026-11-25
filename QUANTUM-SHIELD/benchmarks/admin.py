from django.contrib import admin

from .models import BenchmarkMeasurement, BenchmarkRun


@admin.register(BenchmarkRun)
class BenchmarkRunAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "operation",
        "algorithm",
        "status",
        "iterations",
        "warmup_iterations",
        "organization",
        "requested_by",
        "created_at",
    )
    list_filter = ("operation", "status", "organization")
    search_fields = ("algorithm", "task_id", "organization__name", "requested_by__username")
    readonly_fields = ("task_id", "summary", "created_at", "started_at", "completed_at")
    date_hierarchy = "created_at"


@admin.register(BenchmarkMeasurement)
class BenchmarkMeasurementAdmin(admin.ModelAdmin):
    list_display = ("id", "run", "iteration", "phase", "duration_ms", "success", "created_at_display")
    list_filter = ("phase", "success")
    search_fields = ("run__algorithm", "run__task_id")
    readonly_fields = ("run", "iteration", "phase", "duration_ms", "success", "detail")
    raw_id_fields = ("run",)

    @admin.display(description="Created")
    def created_at_display(self, obj):
        return obj.run.created_at
