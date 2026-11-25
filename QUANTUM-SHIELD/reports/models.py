from django.conf import settings
from django.db import models


class ReportKind(models.TextChoices):
    OVERVIEW = "overview", "Overview"
    INVENTORY = "inventory", "Inventory"
    SCANNER = "scanner", "Scanner"
    BENCHMARK = "benchmark", "Benchmark"
    MIGRATION = "migration", "Migration"
    COMPARISON = "comparison", "Comparison"


class ReportFormat(models.TextChoices):
    JSON = "json", "JSON"
    CSV = "csv", "CSV"


class ReportStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    READY = "ready", "Ready"
    FAILED = "failed", "Failed"


class Report(models.Model):
    organization = models.ForeignKey(
        "core.Organization",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reports",
    )
    title = models.CharField(max_length=200)
    kind = models.CharField(max_length=24, choices=ReportKind.choices)
    format = models.CharField(max_length=8, choices=ReportFormat.choices, default=ReportFormat.JSON)
    status = models.CharField(max_length=16, choices=ReportStatus.choices, default=ReportStatus.PENDING)
    filters = models.JSONField(default=dict, blank=True)
    summary = models.JSONField(default=dict, blank=True)
    content = models.TextField(blank=True)
    error = models.TextField(blank=True)
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reports_generated",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return self.title
