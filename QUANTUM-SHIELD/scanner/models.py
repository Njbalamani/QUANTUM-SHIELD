from django.conf import settings
from django.db import models

from core.models import Organization


class ScanPattern(models.Model):
    name = models.CharField(max_length=120, unique=True)
    description = models.TextField(blank=True)
    pattern = models.CharField(max_length=500)
    category = models.CharField(max_length=40)
    severity = models.CharField(max_length=16)
    recommendation = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("category", "name")

    def __str__(self):
        return self.name


class ScanSource(models.TextChoices):
    TEXT = "text", "Text"
    FILE = "file", "File"


class ScanStatus(models.TextChoices):
    COMPLETED = "completed", "Completed"
    FAILED = "failed", "Failed"


class Scan(models.Model):
    organization = models.ForeignKey(
        Organization,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scans",
    )
    name = models.CharField(max_length=200)
    source = models.CharField(max_length=16, choices=ScanSource.choices)
    location = models.CharField(max_length=240, blank=True)
    content_hash = models.CharField(max_length=64, blank=True)
    status = models.CharField(max_length=16, choices=ScanStatus.choices, default=ScanStatus.COMPLETED)
    summary = models.JSONField(default=dict, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scans_created",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return self.name


class ScanFinding(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="findings")
    pattern = models.ForeignKey(
        ScanPattern,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="findings",
    )
    line_number = models.PositiveIntegerField()
    column_number = models.PositiveIntegerField(default=1)
    matched_text = models.CharField(max_length=300)
    severity = models.CharField(max_length=16)
    category = models.CharField(max_length=40, blank=True)
    message = models.TextField(blank=True)
    recommendation = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("line_number", "column_number", "id")

    def __str__(self):
        return f"{self.severity}: {self.matched_text}"
