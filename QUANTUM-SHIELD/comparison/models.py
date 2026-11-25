from django.conf import settings
from django.db import models


class ComparisonScope(models.TextChoices):
    INVENTORY = "inventory", "Inventory"
    ALGORITHMS = "algorithms", "Algorithms"


class ComparisonRun(models.Model):
    organization = models.ForeignKey(
        "core.Organization",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="comparison_runs",
    )
    name = models.CharField(max_length=200)
    scope = models.CharField(max_length=24, choices=ComparisonScope.choices)
    algorithms = models.JSONField(default=list, blank=True)
    summary = models.JSONField(default=dict, blank=True)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="comparison_runs",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return self.name
