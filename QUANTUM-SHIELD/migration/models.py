from django.conf import settings
from django.db import models

from core.models import AlgorithmFamily, Organization


class PlanStatus(models.TextChoices):
    DRAFT = "draft", "Draft"
    ACTIVE = "active", "Active"
    COMPLETED = "completed", "Completed"
    ARCHIVED = "archived", "Archived"


class TaskStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    IN_PROGRESS = "in_progress", "In progress"
    BLOCKED = "blocked", "Blocked"
    COMPLETED = "completed", "Completed"
    SKIPPED = "skipped", "Skipped"


class TaskPriority(models.TextChoices):
    LOW = "low", "Low"
    MEDIUM = "medium", "Medium"
    HIGH = "high", "High"
    CRITICAL = "critical", "Critical"


class MigrationPlan(models.Model):
    organization = models.ForeignKey(
        Organization,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="migration_plans",
    )
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    target_algorithm = models.CharField(max_length=120)
    target_family = models.CharField(max_length=24, choices=AlgorithmFamily.choices, default=AlgorithmFamily.POST_QUANTUM)
    status = models.CharField(max_length=16, choices=PlanStatus.choices, default=PlanStatus.DRAFT)
    owner = models.CharField(max_length=160, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="migration_plans_created",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return self.name

    @property
    def progress(self):
        counts = {status: 0 for status in TaskStatus.values}
        for task in self.tasks.all():
            counts[task.status] = counts.get(task.status, 0) + 1
        total = sum(counts.values())
        completed = counts[TaskStatus.COMPLETED]
        percent = int(round(completed * 100 / total)) if total else 0
        result = {"counts": counts, "total": total, "completed": completed, "percent": percent}
        result.update(counts)
        return result


class MigrationTask(models.Model):
    plan = models.ForeignKey(MigrationPlan, on_delete=models.CASCADE, related_name="tasks")
    asset = models.ForeignKey(
        "core.CryptographicAsset",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="migration_tasks",
    )
    from_algorithm = models.CharField(max_length=120)
    to_algorithm = models.CharField(max_length=120)
    status = models.CharField(max_length=16, choices=TaskStatus.choices, default=TaskStatus.PENDING)
    priority = models.CharField(max_length=16, choices=TaskPriority.choices, default=TaskPriority.MEDIUM)
    notes = models.TextField(blank=True)
    due_date = models.DateField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("id",)

    def __str__(self):
        return f"{self.from_algorithm} -> {self.to_algorithm}"
