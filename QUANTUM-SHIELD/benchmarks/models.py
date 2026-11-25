from django.conf import settings
from django.db import models


class BenchmarkOperation(models.TextChoices):
    KEM = "kem", "Key encapsulation"
    SIGNATURE = "signature", "Digital signature"


class BenchmarkStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    RUNNING = "running", "Running"
    COMPLETED = "completed", "Completed"
    FAILED = "failed", "Failed"


class BenchmarkRun(models.Model):
    organization = models.ForeignKey(
        "core.Organization",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="benchmark_runs",
    )
    algorithm = models.CharField(max_length=128)
    operation = models.CharField(max_length=16, choices=BenchmarkOperation.choices)
    iterations = models.PositiveIntegerField()
    warmup_iterations = models.PositiveIntegerField(default=0)
    status = models.CharField(max_length=16, choices=BenchmarkStatus.choices, default=BenchmarkStatus.PENDING)
    task_id = models.CharField(max_length=120, blank=True)
    summary = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="benchmark_runs",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.operation}: {self.algorithm}"


class BenchmarkMeasurement(models.Model):
    run = models.ForeignKey(BenchmarkRun, on_delete=models.CASCADE, related_name="measurements")
    iteration = models.PositiveIntegerField()
    phase = models.CharField(max_length=32, default="total")
    duration_ms = models.FloatField()
    success = models.BooleanField(default=True)
    detail = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ("iteration", "phase")
        constraints = [
            models.UniqueConstraint(fields=["run", "iteration", "phase"], name="unique_benchmark_measurement")
        ]

    def __str__(self):
        return f"{self.run_id}:{self.iteration} {self.phase}"
