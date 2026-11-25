from django.conf import settings
from django.db import models


class Organization(models.Model):
    name = models.CharField(max_length=200, unique=True)
    slug = models.SlugField(max_length=200, unique=True)
    description = models.TextField(blank=True)
    industry = models.CharField(max_length=120, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name


class AssetType(models.TextChoices):
    APPLICATION = "application", "Application"
    SERVICE = "service", "Service"
    DATABASE = "database", "Database"
    ENDPOINT = "endpoint", "Endpoint"
    CERTIFICATE = "certificate", "Certificate"
    LIBRARY = "library", "Cryptographic library"
    PROTOCOL = "protocol", "Protocol"
    DEVICE = "device", "Device"
    OTHER = "other", "Other"


class Criticality(models.TextChoices):
    LOW = "low", "Low"
    MEDIUM = "medium", "Medium"
    HIGH = "high", "High"
    CRITICAL = "critical", "Critical"


class AssetStatus(models.TextChoices):
    ACTIVE = "active", "Active"
    PLANNED = "planned", "Planned"
    DEPRECATED = "deprecated", "Deprecated"
    RETIRED = "retired", "Retired"


class CryptographicAsset(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="assets")
    name = models.CharField(max_length=200)
    asset_type = models.CharField(max_length=32, choices=AssetType.choices, default=AssetType.APPLICATION)
    algorithm = models.CharField(max_length=120)
    key_size = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=120, blank=True)
    owner = models.CharField(max_length=160, blank=True)
    location = models.CharField(max_length=240, blank=True)
    criticality = models.CharField(max_length=16, choices=Criticality.choices, default=Criticality.MEDIUM)
    status = models.CharField(max_length=16, choices=AssetStatus.choices, default=AssetStatus.ACTIVE)
    description = models.TextField(blank=True)
    discovered_at = models.DateField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assets_created",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-criticality", "name")
        indexes = [models.Index(fields=["organization", "criticality"])]

    def __str__(self):
        return f"{self.name} ({self.algorithm})"

    @property
    def pq_risk(self):
        vulnerable = {"rsa", "ecdsa", "ecdh", "ecc", "dh", "dsa"}
        algorithm = self.algorithm.strip().lower()
        return any(token in algorithm for token in vulnerable) or self.asset_type in {
            AssetType.CERTIFICATE,
            AssetType.PROTOCOL,
        }


class AlgorithmFamily(models.TextChoices):
    CLASSICAL = "classical", "Classical"
    POST_QUANTUM = "post_quantum", "Post-quantum"
    HYBRID = "hybrid", "Hybrid"


class AlgorithmOperation(models.TextChoices):
    KEM = "kem", "Key establishment"
    SIGNATURE = "signature", "Digital signature"


class AlgorithmProfile(models.Model):
    name = models.CharField(max_length=120, unique=True)
    family = models.CharField(max_length=24, choices=AlgorithmFamily.choices)
    operation = models.CharField(max_length=24, choices=AlgorithmOperation.choices)
    security_level = models.CharField(max_length=80, blank=True)
    standard = models.CharField(max_length=160, blank=True)
    public_key_size = models.PositiveIntegerField(null=True, blank=True)
    private_key_size = models.PositiveIntegerField(null=True, blank=True)
    output_size = models.PositiveIntegerField(null=True, blank=True)
    implementation_source = models.CharField(max_length=160, blank=True)
    supported = models.BooleanField(default=False)
    deprecated = models.BooleanField(default=False)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("family", "name")

    def __str__(self):
        return self.name


class AuditLog(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
    )
    action = models.CharField(max_length=120)
    object_type = models.CharField(max_length=120, blank=True)
    object_id = models.CharField(max_length=120, blank=True)
    details = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=300, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [models.Index(fields=["action", "created_at"])]

    def __str__(self):
        return f"{self.action} @ {self.created_at:%Y-%m-%d %H:%M:%S}"
