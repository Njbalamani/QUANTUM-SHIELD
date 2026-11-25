from django.contrib import admin

from .models import AlgorithmProfile, AuditLog, CryptographicAsset, Organization


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "industry", "created_at")
    search_fields = ("name", "slug", "industry")
    prepopulated_fields = {"slug": ("name",)}


@admin.register(CryptographicAsset)
class CryptographicAssetAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "algorithm", "key_size", "criticality", "status")
    list_filter = ("organization", "criticality", "status", "asset_type")
    search_fields = ("name", "algorithm", "protocol", "owner", "location")


@admin.register(AlgorithmProfile)
class AlgorithmProfileAdmin(admin.ModelAdmin):
    list_display = ("name", "family", "operation", "supported", "deprecated")
    list_filter = ("family", "operation", "supported", "deprecated")
    search_fields = ("name", "standard", "implementation_source")


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "action", "user", "object_type", "object_id")
    list_filter = ("action", "created_at")
    search_fields = ("action", "object_type", "object_id")
    readonly_fields = ("created_at", "action", "user", "object_type", "object_id", "details", "ip_address", "user_agent")
