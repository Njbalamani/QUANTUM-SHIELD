from django.contrib import admin

from .models import Scan, ScanFinding, ScanPattern


@admin.register(ScanPattern)
class ScanPatternAdmin(admin.ModelAdmin):
    list_display = ("name", "category", "severity", "enabled", "updated_at")
    list_filter = ("category", "severity", "enabled")
    search_fields = ("name", "description", "pattern")


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "source", "status", "created_by", "created_at")
    list_filter = ("source", "status", "organization", "created_at")
    search_fields = ("name", "location", "content_hash", "organization__name")
    readonly_fields = ("content_hash", "summary", "created_at", "updated_at")


@admin.register(ScanFinding)
class ScanFindingAdmin(admin.ModelAdmin):
    list_display = ("scan", "line_number", "column_number", "severity", "category", "matched_text")
    list_filter = ("severity", "category", "created_at")
    search_fields = ("matched_text", "message", "scan__name")
    readonly_fields = (
        "scan",
        "pattern",
        "line_number",
        "column_number",
        "matched_text",
        "severity",
        "category",
        "message",
        "recommendation",
        "created_at",
    )

    def has_add_permission(self, request):
        return False
