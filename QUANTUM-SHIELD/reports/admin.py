from django.contrib import admin

from .models import Report


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ("title", "kind", "format", "status", "organization", "generated_by", "created_at", "completed_at")
    list_filter = ("kind", "format", "status", "organization", "created_at")
    search_fields = ("title", "organization__name", "generated_by__username")
    readonly_fields = ("created_at", "completed_at")
