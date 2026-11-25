from django.contrib import admin

from .models import ComparisonRun


@admin.register(ComparisonRun)
class ComparisonRunAdmin(admin.ModelAdmin):
    list_display = ("name", "scope", "organization", "requested_by", "created_at")
    list_filter = ("scope", "organization", "created_at")
    search_fields = ("name", "organization__name", "requested_by__username")
    readonly_fields = ("created_at", "updated_at")
