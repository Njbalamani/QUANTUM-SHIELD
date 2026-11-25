from django.contrib import admin

from .models import MigrationPlan, MigrationTask


@admin.register(MigrationPlan)
class MigrationPlanAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "status", "target_algorithm", "owner", "created_at", "completed_at")
    list_filter = ("status", "target_family", "organization", "created_at")
    search_fields = ("name", "description", "owner", "target_algorithm", "organization__name")
    readonly_fields = ("created_at", "updated_at", "completed_at")


@admin.register(MigrationTask)
class MigrationTaskAdmin(admin.ModelAdmin):
    list_display = ("plan", "asset", "from_algorithm", "to_algorithm", "status", "priority", "due_date")
    list_filter = ("status", "priority", "due_date", "created_at")
    search_fields = ("from_algorithm", "to_algorithm", "notes", "asset__name", "plan__name")
    readonly_fields = ("created_at", "updated_at", "completed_at")
