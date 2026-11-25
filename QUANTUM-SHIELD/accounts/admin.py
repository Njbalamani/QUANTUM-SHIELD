from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import User


@admin.register(User)
class QuantumShieldUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        ("QuantumShield", {"fields": ("role", "organization", "title")}),
    )
    list_display = ("username", "email", "role", "organization", "is_staff", "is_active")
    list_filter = ("role", "is_staff", "is_active", "organization")
