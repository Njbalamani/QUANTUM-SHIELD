from rest_framework.permissions import SAFE_METHODS, BasePermission

from accounts.models import UserRole


class IsAdminRole(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and user.is_admin_role)


class IsAnalystOrAdmin(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and user.is_analyst_role)


class IsViewerOrHigher(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and getattr(user, "role", None) in UserRole.values)


class IsAdminOrReadOnlyForAnalysis(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if request.method in SAFE_METHODS:
            return getattr(user, "role", None) in UserRole.values
        return user.is_analyst_role


class IsAdminForDestructive(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if request.method in {"DELETE", "PUT", "PATCH"}:
            return user.is_admin_role
        return user.is_authenticated and getattr(user, "role", None) in UserRole.values
