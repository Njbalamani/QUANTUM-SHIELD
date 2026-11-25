from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response

from core.audit import record_audit
from .models import User
from .serializers import UserCreateSerializer, UserSerializer


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.select_related("organization").all()
    serializer_class = UserSerializer

    def get_permissions(self):
        if self.action in {"create", "destroy"}:
            return [IsAdminUser()]
        return [IsAuthenticated()]

    def get_serializer_class(self):
        if self.action == "create":
            return UserCreateSerializer
        return UserSerializer

    @action(detail=False, methods=["get", "patch"], permission_classes=[IsAuthenticated])
    def me(self, request):
        if request.method == "PATCH":
            allowed = {"first_name", "last_name", "email", "title"}
            for field in allowed:
                if field in request.data:
                    setattr(request.user, field, request.data[field])
            request.user.save(update_fields=sorted(allowed.intersection(request.data)))
            record_audit(request, "profile.update", obj=request.user)
        return Response(UserSerializer(request.user).data)
