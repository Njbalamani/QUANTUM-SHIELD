from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from core.models import AuditLog

from .models import User, UserRole


class TokenEndpointTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.password = "LongPassword123!"
        self.user = User.objects.create_user("token_user", password=self.password)

    def test_token_endpoint_returns_token_for_valid_credentials(self):
        response = self.client.post(
            reverse("api-token"),
            {"username": self.user.username, "password": self.password},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("token", response.data)
        self.assertTrue(response.data["token"])

    def test_token_endpoint_rejects_wrong_password(self):
        response = self.client.post(
            reverse("api-token"),
            {"username": self.user.username, "password": "WrongPassword123!"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotIn("token", response.data)


class ProfileEndpointTests(APITestCase):
    def setUp(self):
        self.viewer = User.objects.create_user("viewer")
        self.url = reverse("user-me")

    def test_me_requires_authentication(self):
        response = self.client.get(self.url)
        self.assertIn(
            response.status_code,
            (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN),
        )
        self.assertFalse(AuditLog.objects.exists())

    def test_get_me_returns_current_user(self):
        self.client.force_authenticate(self.viewer)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["username"], self.viewer.username)
        self.assertEqual(response.data["role"], UserRole.VIEWER)

    def test_patch_me_updates_profile_and_records_audit(self):
        self.client.force_authenticate(self.viewer)
        response = self.client.patch(
            self.url,
            {"first_name": "Ada", "title": "Security Viewer"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.viewer.refresh_from_db()
        self.assertEqual(self.viewer.first_name, "Ada")
        self.assertEqual(self.viewer.title, "Security Viewer")
        audit = AuditLog.objects.get(action="profile.update")
        self.assertEqual(audit.user, self.viewer)
        self.assertEqual(audit.object_type, User._meta.label)
        self.assertEqual(audit.object_id, str(self.viewer.pk))


class UserManagementTests(APITestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser("admin", password="AdminPassword123!")
        self.viewer = User.objects.create_user("viewer")
        self.url = reverse("user-list")

    def test_admin_can_create_user_with_valid_password(self):
        self.client.force_authenticate(self.admin)
        response = self.client.post(
            self.url,
            {
                "username": "new_analyst",
                "email": "analyst@example.com",
                "password": "StrongPassphrase123",
                "role": UserRole.ANALYST,
                "title": "Analyst",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        created = User.objects.get(username="new_analyst")
        self.assertEqual(created.role, UserRole.ANALYST)
        self.assertEqual(created.title, "Analyst")
        self.assertTrue(created.check_password("StrongPassphrase123"))

    def test_admin_cannot_create_user_with_short_password(self):
        self.client.force_authenticate(self.admin)
        response = self.client.post(
            self.url,
            {"username": "short", "password": "short"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(User.objects.filter(username="short").exists())

    def test_viewer_cannot_create_user(self):
        self.client.force_authenticate(self.viewer)
        response = self.client.post(
            self.url,
            {
                "username": "blocked",
                "password": "StrongPassphrase123",
                "role": UserRole.ANALYST,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(User.objects.filter(username="blocked").exists())
