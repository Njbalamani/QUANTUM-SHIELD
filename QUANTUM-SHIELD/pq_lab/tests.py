import uuid
from unittest.mock import patch

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from accounts.models import User, UserRole
from core.models import AuditLog

CAPABILITY_PAYLOAD = {
    "oqs_available": True,
    "oqs_version": "1.0.0-test",
    "enabled_kems": ["Kyber768"],
    "enabled_signatures": ["Dilithium3"],
    "warning": None,
    "library_versions": {
        "python": "3.11.0",
        "django": "5.0.0",
        "cryptography": "42.0.0",
        "oqs": "1.0.0-test",
    },
}


class PqLabApiTests(APITestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser("admin", password="AdminPassword123!")
        self.analyst = User.objects.create_user("analyst", role=UserRole.ANALYST)
        self.viewer = User.objects.create_user("viewer", role=UserRole.VIEWER)

    def test_capabilities_requires_authentication(self):
        response = self.client.get(reverse("pq-capabilities"))
        self.assertIn(
            response.status_code,
            (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN),
        )
        self.assertFalse(AuditLog.objects.filter(action="pq_lab.capabilities.read").exists())

    def test_capabilities_returns_expected_keys(self):
        self.client.force_authenticate(self.viewer)
        with patch("pq_lab.views.capability_data", return_value=CAPABILITY_PAYLOAD) as mocked:
            response = self.client.get(reverse("pq-capabilities"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        mocked.assert_called_once_with()
        self.assertEqual(set(response.data), set(CAPABILITY_PAYLOAD))
        self.assertEqual(response.data["enabled_kems"], ["Kyber768"])
        self.assertEqual(response.data["library_versions"], CAPABILITY_PAYLOAD["library_versions"])
        self.assertTrue(
            AuditLog.objects.filter(action="pq_lab.capabilities.read", user=self.viewer).exists()
        )

    def test_viewer_cannot_generate_kem(self):
        self.client.force_authenticate(self.viewer)
        response = self.client.post(
            reverse("pq-kem-generate"),
            {"algorithm": "Kyber768"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(AuditLog.objects.filter(action="pq_lab.kem.generate").exists())

    def test_analyst_can_generate_kem_and_audit(self):
        operation_id = str(uuid.uuid4())
        result = {
            "operation_id": operation_id,
            "algorithm": "Kyber768",
            "public_key": "cHVibGljLWtleQ",
            "public_key_size": 1184,
            "private_key_size": 2400,
            "warning": None,
        }
        self.client.force_authenticate(self.analyst)
        with patch("pq_lab.views.kem_generate", return_value=result) as mocked:
            response = self.client.post(
                reverse("pq-kem-generate"),
                {"algorithm": "Kyber768"},
                format="json",
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        mocked.assert_called_once_with("Kyber768")
        self.assertEqual(str(response.data["operation_id"]), operation_id)
        self.assertEqual(response.data["public_key_size"], 1184)
        audit = AuditLog.objects.get(action="pq_lab.kem.generate")
        self.assertEqual(audit.user, self.analyst)
        self.assertEqual(audit.object_type, "str")
        self.assertEqual(audit.object_id, operation_id)
        self.assertEqual(audit.details["algorithm"], "Kyber768")
        self.assertEqual(audit.details["operation_id"], operation_id)

    def test_ephemeral_delete_deletes_operation_and_audits(self):
        operation_id = str(uuid.uuid4())
        self.client.force_authenticate(self.analyst)
        with patch("pq_lab.views.delete_operation", return_value=True) as mocked:
            response = self.client.delete(reverse("pq-ephemeral-delete", args=[operation_id]))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        mocked.assert_called_once_with(operation_id)
        self.assertEqual(str(response.data["operation_id"]), operation_id)
        self.assertTrue(response.data["deleted"])
        audit = AuditLog.objects.get(action="pq_lab.ephemeral.delete")
        self.assertEqual(audit.user, self.analyst)
        self.assertEqual(audit.object_id, operation_id)
        self.assertTrue(audit.details["deleted"])
