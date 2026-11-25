from unittest.mock import Mock, patch

from django.test import TestCase
from rest_framework.test import APIRequestFactory

from accounts.models import User, UserRole

from .audit import record_audit
from .crypto import capability_report, get_oqs
from .models import AssetStatus, AssetType, AuditLog, Criticality, CryptographicAsset, Organization
from .permissions import IsAdminRole, IsAnalystOrAdmin, IsViewerOrHigher


class CryptographicAssetRiskTests(TestCase):
    def test_pq_risk_flags_legacy_algorithms_and_certificates_or_protocols(self):
        cases = (
            ("RSA-2048", AssetType.APPLICATION, True),
            ("ECDSA P-256", AssetType.APPLICATION, True),
            ("AES-256-GCM", AssetType.APPLICATION, False),
            ("ChaCha20-Poly1305", AssetType.CERTIFICATE, True),
            ("Custom TLS suite", AssetType.PROTOCOL, True),
        )
        for algorithm, asset_type, expected in cases:
            with self.subTest(algorithm=algorithm, asset_type=asset_type):
                asset = CryptographicAsset(algorithm=algorithm, asset_type=asset_type)
                self.assertIs(asset.pq_risk, expected)


class RecordAuditTests(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(name="Acme", slug="acme")

    def test_record_audit_redacts_secrets_and_records_model_identity(self):
        asset = CryptographicAsset.objects.create(
            organization=self.organization,
            name="Legacy VPN",
            algorithm="RSA-2048",
            criticality=Criticality.HIGH,
            status=AssetStatus.ACTIVE,
        )
        record_audit(
            action="core.test.audit",
            obj=asset,
            details={
                "secret_key": "do-not-log",
                "private_key": "private",
                "token": "abc123",
                "public_key": "safe",
                "nested": {"api_key": "hidden", "visible": "ok"},
            },
        )
        log = AuditLog.objects.get(action="core.test.audit")
        self.assertEqual(log.object_type, CryptographicAsset._meta.label)
        self.assertEqual(log.object_id, str(asset.pk))
        self.assertIsNone(log.user)
        self.assertEqual(log.details["secret_key"], "[redacted]")
        self.assertEqual(log.details["private_key"], "[redacted]")
        self.assertEqual(log.details["token"], "[redacted]")
        self.assertEqual(log.details["public_key"], "safe")
        self.assertEqual(log.details["nested"]["api_key"], "[redacted]")
        self.assertEqual(log.details["nested"]["visible"], "ok")

    def test_record_audit_with_request_captures_user_ip_and_non_model_object(self):
        user = User.objects.create_user("viewer")
        request = APIRequestFactory().post(
            "/",
            REMOTE_ADDR="203.0.113.7",
            HTTP_X_FORWARDED_FOR="198.51.100.9, 203.0.113.7",
        )
        request.user = user
        record_audit(request, action="core.test.request", obj="operation-1")
        log = AuditLog.objects.get(action="core.test.request")
        self.assertEqual(log.user, user)
        self.assertEqual(log.ip_address, "198.51.100.9")
        self.assertEqual(log.object_type, "str")
        self.assertEqual(log.object_id, "operation-1")


class PermissionTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.admin = User.objects.create_superuser("admin", password="AdminPassword123!")
        self.analyst = User.objects.create_user("analyst", role=UserRole.ANALYST)
        self.viewer = User.objects.create_user("viewer", role=UserRole.VIEWER)

    def request_for(self, user):
        request = self.factory.get("/")
        request.user = user
        return request

    def test_is_admin_role_allows_only_admins(self):
        permission = IsAdminRole()
        self.assertTrue(permission.has_permission(self.request_for(self.admin), None))
        self.assertFalse(permission.has_permission(self.request_for(self.analyst), None))
        self.assertFalse(permission.has_permission(self.request_for(self.viewer), None))

    def test_is_analyst_or_admin_allows_analysts_and_admins(self):
        permission = IsAnalystOrAdmin()
        self.assertTrue(permission.has_permission(self.request_for(self.admin), None))
        self.assertTrue(permission.has_permission(self.request_for(self.analyst), None))
        self.assertFalse(permission.has_permission(self.request_for(self.viewer), None))

    def test_is_viewer_or_higher_allows_known_roles_but_not_anonymous(self):
        permission = IsViewerOrHigher()
        for user in (self.admin, self.analyst, self.viewer):
            with self.subTest(username=user.username):
                self.assertTrue(permission.has_permission(self.request_for(user), None))
        self.assertFalse(permission.has_permission(self.request_for(None), None))


class CapabilityReportTests(TestCase):
    def setUp(self):
        get_oqs.cache_clear()

    def test_capability_report_returns_expected_keys(self):
        report = capability_report()
        self.assertEqual(
            set(report),
            {
                "oqs_available",
                "oqs_version",
                "enabled_kems",
                "enabled_signatures",
                "warning",
            },
        )
        self.assertIsInstance(report["enabled_kems"], list)
        self.assertIsInstance(report["enabled_signatures"], list)

    def test_capability_report_with_available_oqs(self):
        module = Mock(OQS_VERSION="1.0.0-test")
        module.get_enabled_kem_algos.return_value = ["Kyber768"]
        module.get_enabled_sig_algos.return_value = ["Dilithium3"]
        with patch("core.crypto.get_oqs", return_value=module):
            report = capability_report()
        self.assertTrue(report["oqs_available"])
        self.assertEqual(report["oqs_version"], "1.0.0-test")
        self.assertEqual(report["enabled_kems"], ["Kyber768"])
        self.assertEqual(report["enabled_signatures"], ["Dilithium3"])
        self.assertIsNone(report["warning"])

    def test_capability_report_degrades_when_oqs_is_unavailable(self):
        with patch("core.crypto.get_oqs", return_value=None):
            report = capability_report()
        self.assertFalse(report["oqs_available"])
        self.assertIsNone(report["oqs_version"])
        self.assertEqual(report["enabled_kems"], [])
        self.assertEqual(report["enabled_signatures"], [])
        self.assertIn("unavailable", report["warning"].lower())
