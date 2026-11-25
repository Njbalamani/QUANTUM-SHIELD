from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from accounts.models import User, UserRole
from benchmarks.models import BenchmarkMeasurement, BenchmarkOperation, BenchmarkRun, BenchmarkStatus
from benchmarks.services import create_benchmark_run, require_algorithm, summarize_measurements
from benchmarks.tasks import run_benchmark_task
from core.crypto import UnsupportedAlgorithmError
from core.models import AuditLog


class FakePrimitive:
    def __init__(self, algorithm, secret_key=None):
        self.algorithm = algorithm
        self.secret_key = secret_key
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.closed = True
        return False

    def generate_keypair(self):
        return b"public-key"

    def export_secret_key(self):
        return b"private-key"

    def encap_secret(self, public_key):
        return b"ciphertext", b"shared-secret"

    def decap_secret(self, ciphertext):
        return b"shared-secret"

    def sign(self, message):
        return b"signature"

    def verify(self, message, signature, public_key):
        return signature == b"signature" and public_key == b"public-key"


class FakeOQS:
    OQS_VERSION = "test-1.0"
    KeyEncapsulation = FakePrimitive
    Signature = FakePrimitive

    @staticmethod
    def get_enabled_kem_mechanisms():
        return ["TestKEM", "Kyber768"]

    @staticmethod
    def get_enabled_sig_mechanisms():
        return ["TestSig", "Dilithium3"]


class BenchmarkServiceTests(TestCase):
    @override_settings(QS_BENCHMARK_ASYNC=False)
    def test_kem_run_creates_measurements_and_summary(self):
        with patch("benchmarks.services.get_oqs", return_value=FakeOQS):
            run = create_benchmark_run(
                algorithm="TestKEM",
                operation=BenchmarkOperation.KEM,
                iterations=3,
                warmup_iterations=1,
            )
        self.assertEqual(run.status, BenchmarkStatus.COMPLETED)
        self.assertEqual(run.measurements.count(), 3)
        self.assertIsNotNone(run.started_at)
        self.assertIsNotNone(run.completed_at)
        first = run.measurements.first()
        self.assertTrue(first.success)
        self.assertTrue(first.detail["match"])
        self.assertIn("encapsulation_ms", first.detail)
        self.assertIn("decapsulation_ms", first.detail)
        self.assertEqual(run.summary["algorithm"], "TestKEM")
        self.assertEqual(run.summary["operation"], BenchmarkOperation.KEM)
        self.assertEqual(run.summary["warmup_iterations"], 1)
        self.assertEqual(run.summary["count"], 3)
        self.assertIn("library_versions", run.summary)
        self.assertTrue(AuditLog.objects.filter(action="benchmark.create").exists())

    @override_settings(QS_BENCHMARK_ASYNC=False)
    def test_signature_run_records_valid_flag(self):
        with patch("benchmarks.services.get_oqs", return_value=FakeOQS):
            run = create_benchmark_run(
                algorithm="TestSig",
                operation=BenchmarkOperation.SIGNATURE,
                iterations=2,
                warmup_iterations=0,
            )
        self.assertEqual(run.status, BenchmarkStatus.COMPLETED)
        measurement = run.measurements.first()
        self.assertTrue(measurement.detail["valid"])
        self.assertIn("sign_ms", measurement.detail)
        self.assertIn("verify_ms", measurement.detail)
        self.assertEqual(run.summary["successful"], 2)

    def test_summary_math_is_empty_safe_and_rounded(self):
        run = BenchmarkRun.objects.create(algorithm="TestKEM", operation=BenchmarkOperation.KEM, iterations=4)
        BenchmarkMeasurement.objects.bulk_create(
            [
                BenchmarkMeasurement(run=run, iteration=1, duration_ms=10.0, success=True),
                BenchmarkMeasurement(run=run, iteration=2, duration_ms=20.1234, success=True),
                BenchmarkMeasurement(run=run, iteration=3, duration_ms=30.0, success=False),
                BenchmarkMeasurement(run=run, iteration=4, duration_ms=40.0, success=True),
            ]
        )
        summary = summarize_measurements(run)
        self.assertEqual(summary["count"], 4)
        self.assertEqual(summary["successful"], 3)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["avg_ms"], 25.031)
        self.assertEqual(summary["min_ms"], 10.0)
        self.assertEqual(summary["max_ms"], 40.0)
        self.assertEqual(summary["total_ms"], 100.123)
        self.assertEqual(summary["p95_ms"], 40.0)

        empty = BenchmarkRun.objects.create(algorithm="TestKEM", operation=BenchmarkOperation.KEM, iterations=1)
        self.assertEqual(summarize_measurements(empty)["count"], 0)
        self.assertEqual(summarize_measurements(empty)["avg_ms"], 0.0)

    def test_require_algorithm_rejects_missing_module_operation_and_algorithm(self):
        with patch("benchmarks.services.get_oqs", return_value=None):
            with self.assertRaises(UnsupportedAlgorithmError):
                require_algorithm("TestKEM", BenchmarkOperation.KEM)
        with patch("benchmarks.services.get_oqs", return_value=FakeOQS):
            with self.assertRaises(UnsupportedAlgorithmError):
                require_algorithm("UnknownKEM", BenchmarkOperation.KEM)
            with self.assertRaises(UnsupportedAlgorithmError):
                require_algorithm("TestKEM", "bogus")
            module = require_algorithm("TestSig", BenchmarkOperation.SIGNATURE)
            self.assertIs(module, FakeOQS)

    @override_settings(QS_BENCHMARK_ASYNC=False)
    def test_failed_synchronous_run_keeps_failed_row(self):
        with patch("benchmarks.services.get_oqs", return_value=None):
            with self.assertRaises(UnsupportedAlgorithmError):
                create_benchmark_run(
                    algorithm="TestKEM",
                    operation=BenchmarkOperation.KEM,
                    iterations=1,
                    warmup_iterations=0,
                )
        run = BenchmarkRun.objects.get()
        self.assertEqual(run.status, BenchmarkStatus.FAILED)
        self.assertIn("unavailable", run.error)
        self.assertEqual(run.measurements.count(), 0)

    @override_settings(QS_BENCHMARK_ASYNC=True)
    def test_async_run_dispatches_task_without_measurements(self):
        with patch("benchmarks.tasks.run_benchmark_task.delay") as delay:
            delay.return_value.id = "celery-task-123"
            with patch("benchmarks.services.get_oqs", return_value=FakeOQS):
                run = create_benchmark_run(
                    algorithm="TestKEM",
                    operation=BenchmarkOperation.KEM,
                    iterations=2,
                    warmup_iterations=0,
                )
        delay.assert_called_once_with(run.pk)
        self.assertEqual(run.task_id, "celery-task-123")
        self.assertEqual(run.status, BenchmarkStatus.PENDING)
        self.assertEqual(run.measurements.count(), 0)

    def test_missing_task_run_returns_none(self):
        self.assertIsNone(run_benchmark_task.run(999999))


@override_settings(ROOT_URLCONF="benchmarks.urls", QS_BENCHMARK_ASYNC=False)
class BenchmarkApiTests(APITestCase):
    def setUp(self):
        self.analyst = User.objects.create_user("analyst", password="password", role=UserRole.ANALYST)
        self.viewer = User.objects.create_user("viewer", password="password", role=UserRole.VIEWER)

    def test_analyst_can_create_benchmark_and_read_measurements(self):
        self.client.force_authenticate(self.analyst)
        with patch("benchmarks.services.get_oqs", return_value=FakeOQS):
            response = self.client.post(
                reverse("benchmark-run-list"),
                {"algorithm": "TestKEM", "operation": "kem", "iterations": 2, "warmup_iterations": 0},
                format="json",
            )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["requested_by_username"], "analyst")
        self.assertEqual(response.data["measurement_count"], 2)
        self.assertEqual(response.data["summary"]["count"], 2)
        run_id = response.data["id"]

        detail = self.client.get(reverse("benchmark-run-detail", args=[run_id]))
        self.assertEqual(detail.status_code, status.HTTP_200_OK)
        measurements = self.client.get(reverse("benchmark-run-measurements", args=[run_id]))
        self.assertEqual(len(measurements.data), 2)
        self.assertTrue(AuditLog.objects.filter(action="benchmark.create").exists())

    def test_viewer_cannot_create_benchmark(self):
        self.client.force_authenticate(self.viewer)
        response = self.client.post(
            reverse("benchmark-run-list"),
            {"algorithm": "TestKEM", "operation": "kem"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_failed_create_returns_400_and_keeps_failed_row(self):
        self.client.force_authenticate(self.analyst)
        with patch("benchmarks.services.get_oqs", return_value=None):
            response = self.client.post(
                reverse("benchmark-run-list"),
                {"algorithm": "TestKEM", "operation": "kem", "iterations": 1, "warmup_iterations": 0},
                format="json",
            )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(BenchmarkRun.objects.count(), 1)
        self.assertEqual(BenchmarkRun.objects.get().status, BenchmarkStatus.FAILED)

    def test_capabilities_are_available_to_viewers(self):
        self.client.force_authenticate(self.viewer)
        response = self.client.get(reverse("benchmark-run-capabilities"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for key in (
            "oqs_available",
            "oqs_version",
            "enabled_kems",
            "enabled_signatures",
            "default_iterations",
            "max_iterations",
            "async_enabled",
        ):
            self.assertIn(key, response.data)
