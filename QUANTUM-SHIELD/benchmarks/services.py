import hmac
import math
import time
from contextlib import ExitStack

from django.conf import settings
from django.utils import timezone

from core import crypto
from core.audit import record_audit
from core.crypto import UnsupportedAlgorithmError, capability_report, enabled_kems, enabled_signatures, get_oqs

from .models import BenchmarkMeasurement, BenchmarkOperation, BenchmarkRun, BenchmarkStatus

MESSAGE = b"quantumshield benchmark message"


def _setting_int(name, default, minimum=None, maximum=None):
    try:
        value = int(getattr(settings, name, default))
    except (TypeError, ValueError):
        value = default
    if minimum is not None:
        value = max(value, minimum)
    if maximum is not None:
        value = min(value, maximum)
    return value


def _iterations(value):
    default = _setting_int("QS_BENCHMARK_ITERATIONS", 10, minimum=1)
    if value is None:
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    maximum = _setting_int("QS_BENCHMARK_MAX_ITERATIONS", 200, minimum=1)
    return min(max(parsed, 1), maximum)


def _warmup_iterations(value):
    default = _setting_int("QS_BENCHMARK_WARMUP_ITERATIONS", 2, minimum=0)
    if value is None:
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(parsed, 0)


def _enabled_names(module, kind):
    if kind == BenchmarkOperation.KEM:
        prefix = "kem"
        fallback = enabled_kems
    else:
        prefix = "sig"
        fallback = enabled_signatures
    names = set()
    for attribute in ("get_enabled_{0}_mechanisms".format(prefix), "get_enabled_{0}_algos".format(prefix)):
        getter = getattr(module, attribute, None)
        if callable(getter):
            try:
                names.update(str(item) for item in getter())
            except Exception:
                pass
    try:
        names.update(str(item) for item in fallback())
    except Exception:
        pass
    return names


def require_algorithm(algorithm, operation):
    if not isinstance(algorithm, str) or not algorithm.strip():
        raise UnsupportedAlgorithmError("An algorithm name is required.")
    if operation not in BenchmarkOperation.values:
        raise UnsupportedAlgorithmError("Unknown benchmark operation: {0}".format(operation))
    module = get_oqs()
    if module is None:
        raise UnsupportedAlgorithmError("Open Quantum Safe bindings are unavailable; benchmarking is disabled.")
    if algorithm not in _enabled_names(module, operation):
        label = "KEM" if operation == BenchmarkOperation.KEM else "signature"
        raise UnsupportedAlgorithmError("{0} is not an enabled {1} algorithm.".format(algorithm, label))
    return module


def summarize_measurements(run):
    rows = list(run.measurements.values_list("duration_ms", "success"))
    count = len(rows)
    successful = sum(1 for _, success in rows if success)
    if not count:
        return {
            "count": 0,
            "successful": 0,
            "failed": 0,
            "avg_ms": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0,
            "p95_ms": 0.0,
            "total_ms": 0.0,
        }
    durations = sorted(float(duration) for duration, _ in rows)
    total = sum(durations)
    p95_index = max(0, min(count - 1, math.ceil(0.95 * count) - 1))
    return {
        "count": count,
        "successful": successful,
        "failed": count - successful,
        "avg_ms": round(total / count, 3),
        "min_ms": round(durations[0], 3),
        "max_ms": round(durations[-1], 3),
        "p95_ms": round(durations[p95_index], 3),
        "total_ms": round(total, 3),
    }


def _elapsed(started):
    return round((time.perf_counter() - started) * 1000.0, 6)


def _open_primitive(stack, module, attribute, algorithm, secret_key=None):
    factory = getattr(module, attribute, None)
    if not callable(factory):
        raise UnsupportedAlgorithmError("The OQS module does not provide {0}.".format(attribute))
    if secret_key is None:
        instance = factory(algorithm)
    else:
        try:
            instance = factory(algorithm, secret_key)
        except TypeError:
            instance = factory(algorithm)
    if hasattr(instance, "__enter__") and hasattr(instance, "__exit__"):
        return stack.enter_context(instance)
    return instance


def _compare_secrets(expected, actual):
    try:
        return bool(hmac.compare_digest(bytes(expected), bytes(actual)))
    except (TypeError, ValueError):
        return bool(expected == actual)


def _kem_operation(module, algorithm):
    detail = {}
    with ExitStack() as stack:
        kem = _open_primitive(stack, module, "KeyEncapsulation", algorithm)
        started = time.perf_counter()
        public_key = kem.generate_keypair()
        detail["generate_ms"] = _elapsed(started)
        started = time.perf_counter()
        secret_key = kem.export_secret_key()
        detail["key_export_ms"] = _elapsed(started)
        started = time.perf_counter()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        detail["encapsulation_ms"] = _elapsed(started)
        started = time.perf_counter()
        decapsulator = _open_primitive(stack, module, "KeyEncapsulation", algorithm, secret_key=secret_key)
        recovered = decapsulator.decap_secret(ciphertext)
        detail["decapsulation_ms"] = _elapsed(started)
    match = _compare_secrets(shared_secret, recovered)
    detail["match"] = match
    return match, detail


def _signature_operation(module, algorithm):
    detail = {}
    with ExitStack() as stack:
        signer = _open_primitive(stack, module, "Signature", algorithm)
        started = time.perf_counter()
        public_key = signer.generate_keypair()
        detail["generate_ms"] = _elapsed(started)
        started = time.perf_counter()
        signer.export_secret_key()
        detail["key_export_ms"] = _elapsed(started)
        started = time.perf_counter()
        signature = signer.sign(MESSAGE)
        detail["sign_ms"] = _elapsed(started)
        started = time.perf_counter()
        verifier = _open_primitive(stack, module, "Signature", algorithm)
        try:
            valid = bool(verifier.verify(MESSAGE, signature, public_key))
        except (ValueError, TypeError, RuntimeError, OverflowError):
            valid = False
        detail["verify_ms"] = _elapsed(started)
    detail["valid"] = valid
    return valid, detail


def _perform_operation(operation, module, algorithm):
    if operation == BenchmarkOperation.KEM:
        return _kem_operation(module, algorithm)
    return _signature_operation(module, algorithm)


def _library_versions():
    getter = getattr(crypto, "library_versions", None)
    if not callable(getter):
        return {}
    try:
        return getter()
    except Exception:
        return {}


def run_benchmark(run):
    run.status = BenchmarkStatus.RUNNING
    run.started_at = timezone.now()
    run.error = ""
    run.save(update_fields=["status", "started_at", "error"])
    try:
        module = require_algorithm(run.algorithm, run.operation)
        for _ in range(run.warmup_iterations):
            _perform_operation(run.operation, module, run.algorithm)
        for iteration in range(1, run.iterations + 1):
            started = time.perf_counter()
            success, detail = _perform_operation(run.operation, module, run.algorithm)
            duration_ms = _elapsed(started)
            BenchmarkMeasurement.objects.create(
                run=run,
                iteration=iteration,
                phase="total",
                duration_ms=duration_ms,
                success=success,
                detail=detail,
            )
    except Exception as exc:
        run.status = BenchmarkStatus.FAILED
        run.error = str(exc)
        run.completed_at = timezone.now()
        run.summary = summarize_measurements(run)
        run.save(update_fields=["status", "error", "completed_at", "summary"])
        raise
    run.status = BenchmarkStatus.COMPLETED
    run.completed_at = timezone.now()
    summary = summarize_measurements(run)
    summary.update(
        {
            "algorithm": run.algorithm,
            "operation": run.operation,
            "iterations": run.iterations,
            "warmup_iterations": run.warmup_iterations,
            "library_versions": _library_versions(),
        }
    )
    run.summary = summary
    run.save(update_fields=["status", "completed_at", "summary"])
    return run


def create_benchmark_run(
    *,
    algorithm,
    operation,
    iterations=None,
    warmup_iterations=None,
    organization=None,
    requested_by=None,
    request=None,
):
    run = BenchmarkRun.objects.create(
        algorithm=str(algorithm or "").strip(),
        operation=operation,
        iterations=_iterations(iterations),
        warmup_iterations=_warmup_iterations(warmup_iterations),
        organization=organization,
        requested_by=requested_by,
    )
    record_audit(
        request,
        "benchmark.create",
        obj=run,
        details={
            "algorithm": run.algorithm,
            "operation": run.operation,
            "iterations": run.iterations,
            "warmup_iterations": run.warmup_iterations,
        },
        user=requested_by,
    )
    if bool(getattr(settings, "QS_BENCHMARK_ASYNC", False)):
        try:
            from .tasks import run_benchmark_task
        except ImportError:
            run_benchmark_task = None
        if run_benchmark_task is not None:
            result = run_benchmark_task.delay(run.pk)
            run.task_id = str(getattr(result, "id", result) or "")[:120]
            run.save(update_fields=["task_id"])
            return run
    run_benchmark(run)
    return run


def capabilities(report=None):
    report = report if report is not None else capability_report()
    return {
        "oqs_available": bool(report.get("oqs_available")),
        "oqs_version": report.get("oqs_version"),
        "enabled_kems": report.get("enabled_kems") or [],
        "enabled_signatures": report.get("enabled_signatures") or [],
        "default_iterations": _setting_int("QS_BENCHMARK_ITERATIONS", 10, minimum=1),
        "max_iterations": _setting_int("QS_BENCHMARK_MAX_ITERATIONS", 200, minimum=1),
        "async_enabled": bool(getattr(settings, "QS_BENCHMARK_ASYNC", False)),
    }
