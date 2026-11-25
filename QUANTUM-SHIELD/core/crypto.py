import base64
import hashlib
import importlib
import os
from functools import lru_cache

from django.conf import settings


class UnsupportedAlgorithmError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def get_oqs():
    prefix = str(getattr(settings, "QS_OQS_PREFIX", "") or "")
    if prefix and os.name == "nt" and hasattr(os, "add_dll_directory"):
        bin_dir = os.path.join(prefix, "bin")
        if os.path.isdir(bin_dir):
            try:
                os.add_dll_directory(bin_dir)
            except OSError:
                pass
    try:
        return importlib.import_module("oqs")
    except Exception:
        return None


def oqs_available():
    return get_oqs() is not None


def oqs_version():
    module = get_oqs()
    if module is None:
        return None
    return getattr(module, "OQS_VERSION", None) or getattr(module, "__version__", None)


def enabled_kems():
    module = get_oqs()
    if module is None:
        return []
    try:
        return sorted(module.get_enabled_kem_algos())
    except Exception:
        return []


def enabled_signatures():
    module = get_oqs()
    if module is None:
        return []
    try:
        return sorted(module.get_enabled_sig_algos())
    except Exception:
        return []


def is_enabled_kem(name):
    return name in enabled_kems()


def is_enabled_signature(name):
    return name in enabled_signatures()


def capability_report():
    module = get_oqs()
    return {
        "oqs_available": module is not None,
        "oqs_version": oqs_version(),
        "enabled_kems": enabled_kems(),
        "enabled_signatures": enabled_signatures(),
        "warning": None if module is not None else "Open Quantum Safe bindings unavailable; PQ operations are disabled.",
    }


def b64encode(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii")


def b64decode(value):
    return base64.urlsafe_b64decode(value.encode("ascii"))


def digest_b64(raw):
    return b64encode(hashlib.sha256(raw).digest())


def library_versions():
    versions = {"python": None, "django": None, "cryptography": None, "oqs": oqs_version()}
    try:
        import platform

        versions["python"] = platform.python_version()
    except Exception:
        pass
    try:
        import django

        versions["django"] = django.get_version()
    except Exception:
        pass
    try:
        import cryptography

        versions["cryptography"] = cryptography.__version__
    except Exception:
        pass
    return versions
