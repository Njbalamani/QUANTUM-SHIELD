import hmac
import uuid

from django.conf import settings
from django.core.cache import cache

from core.crypto import (
    UnsupportedAlgorithmError,
    b64decode,
    b64encode,
    capability_report,
    digest_b64,
    enabled_kems,
    enabled_signatures,
    get_oqs,
    library_versions,
    oqs_version,
)

CACHE_PREFIX = "pq_lab:operation:"
DEFAULT_TTL = 300
KEM = "kem"
SIGNATURE = "signature"


def _ttl():
    try:
        value = int(getattr(settings, "QS_EPHEMERAL_KEY_TTL", DEFAULT_TTL))
    except (TypeError, ValueError):
        return DEFAULT_TTL
    return value if value > 0 else DEFAULT_TTL


def _warning(extra=None):
    message = "Ephemeral private key is held only in cache and expires in {0} seconds.".format(_ttl())
    return "{0} {1}".format(message, extra) if extra else message


def _module():
    module = get_oqs()
    if module is None or not hasattr(module, "KeyEncapsulation") or not hasattr(module, "Signature"):
        raise UnsupportedAlgorithmError(
            "Open Quantum Safe bindings are unavailable; PQ operations are disabled."
        )
    return module


def _enabled_names(module, oqs_kind, legacy_names):
    names = set()
    for attribute in ("get_enabled_{0}_mechanisms".format(oqs_kind), "get_enabled_{0}_algos".format(oqs_kind)):
        getter = getattr(module, attribute, None)
        if callable(getter):
            try:
                names.update(str(item) for item in getter())
            except Exception:
                pass
    try:
        names.update(legacy_names())
    except Exception:
        pass
    return names


def _require_algorithm(algorithm, kind):
    if not isinstance(algorithm, str) or not algorithm.strip():
        raise UnsupportedAlgorithmError("An algorithm name is required.")
    module = _module()
    if kind == KEM:
        names = _enabled_names(module, "kem", enabled_kems)
        checker = getattr(module, "is_kem_enabled", None)
        label = "KEM"
    else:
        names = _enabled_names(module, "sig", enabled_signatures)
        checker = getattr(module, "is_sig_enabled", None)
        label = "signature"
    enabled = algorithm in names
    if not enabled and callable(checker):
        try:
            enabled = bool(checker(algorithm))
        except Exception:
            enabled = False
    if not enabled:
        raise UnsupportedAlgorithmError("{0} is not an enabled {1} algorithm.".format(algorithm, label))
    return module


def _decode_b64(value, field):
    if not isinstance(value, str) or not value:
        raise ValueError("{0} must be a non-empty base64 value.".format(field))
    try:
        raw = b64decode(value)
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise ValueError("{0} is not valid url-safe base64.".format(field)) from exc
    if not raw:
        raise ValueError("{0} must not be empty.".format(field))
    if b64encode(raw).rstrip("=") != value.rstrip("="):
        raise ValueError("{0} is not valid url-safe base64.".format(field))
    return raw


def _message_bytes(message):
    if isinstance(message, bytes):
        return message
    if not isinstance(message, str):
        raise ValueError("message must be a string.")
    return message.encode("utf-8")


def _operation_key(operation_id):
    return "{0}{1}".format(CACHE_PREFIX, operation_id)


def _normalize_operation_id(operation_id):
    try:
        return str(uuid.UUID(str(operation_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("operation_id must be a valid UUID.") from exc


def _store(operation_id, payload):
    cache.set(_operation_key(operation_id), payload, timeout=_ttl())


def _load(operation_id, expected_kind):
    operation_id = _normalize_operation_id(operation_id)
    payload = cache.get(_operation_key(operation_id))
    if not isinstance(payload, dict) or payload.get("kind") != expected_kind:
        raise ValueError("Operation not found or expired.")
    return operation_id, payload


def capability_data():
    report = capability_report()
    module = get_oqs()
    if module is None:
        result = dict(report)
        result["library_versions"] = library_versions()
        return result
    result = dict(report)
    result["oqs_available"] = True
    result["oqs_version"] = oqs_version() or result.get("oqs_version")
    result["enabled_kems"] = sorted(_enabled_names(module, "kem", enabled_kems))
    result["enabled_signatures"] = sorted(_enabled_names(module, "sig", enabled_signatures))
    result["warning"] = None
    result["library_versions"] = library_versions()
    return result


def kem_generate(algorithm):
    module = _require_algorithm(algorithm, KEM)
    with module.KeyEncapsulation(algorithm) as kem:
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
    operation_id = str(uuid.uuid4())
    _store(
        operation_id,
        {
            "kind": KEM,
            "algorithm": algorithm,
            "public_key": b64encode(public_key),
            "private_key": private_key,
            "shared_secret_digest": None,
        },
    )
    return {
        "operation_id": operation_id,
        "algorithm": algorithm,
        "public_key": b64encode(public_key),
        "public_key_size": len(public_key),
        "private_key_size": len(private_key),
        "warning": _warning(),
    }


def kem_encapsulate(operation_id):
    operation_id, payload = _load(operation_id, KEM)
    module = _module()
    algorithm = payload["algorithm"]
    public_key = _decode_b64(payload["public_key"], "public_key")
    with module.KeyEncapsulation(algorithm) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    secret_digest = digest_b64(shared_secret)
    payload["shared_secret_digest"] = secret_digest
    _store(operation_id, payload)
    return {
        "operation_id": operation_id,
        "algorithm": algorithm,
        "ciphertext": b64encode(ciphertext),
        "ciphertext_size": len(ciphertext),
        "shared_secret_digest": secret_digest,
        "warning": _warning(),
    }


def kem_decapsulate(operation_id, ciphertext_b64):
    operation_id, payload = _load(operation_id, KEM)
    expected_digest = payload.get("shared_secret_digest")
    if not expected_digest:
        raise ValueError("This operation has not been encapsulated yet.")
    ciphertext = _decode_b64(ciphertext_b64, "ciphertext")
    module = _module()
    with module.KeyEncapsulation(payload["algorithm"], payload["private_key"]) as kem:
        shared_secret = kem.decap_secret(ciphertext)
    actual_digest = digest_b64(shared_secret)
    return {
        "operation_id": operation_id,
        "algorithm": payload["algorithm"],
        "shared_secret_digest": actual_digest,
        "matches": hmac.compare_digest(actual_digest, expected_digest),
        "warning": _warning(),
    }


def signature_generate(algorithm):
    module = _require_algorithm(algorithm, SIGNATURE)
    with module.Signature(algorithm) as signer:
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()
    operation_id = str(uuid.uuid4())
    _store(
        operation_id,
        {
            "kind": SIGNATURE,
            "algorithm": algorithm,
            "public_key": b64encode(public_key),
            "private_key": private_key,
        },
    )
    return {
        "operation_id": operation_id,
        "algorithm": algorithm,
        "public_key": b64encode(public_key),
        "public_key_size": len(public_key),
        "private_key_size": len(private_key),
        "warning": _warning(),
    }


def signature_sign(operation_id, message, tamper=False):
    operation_id, payload = _load(operation_id, SIGNATURE)
    message_bytes = _message_bytes(message)
    module = _module()
    with module.Signature(payload["algorithm"], payload["private_key"]) as signer:
        signature = signer.sign(message_bytes)
    extra = None
    if tamper:
        if not signature:
            raise ValueError("The signature engine returned an empty signature.")
        signature = bytes([signature[0] ^ 1]) + signature[1:]
        extra = "The signature was deliberately altered to demonstrate verification failure."
    return {
        "operation_id": operation_id,
        "algorithm": payload["algorithm"],
        "signature": b64encode(signature),
        "signature_size": len(signature),
        "message_digest": digest_b64(message_bytes),
        "warning": _warning(extra),
    }


def signature_verify(algorithm, public_key_b64, message, signature_b64):
    module = _require_algorithm(algorithm, SIGNATURE)
    public_key = _decode_b64(public_key_b64, "public_key")
    signature = _decode_b64(signature_b64, "signature")
    message_bytes = _message_bytes(message)
    try:
        with module.Signature(algorithm) as verifier:
            valid = bool(verifier.verify(message_bytes, signature, public_key))
    except (ValueError, TypeError, RuntimeError, OverflowError):
        valid = False
    return {
        "algorithm": algorithm,
        "valid": valid,
        "message_digest": digest_b64(message_bytes),
        "warning": None,
    }


def delete_operation(operation_id):
    try:
        operation_id = _normalize_operation_id(operation_id)
    except ValueError:
        return False
    return bool(cache.delete(_operation_key(operation_id)))
