from django.db.models import Model

SECRET_KEYS = {
    "private_key",
    "privatekey",
    "secret",
    "secret_key",
    "password",
    "passphrase",
    "token",
    "authorization",
    "api_key",
    "apikey",
}


def sanitize(value, depth=0):
    if depth > 6:
        return "[redacted]"
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            normalized = str(key).strip().lower().replace("-", "_").replace(" ", "_")
            if normalized in SECRET_KEYS or normalized.endswith("_key") and "public" not in normalized:
                result[str(key)] = "[redacted]"
            else:
                result[str(key)] = sanitize(item, depth + 1)
        return result
    if isinstance(value, (list, tuple, set)):
        return [sanitize(item, depth + 1) for item in value]
    if isinstance(value, Model):
        return f"{value._meta.label}:{value.pk}"
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def client_ip(request):
    if request is None:
        return None
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR") or None


def record_audit(request=None, action="", obj=None, details=None, user=None):
    from .models import AuditLog

    actor = user or getattr(request, "user", None)
    if actor is not None and not getattr(actor, "is_authenticated", False):
        actor = None
    user_agent = ""
    if request is not None:
        user_agent = request.META.get("HTTP_USER_AGENT", "")[:300]
    object_type = ""
    object_id = ""
    if isinstance(obj, Model):
        object_type = obj._meta.label
        object_id = str(obj.pk)
    elif obj is not None:
        object_type = type(obj).__name__
        object_id = str(obj)[:120]
    return AuditLog.objects.create(
        user=actor,
        action=action[:120],
        object_type=object_type[:120],
        object_id=object_id[:120],
        details=sanitize(details or {}),
        ip_address=client_ip(request),
        user_agent=user_agent,
    )
