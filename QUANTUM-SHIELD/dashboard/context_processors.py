from core.crypto import get_oqs, oqs_version


def platform_context(request):
    try:
        module = get_oqs()
    except Exception:
        module = None
    version = None
    if module is not None:
        try:
            version = oqs_version()
        except Exception:
            version = None
    navigation = [
        {"label": "Dashboard", "url": "/dashboard/"},
        {"label": "Health", "url": "/health/"},
    ]
    user = getattr(request, "user", None)
    if user is not None and getattr(user, "is_authenticated", False):
        if getattr(user, "is_staff", False):
            navigation.append({"label": "Admin", "url": "/admin/"})
        navigation.append({"label": "Logout", "url": "/logout/"})
    else:
        navigation.append({"label": "Login", "url": "/login/"})
    return {
        "platform": {
            "name": "QuantumShield",
            "tagline": "Inventory, assess, and migrate cryptographic assets for the post-quantum era.",
            "oqs_available": module is not None,
            "oqs_version": version,
            "navigation": navigation,
        }
    }
