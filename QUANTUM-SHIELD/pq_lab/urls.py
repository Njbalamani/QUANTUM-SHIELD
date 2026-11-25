from django.urls import path

from .views import (
    CapabilityView,
    EphemeralDeleteView,
    KemDecapsulateView,
    KemEncapsulateView,
    KemGenerateView,
    SignatureGenerateView,
    SignatureSignView,
    SignatureVerifyView,
)

urlpatterns = [
    path("capabilities/", CapabilityView.as_view(), name="pq-capabilities"),
    path("kem/generate/", KemGenerateView.as_view(), name="pq-kem-generate"),
    path("kem/encapsulate/", KemEncapsulateView.as_view(), name="pq-kem-encapsulate"),
    path("kem/decapsulate/", KemDecapsulateView.as_view(), name="pq-kem-decapsulate"),
    path("signature/generate/", SignatureGenerateView.as_view(), name="pq-signature-generate"),
    path("signature/sign/", SignatureSignView.as_view(), name="pq-signature-sign"),
    path("signature/verify/", SignatureVerifyView.as_view(), name="pq-signature-verify"),
    path("ephemeral/<str:operation_id>/", EphemeralDeleteView.as_view(), name="pq-ephemeral-delete"),
]
