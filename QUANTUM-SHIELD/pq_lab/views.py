from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from core.audit import record_audit
from core.crypto import UnsupportedAlgorithmError
from core.permissions import IsAnalystOrAdmin, IsViewerOrHigher

from .serializers import (
    AlgorithmInputSerializer,
    CapabilitySerializer,
    EphemeralDeleteResultSerializer,
    KemDecapsulateInputSerializer,
    KemDecapsulateResultSerializer,
    KemEncapsulateResultSerializer,
    KemGenerateResultSerializer,
    OperationIdInputSerializer,
    SignatureGenerateResultSerializer,
    SignatureSignInputSerializer,
    SignatureSignResultSerializer,
    SignatureVerifyInputSerializer,
    SignatureVerifyResultSerializer,
)
from .services import (
    capability_data,
    delete_operation,
    kem_decapsulate,
    kem_encapsulate,
    kem_generate,
    signature_generate,
    signature_sign,
    signature_verify,
)


class CapabilityView(APIView):
    permission_classes = (IsViewerOrHigher,)

    def get(self, request):
        payload = capability_data()
        serializer = CapabilitySerializer(data=payload)
        serializer.is_valid(raise_exception=True)
        record_audit(request, "pq_lab.capabilities.read", details={})
        return Response(serializer.data)


class PqLabOperationView(APIView):
    permission_classes = (IsAnalystOrAdmin,)
    input_serializer_class = None
    output_serializer_class = None

    def post(self, request, *args, **kwargs):
        input_serializer = self.input_serializer_class(data=request.data)
        input_serializer.is_valid(raise_exception=True)
        try:
            result = self.perform(input_serializer.validated_data, **kwargs)
        except (UnsupportedAlgorithmError, ValueError, TypeError) as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        self.audit(request, result)
        output_serializer = self.output_serializer_class(data=result)
        output_serializer.is_valid(raise_exception=True)
        return Response(output_serializer.data)

    def perform(self, validated_data, **kwargs):
        raise NotImplementedError

    def audit(self, request, result):
        return None


class KemGenerateView(PqLabOperationView):
    input_serializer_class = AlgorithmInputSerializer
    output_serializer_class = KemGenerateResultSerializer

    def perform(self, validated_data, **kwargs):
        return kem_generate(validated_data["algorithm"])

    def audit(self, request, result):
        record_audit(
            request,
            "pq_lab.kem.generate",
            obj=result["operation_id"],
            details={
                "algorithm": result["algorithm"],
                "operation_id": result["operation_id"],
                "public_key_size": result["public_key_size"],
                "private_key_size": result["private_key_size"],
            },
        )


class KemEncapsulateView(PqLabOperationView):
    input_serializer_class = OperationIdInputSerializer
    output_serializer_class = KemEncapsulateResultSerializer

    def perform(self, validated_data, **kwargs):
        return kem_encapsulate(str(validated_data["operation_id"]))

    def audit(self, request, result):
        record_audit(
            request,
            "pq_lab.kem.encapsulate",
            obj=result["operation_id"],
            details={
                "algorithm": result["algorithm"],
                "operation_id": result["operation_id"],
                "ciphertext_size": result["ciphertext_size"],
            },
        )


class KemDecapsulateView(PqLabOperationView):
    input_serializer_class = KemDecapsulateInputSerializer
    output_serializer_class = KemDecapsulateResultSerializer

    def perform(self, validated_data, **kwargs):
        return kem_decapsulate(str(validated_data["operation_id"]), validated_data["ciphertext"])

    def audit(self, request, result):
        record_audit(
            request,
            "pq_lab.kem.decapsulate",
            obj=result["operation_id"],
            details={
                "algorithm": result["algorithm"],
                "operation_id": result["operation_id"],
                "matches": result["matches"],
            },
        )


class SignatureGenerateView(PqLabOperationView):
    input_serializer_class = AlgorithmInputSerializer
    output_serializer_class = SignatureGenerateResultSerializer

    def perform(self, validated_data, **kwargs):
        return signature_generate(validated_data["algorithm"])

    def audit(self, request, result):
        record_audit(
            request,
            "pq_lab.signature.generate",
            obj=result["operation_id"],
            details={
                "algorithm": result["algorithm"],
                "operation_id": result["operation_id"],
                "public_key_size": result["public_key_size"],
                "private_key_size": result["private_key_size"],
            },
        )


class SignatureSignView(PqLabOperationView):
    input_serializer_class = SignatureSignInputSerializer
    output_serializer_class = SignatureSignResultSerializer

    def perform(self, validated_data, **kwargs):
        return signature_sign(
            str(validated_data["operation_id"]),
            validated_data["message"],
            validated_data["tamper"],
        )

    def audit(self, request, result):
        record_audit(
            request,
            "pq_lab.signature.sign",
            obj=result["operation_id"],
            details={
                "algorithm": result["algorithm"],
                "operation_id": result["operation_id"],
                "signature_size": result["signature_size"],
            },
        )


class SignatureVerifyView(PqLabOperationView):
    input_serializer_class = SignatureVerifyInputSerializer
    output_serializer_class = SignatureVerifyResultSerializer

    def perform(self, validated_data, **kwargs):
        return signature_verify(
            validated_data["algorithm"],
            validated_data["public_key"],
            validated_data["message"],
            validated_data["signature"],
        )

    def audit(self, request, result):
        record_audit(
            request,
            "pq_lab.signature.verify",
            details={
                "algorithm": result["algorithm"],
                "valid": result["valid"],
            },
        )


class EphemeralDeleteView(APIView):
    permission_classes = (IsAnalystOrAdmin,)

    def delete(self, request, operation_id):
        serializer = OperationIdInputSerializer(data={"operation_id": operation_id})
        serializer.is_valid(raise_exception=True)
        operation_id = str(serializer.validated_data["operation_id"])
        result = {"operation_id": operation_id, "deleted": delete_operation(operation_id)}
        record_audit(
            request,
            "pq_lab.ephemeral.delete",
            obj=operation_id,
            details=result,
        )
        output_serializer = EphemeralDeleteResultSerializer(data=result)
        output_serializer.is_valid(raise_exception=True)
        return Response(output_serializer.data)
