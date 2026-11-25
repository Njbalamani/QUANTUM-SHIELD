from rest_framework import serializers


class AlgorithmInputSerializer(serializers.Serializer):
    algorithm = serializers.CharField(max_length=128)


class OperationIdInputSerializer(serializers.Serializer):
    operation_id = serializers.UUIDField()


class KemDecapsulateInputSerializer(OperationIdInputSerializer):
    ciphertext = serializers.CharField()


class SignatureSignInputSerializer(OperationIdInputSerializer):
    message = serializers.CharField(allow_blank=True, trim_whitespace=False)
    tamper = serializers.BooleanField(required=False, default=False)


class SignatureVerifyInputSerializer(serializers.Serializer):
    algorithm = serializers.CharField(max_length=128)
    public_key = serializers.CharField()
    message = serializers.CharField(allow_blank=True, trim_whitespace=False)
    signature = serializers.CharField()


class CapabilitySerializer(serializers.Serializer):
    oqs_available = serializers.BooleanField()
    oqs_version = serializers.CharField(allow_null=True)
    enabled_kems = serializers.ListField(child=serializers.CharField())
    enabled_signatures = serializers.ListField(child=serializers.CharField())
    warning = serializers.CharField(allow_null=True)
    library_versions = serializers.DictField(child=serializers.CharField(allow_null=True))


class KemGenerateResultSerializer(serializers.Serializer):
    operation_id = serializers.UUIDField()
    algorithm = serializers.CharField()
    public_key = serializers.CharField()
    public_key_size = serializers.IntegerField(min_value=0)
    private_key_size = serializers.IntegerField(min_value=0)
    warning = serializers.CharField(allow_null=True)


class KemEncapsulateResultSerializer(serializers.Serializer):
    operation_id = serializers.UUIDField()
    algorithm = serializers.CharField()
    ciphertext = serializers.CharField()
    ciphertext_size = serializers.IntegerField(min_value=0)
    shared_secret_digest = serializers.CharField()
    warning = serializers.CharField(allow_null=True)


class KemDecapsulateResultSerializer(serializers.Serializer):
    operation_id = serializers.UUIDField()
    algorithm = serializers.CharField()
    shared_secret_digest = serializers.CharField()
    matches = serializers.BooleanField()
    warning = serializers.CharField(allow_null=True)


class SignatureGenerateResultSerializer(serializers.Serializer):
    operation_id = serializers.UUIDField()
    algorithm = serializers.CharField()
    public_key = serializers.CharField()
    public_key_size = serializers.IntegerField(min_value=0)
    private_key_size = serializers.IntegerField(min_value=0)
    warning = serializers.CharField(allow_null=True)


class SignatureSignResultSerializer(serializers.Serializer):
    operation_id = serializers.UUIDField()
    algorithm = serializers.CharField()
    signature = serializers.CharField()
    signature_size = serializers.IntegerField(min_value=0)
    message_digest = serializers.CharField()
    warning = serializers.CharField(allow_null=True)


class SignatureVerifyResultSerializer(serializers.Serializer):
    algorithm = serializers.CharField()
    valid = serializers.BooleanField()
    message_digest = serializers.CharField()
    warning = serializers.CharField(allow_null=True)


class EphemeralDeleteResultSerializer(serializers.Serializer):
    operation_id = serializers.UUIDField()
    deleted = serializers.BooleanField()
