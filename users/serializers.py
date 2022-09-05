from rest_framework import serializers


class KakaoSignInSerializer(serializers.Serializer):
    refresh = serializers.CharField(max_length=255)
    access  = serializers.CharField(max_length=255)