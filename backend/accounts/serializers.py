from rest_framework import serializers

from core.serializers import StrictSerializer


class LoginSerializer(StrictSerializer):
    username = serializers.CharField(max_length=150)
    # Capped before hashing: Argon2 on a megabyte-long "password" would be a cheap DoS.
    password = serializers.CharField(max_length=128, trim_whitespace=False, write_only=True)
