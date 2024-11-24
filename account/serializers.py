from rest_framework import serializers
from .utils import *
from .models import *


class AccountSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    password_confirmation = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = Account
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "date_of_birth",
            "age",
            "gender",
            "username",
            "phone_number",
            "password",
            "password_confirmation"
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "password": {"write_only": True},
            "password_confirmation": {"write_only": True},
            "age": {"read_only": True},
        }

    def validate(self, data):
        if data["password"] != data["password_confirmation"]:
            raise serializers.ValidationError("password do not match")
        try:
            validate_password(data["password"])
        except ValidationError as e:
            raise serializers.ValidationError(str(e))
        return data
    
    def create(self, validated_data):
        validated_data.pop("password_confirmation")
        user = Account.objects.create_user(**validated_data)
        return user
    


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    username = serializers.CharField(required=False)
    password = serializers.CharField()



class ProfileSerializer(serializers.ModelSerializer):
    age = serializers.IntegerField(read_only=True)

    class Meta:
        model = Account
        fields = [
            "email",
            "first_name",
            "last_name",
            "date_of_birth",
            "age",
            "gender",
            "username",
            "phone_number"
        ]



class SetNewPasswordSerializer(serializers.Serializer):
    otp = serializers.CharField()
    password = serializers.CharField()
    password_confirmation = serializers.CharField()

    def validate(self, data):
        if data["password"]!= data["password_confirmation"]:
            serializers.ValidationError("password do not match")
        try:
            validate_otp(self.context["request"].user.email, data["otp"])
        except ValidationError as e:
            raise serializers.ValidationError(str(e))
        return data
    


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    password = serializers.CharField()
    password_confirmation = serializers.CharField()

    def validate(self, data):
        user = self.context["request"].user
        if not user.check_password(data["old_password"]):
            raise serializers.ValidationError("old password is incorrect")
        if user.password != data["password"] != data["password_confirmation"]:
            raise serializers.ValidationError("password do not match")
        try:
            validate_password(data["password"], user=user)
        except ValidationError as e:
            raise serializers.ValidationError(str(e))
        return data