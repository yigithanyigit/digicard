from rest_framework import serializers
from django.contrib.auth import get_user_model
from user_api.models import Social, Profile, Image


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=100, min_length=8, style={'input_type': 'password'})

    class Meta:
        model = get_user_model()
        fields = ['email', 'username', 'password', 'name', 'surname', 'title']

    def create(self, validated_data):
        user_password = validated_data.get('password', None)
        db_instance = self.Meta.model(email=validated_data.get('email'), username=validated_data.get('username'),
                                      name=validated_data.get('name'), surname=validated_data.get('surname'),
                                      title=validated_data.get('title'))
        db_instance.set_password(user_password)
        db_instance.save()
        return db_instance


class UserLoginSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=100)
    username = serializers.CharField(max_length=100)
    password = serializers.CharField(max_length=100, min_length=8, style={'input_type': 'password'})
    token = serializers.CharField(max_length=255, read_only=True)


class UserViewSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ['user_id', 'username', 'name', 'surname', 'title']


class SocialSerializer(serializers.ModelSerializer):
    class Meta:
        model = Social
        fields = ["social_id", "user", "type", "url"]

    def create(self, validated_data):
        db_instance = self.Meta.model(type=validated_data.get('type'), user=validated_data.get('user'),
                                      url=validated_data.get('url'))
        db_instance.save()
        return db_instance


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ["user", "content", "type"]


class ImageSeriliazer(serializers.ModelSerializer):
    class Meta:
        model = Image
        fields = ["image"]


class UserAttributesSerializer(serializers.Serializer):
    user = UserViewSerializer(many=True)
    social = SocialSerializer(many=True)
    profile = ProfileSerializer(many=True)


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    new_password_confirmation = serializers.CharField(required=True)

class UserProfileSerializer(serializers.ModelSerializer):

    # To prevent multiple users we do not provide change name options
    class Meta:
        model = get_user_model()
        fields = ["user", "title"]

