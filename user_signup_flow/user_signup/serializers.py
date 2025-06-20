from rest_framework import serializers
from .models import User
from django.contrib.auth.hashers import make_password

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id', 'full_name', 'email', 'password', 'phone',
            'dob', 'nationality', 'gender', 'address', 'profile_picture',
            'registered_at',"type_flag", 'google_id', 'facebook_id', 'is_verified','is_active'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'registered_at': {'read_only': True},
        }

    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data['password'])
        return super().create(validated_data)
