from rest_framework import serializers
from django.contrib.auth import get_user_model # If used custom user model
from django.contrib.auth.models import Permission

UserModel = get_user_model()


class UserSerializer(serializers.ModelSerializer):

    password = serializers.CharField(write_only=True)

    def create(self, validated_data):

        user = UserModel.objects.create(
            username=validated_data['username'], 
            email=validated_data['email']
        )
        user.set_password(validated_data['password'])
        permission = Permission.objects.get(name="Can view movie")
        user.user_permissions.add(permission)
        user.save()
        return user

    class Meta:
        model = UserModel
        # Tuple of serialized model fields (see link [2])
        fields = ( "id", "email", "username", "password", )