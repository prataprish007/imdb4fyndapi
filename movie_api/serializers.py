from movie_api.models import *
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
        # Tuple of serialized model 
        fields = ( "id", "email", "username", "password", )

class MovieListSerializer(serializers.BaseSerializer):
    def to_representation(self, instance):
        return {
            'id': instance.id,
            'movie_name': instance.name
        }

class GetMovieSerializer(serializers.BaseSerializer):
    def to_representation(self, instance):
        return {
            "id": instance.id,
            "99popularity": instance._99popularity,
            "imdb_score":instance.imdb_score,
            "genre":[x.name for x in instance.genre.all()],
            "director": instance.director,
            "movie_name": instance.name
        }
class MovieSearchSerializer(serializers.BaseSerializer):
    def to_representation(self, instance):
        return {
            "id": instance.id,
            "99popularity": instance._99popularity,
            "imdb_score":instance.imdb_score,
            "genre":[x.name for x in instance.genre.all()],
            "director": instance.director,
            "movie_name": instance.name
        }
class MovieSerializer(serializers.BaseSerializer):
    def to_internal_value(self, data):
        _99popularity  = data.get('99popularity')
        genre = data.get('genre')
        imdb_score = data.get('imdb_score')
        director = data.get('director')
        name = data.get('name')
        if not _99popularity :
            raise serializers.ValidationError({
                '99popularity': 'This field is required.'
            })
        if not genre :
            raise serializers.ValidationError({
                'genre': 'This field is required.'
            })
        if not imdb_score :
            raise serializers.ValidationError({
                'imdb_score': 'This field is required.'
            })
        if not director :
            raise serializers.ValidationError({
                'director': 'This field is required.'
            })
        if not name :
            raise serializers.ValidationError({
                'name': 'This field is required.'
            })
        if imdb_score < 0 or imdb_score > 10:
            raise serializers.ValidationError({
                'imdb_score': 'Should be a number between 0 to 10'
            })
        if _99popularity < 0 or _99popularity > 100:
            raise serializers.ValidationError({
                '_99popularity': 'Should be a number between 0 to 100'
            })
        if type(genre) != list:
            raise serializers.ValidationError({
                'genre': 'Should be a list or array'
            })

        # # Return the validated values. This will be available as
        # # the `.validated_data` property.
        return {
           "_99popularity":_99popularity,
            "genre":genre,
            "imdb_score" :imdb_score,
            "director" :director,
            "name":name
        }

    def to_representation(self, instance):
        print("inside to represent",[x.name for x in instance.genre.all()])
        return {
            "id": instance.id,
            "_99popularity":instance._99popularity,
            "genre":[x.name for x in instance.genre.all()],
            "imdb_score":instance.imdb_score,
            "director":instance.director,
            "name":instance.name
        }

    def create(self, validated_data):
        search_string = ' '
        for i in validated_data.keys():
            if i != "genre":
                search_string = str(validated_data[i]) +  search_string
        validated_data["search_string"] = search_string + (' ').join(validated_data["genre"])
        genre = validated_data.pop("genre")
        movie = Movie.objects.create(**validated_data)
        movie.save()
        print("movie saved: ", movie.id)

        return movie

    def update(self, instance, validated_data):
        genre = validated_data.pop("genre")
        for key, value in validated_data.items():
            setattr(instance, key, value)
        instance.save()
        return instance



   