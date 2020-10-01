from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import BasicAuthentication, SessionAuthentication
from rest_framework import permissions, exceptions, HTTP_HEADER_ENCODING
from django.utils.translation import gettext as _
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK,
    HTTP_500_INTERNAL_SERVER_ERROR,
)
from rest_framework.generics import CreateAPIView
from django.contrib.auth import authenticate, get_user_model
from django.core import serializers
from django.db.models import Q
from movie_api.serializers import *
from movie_api.models import *
import json, re
import base64
import binascii

class CreateUserAPI(CreateAPIView):
    model = get_user_model()
    permission_classes = [
        permissions.AllowAny # Or anon users can't register
    ]
    serializer_class = UserSerializer

def get_authorization_header(request):
    """
    Return request's 'Authorization:' header, as a bytestring.
    Hide some test client ickyness where the header can be unicode.
    """
    auth = request.META.get('HTTP_AUTHORIZATION', b'')
    if isinstance(auth, str):
        # Work around django test client oddness
        auth = auth.encode(HTTP_HEADER_ENCODING)
    return auth

class CustomAuthentication(BasicAuthentication):
   
    # HTTP Basic authentication against username/password.
   
    www_authenticate_realm = 'api'

    def authenticate(self, request):
       
        # Returns a `User` if a correct username and password have been supplied
        # using HTTP Basic authentication.  Otherwise returns `None`.
    
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b'basic':
            return None

        if len(auth) == 1:
            msg = _('Invalid basic header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid basic header. Credentials string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            try:
                auth_decoded = base64.b64decode(auth[1]).decode('utf-8')
            except UnicodeDecodeError:
                auth_decoded = base64.b64decode(auth[1]).decode('latin-1')
            auth_parts = auth_decoded.partition(':')
        except (TypeError, UnicodeDecodeError, binascii.Error):
            msg = _('Invalid basic header. Credentials not correctly base64 encoded.')
            raise exceptions.AuthenticationFailed(msg)

        userid, password = auth_parts[0], auth_parts[2]
        return self.authenticate_credentials(userid, password, request)


class ViewMoviePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user.has_perm('movie_api.view_movie'):
            raise exceptions.PermissionDenied("Don't have permission")
        return True

class AdminMoviePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user.is_superuser:
            raise exceptions.PermissionDenied("Don't have permission")
        return True



# View for Getting Movies in List or With id
class ListAPI(APIView):
    authentication_classes = (CustomAuthentication, )
    # authentication_classes = (SessionAuthentication, BasicAuthentication, )
    permission_classes = (IsAuthenticated, ViewMoviePermission )
    # serializer_class = MovieListSerializer

    def get(self, request, *args, **kwargs):
        try:
            movie_queryset = Movie.objects.all().order_by('-search_count')[:50]
            serializer = MovieListSerializer(movie_queryset, many=True)
            return Response(serializer.data, status=HTTP_200_OK)
            
        except Exception as e:
            result = {
                "Error": "Something Went Wrong!! {}".format(e)
            }
            return Response(result, status=HTTP_500_INTERNAL_SERVER_ERROR)

class GetMovieAPI(APIView):
    authentication_classes = (CustomAuthentication, )
    # authentication_classes = (SessionAuthentication, BasicAuthentication, )
    permission_classes = (IsAuthenticated, ViewMoviePermission )
    # serializer_class = MovieListSerializer

    def get(self, request, *args, **kwargs):
        try:
            if "id" in self.kwargs:
                id = self.kwargs['id']
            else:
                return Response("Please provide Movie ID in URL.", status=HTTP_400_BAD_REQUEST)
            
            try:
                movie_obj = Movie.objects.get(pk=id)
                search_count = movie_obj.search_count + 1 
                movie_obj.search_count = search_count
                movie_obj.save()
            except Exception as e:
                print("exception : {}".format(e))
                return Response("Movie with matching ID does not exist.", status=HTTP_404_NOT_FOUND)
            serializer = GetMovieSerializer(movie_obj)
            return Response(serializer.data, status=HTTP_200_OK)
            
            
        except Exception as e:
            result = {
                "Error": "Something Went Wrong!! {}".format(e)
            }
            return Response(result, status=HTTP_500_INTERNAL_SERVER_ERROR)

# View for search in movie dataset
class SearchAPI(APIView):
    authentication_classes = (CustomAuthentication, )
    # authentication_classes = (SessionAuthentication, BasicAuthentication, )
    permission_classes = (IsAuthenticated, ViewMoviePermission )
    
    def get(self, request, *args, **kwargs):
        try:
            if "search_keyword" in self.kwargs:
                search_keyword = self.kwargs['search_keyword']
                lookups= Q(name__icontains=search_keyword) | Q(director__icontains=search_keyword) | Q(genre__name__icontains=search_keyword)
                movie_queryset= Movie.objects.filter(lookups).distinct().order_by('-search_count')[:30]

                if movie_queryset.count() != 0:
                    serializer = MovieSearchSerializer(movie_queryset, many=True)
                    return Response(serializer.data, status=HTTP_200_OK)
                else:
                    return Response("No Search Results", status=HTTP_200_OK)

        except Exception as e:
            result = {
                "Error": "Something Went Wrong!! {}".format(e)
            }
            return Response(result, status=HTTP_500_INTERNAL_SERVER_ERROR)

# View for Update in Movie Dataset, Only for Admin
class UpdateAPI(APIView):
    authentication_classes = (CustomAuthentication, )
    # authentication_classes = (SessionAuthentication, BasicAuthentication, )
    permission_classes = (IsAuthenticated, AdminMoviePermission )  # Only for Admin

    def put(self, request, *args, **kwargs):
        try:
            if "id" in self.kwargs:
                id = self.kwargs["id"]
                try:
                    movie = Movie.objects.get(pk=id)
                except Exception as e:
                    print("ex: {}".format(e))
                    return Response("Given ID does not exist.", status=HTTP_404_NOT_FOUND)

                serializer = MovieSerializer(movie, data=request.data)
                try:
                    serializer.is_valid(raise_exception=True)
                except Exception as e:
                    return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)
                movie = serializer.save()
                for gen in movie.genre.all():
                    movie.genre.remove(gen)
                for g in  request.data["genre"]:
                    genre_obj, created = Genre.objects.get_or_create(name=g)
                    movie.genre.add(genre_obj)
                print("updated", movie.id)
                return Response(serializer.data, status=HTTP_200_OK)
               

        except Exception as e:
            result = {
                "Error": "Something Went Wrong!! {}".format(e)
            }
            return Response(result, status=HTTP_500_INTERNAL_SERVER_ERROR)


# View for Add in Movie Dataset, Only for Admin
class CreateAPI(APIView):
    authentication_classes = (CustomAuthentication, )
    # authentication_classes = (SessionAuthentication, BasicAuthentication, )
    permission_classes = (IsAuthenticated, AdminMoviePermission )  # Only for Admin

    def post(self, request, *args, **kwargs):
        try:
            serializer = MovieSerializer(data=request.data)
            try:
                serializer.is_valid(raise_exception=True)
            except Exception as e:
                return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)
            movie = serializer.save()
            for g in request.data.get('genre'):
                genre_obj, created = Genre.objects.get_or_create(name=g)
                movie.genre.add(genre_obj)
            print("saved", movie.id)
            return Response(serializer.data, status=HTTP_200_OK)
           
        except Exception as e:
            if "UNIQUE" in "{}".format(e):
                return Response("Director Name and Movie Name should be UNIQUE together.", status=HTTP_400_BAD_REQUEST)
            
            result = {
                "Error": "Something Went Wrong!! {}".format(e)
            }
            return Response(result, status=HTTP_500_INTERNAL_SERVER_ERROR)


# View for Update in Movie Dataset, Only for Admin
class RemoveAPI(APIView):
    authentication_classes = (CustomAuthentication, )
    # authentication_classes = (SessionAuthentication, BasicAuthentication, )
    permission_classes = (IsAuthenticated, AdminMoviePermission ) # Only for Admin


    def delete(self, request, *args, **kwargs):
        try:
            if "id" in self.kwargs:
                id = self.kwargs['id']
                movie = Movie.objects.filter(id=id)
                movie.delete()
                return Response("Movie Successfully deleted with id: "+id, status=HTTP_200_OK)
            else:
                return Response("Pass movie id in URL.", status=HTTP_400_BAD_REQUEST)
        except Exception as e:
            result = {
                "Error": "Something Went Wrong!! {}".format(e)
            }
            return Response(result, status=HTTP_500_INTERNAL_SERVER_ERROR)


