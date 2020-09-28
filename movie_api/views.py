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

    def get(self, request, *args, **kwargs):
        try:
            if "id" in self.kwargs:
                if self.kwargs['id'].isdigit():
                    id = self.kwargs['id']
                else:
                    return Response("To get movie by ID. ID should be a number", status=HTTP_200_OK)
            else:
                id = None

            if id is not None:
                movie_queryset = Movie.objects.filter(id=id).values_list('id', '_99popularity', 'name', 'genre', 'director', 'imdb_score')
            else:
                movie_queryset = Movie.objects.all().values_list('id', '_99popularity', 'name', 'genre', 'director', 'imdb_score')

            if movie_queryset.count() != 0:
                filtered_set = list(movie_queryset.values('id', '_99popularity', 'name', 'genre', 'director', 'imdb_score'))
                movie_list = json.loads(json.dumps(filtered_set))
            else:
                if id is not None:
                    return Response("Movie with ID: "+id+" Not Found", status=HTTP_404_NOT_FOUND)
                else:
                    return Response("Movies Not Found", status=HTTP_404_NOT_FOUND)

            return Response(movie_list, status=HTTP_200_OK)

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
            search_keyword = self.kwargs['search_keyword']
            movie_queryset = Movie.objects.filter(search_string__contains=search_keyword).values_list('id', '_99popularity', 'name', 'genre', 'director', 'imdb_score')
            # movie_json = serializers.serialize('json', movie_queryset)
            # movie_list = json.loads(movie_json)
            if movie_queryset.count() != 0:
                filtered_set = list(movie_queryset.values('id', '_99popularity', 'name', 'genre', 'director', 'imdb_score'))
                movie_list = json.loads(json.dumps(filtered_set))
                return Response(movie_list, status=HTTP_200_OK)
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

    def validate(self, movie_object):
        result = {
            'status': True,
            'message': ''
        }
        if '99popularity' not in movie_object or 'director' not in movie_object or 'genre' not in movie_object or 'imdb_score' not in movie_object or 'name' not in movie_object:
            result['status']=False
            result['message']='Parameter Missing!!'
            return result
        elif type(movie_object['imdb_score']) == str or movie_object['imdb_score'] > 10  or movie_object['imdb_score'] < 0:
            result['status']=False
            result['message']='IMDB Score not valid, should be a number between 0-10 !!'
            return result
        elif type(movie_object['99popularity']) == str or movie_object['99popularity'] > 100  or movie_object['99popularity'] < 0:
            result['status']=False
            result['message']='99popularity Score not valid, should be a number between 0-100 !!'
            return result
        elif type(movie_object['genre']) != list :
            result['status']=False
            result['message']='Genre should be a List or Array !!'
            return result
        else:
            return result

    def put(self, request, *args, **kwargs):
        try:
            id  = self.kwargs['id']
            Movie_obj = json.loads(json.dumps(request.data))
            print(Movie_obj)

            validate_flag = self.validate(Movie_obj)
            print(validate_flag)

            if validate_flag['status']:
                movie = Movie.objects.filter(pk=id)
                if movie.count() != 0:
                    movie.update(_99popularity=Movie_obj['99popularity'], name=Movie_obj['name'], genre=','.join(Movie_obj['genre']), director=Movie_obj['director'], imdb_score=Movie_obj['imdb_score'])
                    return Response("Movie with id: "+ id +" updated successfully.", status=HTTP_200_OK)
                else:
                    return Response("Movie with ID: "+id+" doesn't exist", status=HTTP_400_BAD_REQUEST)
            else:
                return Response(validate_flag['message'], status=HTTP_400_BAD_REQUEST)

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


    def validate(self, movie_object):
        result = {
            'status': True,
            'message': ''
        }
        if '99popularity' not in movie_object or 'director' not in movie_object or 'genre' not in movie_object or 'imdb_score' not in movie_object or 'name' not in movie_object:
            result['status']=False
            result['message']='Parameter Missing!!'
            return result
        elif type(movie_object['imdb_score']) == str or movie_object['imdb_score'] > 10  or movie_object['imdb_score'] < 0:
            result['status']=False
            result['message']='IMDB Score not valid, should be a number between 0-10 !!'
            return result
        elif type(movie_object['99popularity']) == str or movie_object['99popularity'] > 100  or movie_object['99popularity'] < 0:
            result['status']=False
            result['message']='99popularity Score not valid, should be a number between 0-100 !!'
            return result
        elif type(movie_object['genre']) != list :
            result['status']=False
            result['message']='Genre should be a List or Array !!'
            return result
        else:
            return result

    def post(self, request, *args, **kwargs):
        try:
            Movie_obj = json.loads(json.dumps(request.data))
            print(Movie_obj)

            validate_flag = self.validate(Movie_obj)
            print(validate_flag)

            if validate_flag['status']:
                movie = Movie.objects.filter(_99popularity=Movie_obj['99popularity'], name=Movie_obj['name'], genre=','.join(Movie_obj['genre']), director=Movie_obj['director'], imdb_score=Movie_obj['imdb_score'])
                if movie.count() > 0:
                    return Response("Movie already exists with same parameters.", status=HTTP_400_BAD_REQUEST)
                else:
                    search_string = str(Movie_obj['99popularity']) + ' '+ Movie_obj['director']+ ' ' + str(Movie_obj['imdb_score'])+ ' '  + Movie_obj['name']+ ' ' + ' '.join(Movie_obj['genre'])
                    movie = Movie(_99popularity=Movie_obj['99popularity'], name=Movie_obj['name'], genre=','.join(Movie_obj['genre']), director=Movie_obj['director'], imdb_score=Movie_obj['imdb_score'], search_string=search_string, search_count=0)
                    movie.save()
                    id = str(movie.id)
                    return Response("Movie Successfully Added with id: "+id, status=HTTP_200_OK)
            else:
                return Response(validate_flag['message'], status=HTTP_400_BAD_REQUEST)

        except Exception as e:
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
            id = self.kwargs['id']
            if id is not None:
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


