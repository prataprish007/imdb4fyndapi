from django.contrib import admin
from django.conf.urls import url, include
from .views import *

app_name = "movie_api"

urlpatterns = [
    url(r"^getmovies/v1/$", ListAPI.as_view(), name="getmovies"),
    url(r"^getmovies/v1/(?P<id>[-\d]+)/$", GetMovieAPI.as_view(), name="getmovies"),

    url(r"^searchmovies/v1/(?P<search_keyword>[-\w]+)/$", SearchAPI.as_view(), name="searchmovies"),
    url(r"^updatemovies/v1/(?P<id>[-\d]+)/$", UpdateAPI.as_view(), name="updatemovies"),
    url(r"^addmovies/v1/$", CreateAPI.as_view(), name="createmovies"),
    url(r"^removemovies/v1/(?P<id>[-\d]+)/$", RemoveAPI.as_view(), name="removemovies"),


    url(r"^createuser/v1/$", CreateUserAPI.as_view(), name="createuser"),
]
