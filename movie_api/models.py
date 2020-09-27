from django.db import models
import uuid


# Create your models here.
class Movie(models.Model):
    id = models.AutoField(primary_key=True)
    _99popularity = models.FloatField(default=0,null=True)
    genre = models.CharField(max_length=500,null=True,blank=True)
    director = models.CharField(max_length=100,null=True,blank=True)
    imdb_score = models.FloatField(default=0,null=True)
    name = models.CharField(max_length=100)
    search_string = models.CharField(max_length=300)
    search_count = models.IntegerField(default=0, db_index=True)
