import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "imdb_project.settings")
import django
django.setup()

import json
from movie_api.models import Genre, Movie

with open('./imdb_json.json') as f:
  data = json.load(f)
  for item in data:
    print(item['name'])
    search_string = str(item['99popularity']) + ' '+ item['director']+ ' ' + str(item['imdb_score'])+ ' '  + item['name']+ ' ' + ' '.join(item['genre'])
    movie = Movie(_99popularity=item['99popularity'], director=item['director'], imdb_score=item['imdb_score'], name=item['name'], search_string=search_string, search_count=0)
    movie.save()
    for g in item['genre']:
      genre_obj, created = Genre.objects.get_or_create(name=g)
      movie.genre.add(genre_obj)

    

# Output: {'name': 'Bob', 'languages': ['English', 'Fench']}
# print(data)
