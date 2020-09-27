import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "imdb_project.settings")
import django
django.setup()

import json
from movie_api.models import Movie

with open('./imdb_json.json') as f:
  data = json.load(f)
  for item in data:
    print(item['name'])
    genre = ','.join(item['genre'])
    search_string = str(item['99popularity']) + ' '+ item['director']+ ' ' + str(item['imdb_score'])+ ' '  + item['name']+ ' ' + ' '.join(item['genre'])
    movie = Movie(_99popularity=item['99popularity'], genre=genre, director=item['director'], imdb_score=item['imdb_score'], name=item['name'], search_string=search_string, search_count=0)
    movie.save()

# Output: {'name': 'Bob', 'languages': ['English', 'Fench']}
# print(data)
