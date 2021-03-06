# Generated by Django 3.1.1 on 2020-09-27 07:40

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Movie',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('_99popularity', models.FloatField(default=0, null=True)),
                ('genre', models.CharField(blank=True, max_length=500, null=True)),
                ('director', models.CharField(blank=True, max_length=100, null=True)),
                ('imdb_score', models.FloatField(default=0, null=True)),
                ('name', models.CharField(max_length=100)),
                ('search_string', models.CharField(max_length=300)),
                ('search_count', models.IntegerField(db_index=True, default=0)),
            ],
        ),
    ]
