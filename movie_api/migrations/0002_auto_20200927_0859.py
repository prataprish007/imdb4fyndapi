# Generated by Django 3.1.1 on 2020-09-27 08:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('movie_api', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='movie',
            name='id',
            field=models.AutoField(primary_key=True, serialize=False),
        ),
    ]