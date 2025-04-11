from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    bio = models.TextField(null=True, blank=True, editable=True)
    birth_date = models.DateField(null=True, blank=True, editable=True)
    
    class Meta:
        db_table = 'users_user'

    def __str__(self):
        return self.username
