from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django_otp.plugins.otp_totp.models import TOTPDevice


class User(AbstractUser):
    bio = models.TextField(null=True, blank=True, editable=True)
    birth_date = models.DateField(null=True, blank=True, editable=True)
    otp_enabled = models.BooleanField(default=False)
    otp_verified = models.BooleanField(default=False)

    class Meta:
        db_table = 'users_user'

    def __str__(self):
        return self.username

    def get_totp_device(self):
        """Получить TOTP устройство пользователя"""
        try:
            return TOTPDevice.objects.get(user=self, confirmed=True)
        except TOTPDevice.DoesNotExist:
            return None
