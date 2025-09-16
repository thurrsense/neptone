from django.db.models import UniqueConstraint, Index
from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django_otp.plugins.otp_totp.models import TOTPDevice


class User(AbstractUser):
    bio = models.TextField(null=True, blank=True, editable=True)
    birth_date = models.DateField(null=True, blank=True, editable=True)
    otp_enabled = models.BooleanField(default=False)
    otp_verified = models.BooleanField(default=False)
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)

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

    @property
    def followers_count(self):
        return self.follower_relations.count()

    @property
    def following_count(self):
        return self.following_relations.count()

    @property
    def followers(self):
        return User.objects.filter(following_relations__following=self)

    @property
    def following(self):
        return User.objects.filter(follower_relations__follower=self)


class Follow(models.Model):
    follower = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="following_relations"
    )
    following = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="follower_relations"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "users_follow"
        constraints = [
            UniqueConstraint(fields=["follower", "following"],
                             name="uq_follow_follower_following"),
        ]
        indexes = [
            Index(fields=["follower"]),
            Index(fields=["following"]),
        ]

    def __str__(self):
        return f"{self.follower.username} → {self.following.username}"
