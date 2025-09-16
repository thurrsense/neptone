from django.db import models
from django.conf import settings


def track_upload_to(instance, filename):
    return f"tracks/{instance.owner_id}/{filename}"


class Track(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL,
                              on_delete=models.CASCADE, related_name="tracks")
    title = models.CharField(max_length=200)
    audio = models.FileField(upload_to=track_upload_to)
    cover = models.ImageField(upload_to="covers/", blank=True, null=True)
    is_public = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.title} — {self.owner}"
