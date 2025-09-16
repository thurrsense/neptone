from django.urls import path
from .views import my_tracks, upload_track, track_detail, delete_track

urlpatterns = [
    path("mine/", my_tracks, name="my_tracks"),
    path("upload/", upload_track, name="upload_track"),
    path("<int:pk>/", track_detail, name="track_detail"),
    path("<int:pk>/delete/", delete_track, name="delete_track"),
]
