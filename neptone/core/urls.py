from django.urls import path
from .views import home
from . import views
from users.views import artist_profile

urlpatterns = [
    path("", home, name="home"),
    path("u/<str:username>/", artist_profile, name="artist_profile"),
]
