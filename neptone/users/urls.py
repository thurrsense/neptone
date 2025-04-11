from django.urls import path
from .views import register, edit_profile

urlpatterns = [
    path('register/', register, name='register'),
    path('profile/edit/', edit_profile, name='edit_profile'),
]
