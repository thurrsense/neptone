from django.urls import path
from .views import register, edit_profile, RegisterAPIView, LoginAPIView
from .views import TOTPSetupView, TOTPVerifyView, TOTPLoginView

urlpatterns = [
    # HTML endpoints
    path('register/', register, name='register'),
    path('profile/edit/', edit_profile, name='edit_profile'),
    
    # API endpoints
    path('api/register/', RegisterAPIView.as_view(), name='api_register'),
    path('api/login/', LoginAPIView.as_view(), name='api_login'),
    path('api/2fa/setup/', TOTPSetupView.as_view(), name='2fa_setup'),
    path('api/2fa/verify/', TOTPVerifyView.as_view(), name='2fa_verify'),
    path('api/2fa/login/', TOTPLoginView.as_view(), name='2fa_login'),
]