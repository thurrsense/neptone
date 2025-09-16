"""
URL configuration for neptone project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from users.views import CaptchaGenerateView, CaptchaVerifyView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),

    # Капча
    path('captcha/', include('captcha.urls')),        # для форм
    path('api/captcha/generate/', CaptchaGenerateView.as_view(),
         name='captcha-generate'),
    path('api/captcha/verify/', CaptchaVerifyView.as_view(), name='captcha-verify'),
    # можно оставить для API, но можно и убрать
    path('api/captcha/', include('captcha.urls')),

    # Users
    path('users/', include('users.urls')),

    # JWT
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Djoser
    path('api/auth/', include('djoser.urls')),

    # Core
    path('', include('core.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL,
                          document_root=settings.MEDIA_ROOT)

handler404 = "core.views.handle_404"
handler500 = "core.views.handle_500"
