from django.urls import path
from django.contrib.auth.views import (
    LoginView, LogoutView,
    PasswordResetView, PasswordResetDoneView,
    PasswordResetConfirmView, PasswordResetCompleteView,
)
from .views import register, edit_profile, profile
from .views import TOTPSetupView, TOTPVerifyView, TOTPLoginView

urlpatterns = [
    # HTML endpoints
    path("login/",  LoginView.as_view(template_name="users/login.html"), name="login"),
    path("logout/", LogoutView.as_view(next_page="home"), name="logout"),

    path("register/", register, name="register"),
    path("profile/",  profile, name="profile"),
    path("profile/edit/", edit_profile, name="edit_profile"),

    # Password reset (оставь, если реально используешь все шаблоны)
    path("password_reset/", PasswordResetView.as_view(
        template_name="users/password_reset_form.html"), name="password_reset"),
    path("password_reset/done/", PasswordResetDoneView.as_view(
        template_name="users/password_reset_done.html"), name="password_reset_done"),
    path("reset/<uidb64>/<token>/", PasswordResetConfirmView.as_view(
        template_name="users/password_reset_confirm.html"), name="password_reset_confirm"),
    path("reset/done/", PasswordResetCompleteView.as_view(
        template_name="users/password_reset_complete.html"), name="password_reset_complete"),

    # API endpoints (2FA/JWT)
    path("api/2fa/setup/",  TOTPSetupView.as_view(),  name="2fa_setup"),
    path("api/2fa/verify/", TOTPVerifyView.as_view(), name="2fa_verify"),
    path("api/2fa/login/",  TOTPLoginView.as_view(),  name="2fa_login"),
]
