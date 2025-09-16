from django.urls import path
from django.contrib.auth.views import (
    LoginView, LogoutView,
    PasswordResetView, PasswordResetDoneView,
    PasswordResetConfirmView, PasswordResetCompleteView,
)
from .views import TOTPSetupView, TOTPVerifyView, TOTPLoginView
from .views import (
    register,
    settings_profile,
    artist_profile,
    my_profile_redirect,
    deactivate_sessions,
    delete_account,
    delete_my_track,
    follow_toggle,
)

urlpatterns = [
    path("login/",  LoginView.as_view(template_name="users/login.html"), name="login"),
    path("logout/", LogoutView.as_view(next_page="home"), name="logout"),
    path("register/", register, name="register"),

    # Мой профиль -> редирект на публичную страницу себя
    path("profile/", my_profile_redirect, name="my_profile"),

    # Настройки
    path("settings/", settings_profile, name="settings_profile"),
    path("settings/deactivate-sessions/",
         deactivate_sessions, name="deactivate_sessions"),
    path("settings/delete/", delete_account, name="delete_account"),

    # Удаление своего трека
    path("tracks/<int:pk>/delete/", delete_my_track, name="delete_my_track"),
    # Password reset (оставь, если реально используешь все шаблоны)
    path("password_reset/", PasswordResetView.as_view(
        template_name="users/password_reset_form.html"), name="password_reset"),
    path("password_reset/done/", PasswordResetDoneView.as_view(
        template_name="users/password_reset_done.html"), name="password_reset_done"),
    path("reset/<uidb64>/<token>/", PasswordResetConfirmView.as_view(
        template_name="users/password_reset_confirm.html"), name="password_reset_confirm"),
    path("reset/done/", PasswordResetCompleteView.as_view(
        template_name="users/password_reset_complete.html"), name="password_reset_complete"),

    path("u/<str:username>/follow-toggle/",
         follow_toggle, name="follow_toggle"),

    # API endpoints (2FA/JWT)
    path("api/2fa/setup/",  TOTPSetupView.as_view(),  name="2fa_setup"),
    path("api/2fa/verify/", TOTPVerifyView.as_view(), name="2fa_verify"),
    path("api/2fa/login/",  TOTPLoginView.as_view(),  name="2fa_login"),
]
