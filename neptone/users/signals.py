# users/signals.py
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver

@receiver(user_logged_in)
def mark_otp_needed(sender, user, request, **kwargs):
    if getattr(user, "otp_enabled", False):
        request.session["otp_ok"] = False
