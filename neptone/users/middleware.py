# users/middleware.py
from django.shortcuts import redirect
from django.urls import resolve, reverse, Resolver404

ALLOW_PREFIXES = (
    "/users/login/",
    "/users/oauth/",          # social_django (begin/complete)
    "/users/password_reset/",
    "/static/", "/media/",
)

ALLOW_NAMES = {
    "login", "logout",
    "twofactor_verify",       # ваш старый flow для пароля
    "otp_verify_gate",        # наш общий гейт
    "password_reset", "password_reset_done",
    "password_reset_confirm", "password_reset_complete",
    "social_error",
}

def _otp_gate_url():
    # Пытаемся учесть случай с namespace
    try:
        return reverse("otp_verify_gate")
    except Exception:
        try:
            return reverse("users:otp_verify_gate")
        except Exception:
            return "/users/login/otp/"

class OTPRequiredMiddleware:
    """
    Если пользователь аутентифицирован и у него включена 2FA,
    но ещё не подтверждена текущая сессия (session['otp_ok'] != True),
    то пускаем только на страницу ввода кода.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        u = getattr(request, "user", None)
        if getattr(u, "is_authenticated", False) and getattr(u, "otp_enabled", False):
            if not request.session.get("otp_ok", False):
                path = request.path

                # белый список по префиксам
                if any(path.startswith(p) for p in ALLOW_PREFIXES):
                    return self.get_response(request)

                # белый список по именам
                try:
                    if resolve(path).url_name in ALLOW_NAMES:
                        return self.get_response(request)
                except Resolver404:
                    pass

                request.session["post_login_next"] = request.get_full_path()
                return redirect(_otp_gate_url())

        return self.get_response(request)