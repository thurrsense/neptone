from django.urls import reverse
from social_core.pipeline.partial import partial


@partial
def require_2fa(strategy, backend=None, user=None, **kwargs):
    """
    Если у пользователя включена 2FA, прерываем pipeline и шлём на ввод TOTP.
    После успешной верификации продолжаем.
    """

    # --- Диагностика: что именно приходит
    try:
        print("DBG require_2fa:",
              "backend_arg_type=", type(backend),
              "strategy_backend=", getattr(getattr(strategy, "backend", None), "name", None),
              "kwargs_backend=", kwargs.get("backend"),
              "user_id=", getattr(user, "id", None))
    except Exception as e:
        print("DBG require_2fa logging error:", e)

    # Если pipeline уже резюмится ПОСЛЕ нашeго partial (на всякий случай)
    if strategy.session_get("verified_2fa"):
        # очистим флаги и пустим дальше по pipeline
        strategy.session_pop("verified_2fa")
        strategy.session_pop("pre_2fa_user_id")
        return

    if not user:
        return  # новый/неассоциированный соц-пользователь

    if getattr(user, "otp_enabled", False):
        # Надёжно получаем имя бэкенда
        backend_name = getattr(getattr(strategy, "backend", None), "name", None)
        if not backend_name:
            backend_name = getattr(backend, "name", None) or str(kwargs.get("backend") or "")

        if not backend_name:
            backend_name = "yandex-oauth2"  # безопасный дефолт для вашего кейса

        # Ставим маркеры в сессию
        strategy.session_set("pre_2fa_user_id", user.pk)
        # @partial сам добавит ?partial_token=...
        url = reverse("twofactor_verify_oauth")
        return strategy.redirect(f"{url}?backend={backend_name}")