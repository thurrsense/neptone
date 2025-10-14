from django.shortcuts import redirect
from django.urls import reverse
from social_core.pipeline.partial import partial
from urllib.parse import urlencode

@partial
def require_2fa(strategy, backend, user=None, *args, **kwargs):
    """
    Если у пользователя включена 2FA — останавливаем pipeline,
    просим ввести OTP и потом возобновляем pipeline.
    """
    if not user:
        return

    if not getattr(user, 'otp_enabled', False):
        return  # 2FA выключена — продолжаем как обычно

    # Если уже прошли 2FA — чистим флаги и пропускаем дальше
    if strategy.session_get('social_2fa_ok'):
        strategy.session_pop('social_2fa_ok')
        strategy.session_pop('pre_2fa_user_id', None)
        strategy.session_pop('partial_backend', None)
        return

    # Ещё не проходили — ставим паузу и отправляем на ввод OTP
    strategy.session_set('pre_2fa_user_id', user.pk)
    strategy.session_set('partial_backend', backend.name)
    return redirect(reverse('social_twofactor_verify'))


def save_status_to_session(strategy, pipeline_index=None, current_partial=None, *args, **kwargs):
    """
    Минимальный аналог social_core.pipeline.partial.save_status_to_session
    Сохраняет partial в сессию и ничего не рендерит.
    """
    if current_partial:  # объект PartialPipeline
        # токен нужен, чтобы потом возобновить пайплайн
        strategy.session_set('partial_token', current_partial.token)