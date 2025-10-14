from django.shortcuts import redirect
from django.urls import reverse
from social_core.pipeline.partial import partial
from urllib.parse import urlencode

@partial
def require_2fa(strategy, backend, user=None, *args, **kwargs):
    if not user or not getattr(user, 'otp_enabled', False):
        return

    # уже прошли 2FA — просто продолжаем
    if strategy.session_get('social_2fa_ok'):
        strategy.session_pop('social_2fa_ok', None)
        strategy.session_pop('pre_2fa_user_id', None)
        strategy.session_pop('partial_backend', None)
        return

    # ставим на паузу и уводим на ввод кода
    strategy.session_set('pre_2fa_user_id', user.pk)
    strategy.session_set('partial_backend', backend.name)

    url = reverse('social_twofactor_verify')  # БЕЗ ручной сборки partial_token!
    return strategy.redirect(url)             # ← ключевой момент


def save_status_to_session(strategy, pipeline_index=None, *args, **kwargs):
    """
    Совместимый с social-core шаг: сохраняет partial в сессию.
    """
    data = strategy.to_session(pipeline_index, *args, **kwargs)
    strategy.session_set('partial_pipeline', data)

    if data and 'token' in data:
        strategy.session_set('partial_token', data['token'])