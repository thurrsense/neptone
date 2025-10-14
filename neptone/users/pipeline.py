from django.shortcuts import redirect
from django.urls import reverse
from social_core.pipeline.partial import partial
from urllib.parse import urlencode


def require_2fa(strategy, backend, user=None, *args, **kwargs):
    """
    Если у пользователя включена 2FA — ручной partial без @partial.
    ВАЖНО: не передавать **kwargs в partial_save, чтобы не утащить backend как строку.
    """
    if not user or not getattr(user, 'otp_enabled', False):
        return

    # Уже прошли 2FA ранее — подчистить флаги и продолжить пайплайн
    if strategy.session_get('social_2fa_ok'):
        strategy.session_pop('social_2fa_ok', None)
        strategy.session_pop('pre_2fa_user_id', None)
        strategy.session_pop('partial_backend', None)
        strategy.session_pop('partial_token', None)
        return

    # На каком шаге сейчас? Возобновлять нужно со следующего шага
    current_index = kwargs.get('pipeline_index', 0)
    next_index = current_index + 1

    # ВАЖНО: не передавать *args/**kwargs, чтобы 'backend' из kwargs не сохранился!
    partial = strategy.partial_save(backend, next_index)

    # Положим, что нам нужно для страницы 2FA
    strategy.session_set('partial_token', partial.token)
    strategy.session_set('pre_2fa_user_id', user.pk)
    strategy.session_set('partial_backend', backend.name)

    return strategy.redirect(reverse('social_twofactor_verify'))


def save_status_to_session(strategy, pipeline_index=None, *args, **kwargs):
    """
    Совместимый с social-core шаг: сохраняет partial в сессию.
    """
    data = strategy.to_session(pipeline_index, *args, **kwargs)
    strategy.session_set('partial_pipeline', data)

    if data and 'token' in data:
        strategy.session_set('partial_token', data['token'])