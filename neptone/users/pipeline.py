from django.shortcuts import redirect
from django.urls import reverse
from social_core.pipeline.partial import partial
from urllib.parse import urlencode


def require_2fa(strategy, backend, user=None, *args, **kwargs):
    if not user or not getattr(user, 'otp_enabled', False):
        return

    # если уже прошли 2FA — продолжаем
    if strategy.session_get('social_2fa_ok'):
        strategy.session_pop('social_2fa_ok', None)
        strategy.session_pop('pre_2fa_user_id', None)
        strategy.session_pop('partial_backend', None)
        strategy.session_pop('partial_token', None)
        return

    current_index = kwargs.get('pipeline_index', 0)
    next_index = current_index + 1

    # ВАЖНО: 1) первым аргументом — ИМЯ бэкенда (str)
    #        2) вторым — индекс следующего шага (int)
    #        3) НИЧЕГО не передавать в *args/**kwargs, чтобы не унести backend в kwargs!
    partial = strategy.partial_save(backend.name, next_index)

    # сохраним что нужно для формы 2FA
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