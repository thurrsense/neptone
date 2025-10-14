from django.shortcuts import redirect
from django.urls import reverse
from social_core.pipeline.partial import partial
from urllib.parse import urlencode


def require_2fa(strategy, backend, user=None, *args, **kwargs):
    """
    Если у пользователя включена 2FA — вручную создаём partial-проход,
    сохраняем его token в сессию и уводим на страницу ввода OTP.
    """
    # если юзера ещё нет или 2FA выключена — просто продолжаем пайплайн
    if not user or not getattr(user, 'otp_enabled', False):
        return

    # уже прошёл OTP — чистим флаги и продолжаем
    if strategy.session_get('social_2fa_ok'):
        strategy.session_pop('social_2fa_ok', None)
        strategy.session_pop('pre_2fa_user_id', None)
        strategy.session_pop('partial_backend', None)
        strategy.session_pop('partial_token', None)
        return

    # создаём partial и получаем token
    # partial_save вернёт объект с полем .token
    partial = strategy.partial_save(backend, 'require_2fa', *args, **kwargs)
    strategy.session_set('partial_token', partial.token)
    strategy.session_set('pre_2fa_user_id', user.pk)
    strategy.session_set('partial_backend', backend.name)

    # редиректим на нашу форму 2FA
    url = reverse('social_twofactor_verify')
    return strategy.redirect(url)


def save_status_to_session(strategy, pipeline_index=None, *args, **kwargs):
    """
    Совместимый с social-core шаг: сохраняет partial в сессию.
    """
    data = strategy.to_session(pipeline_index, *args, **kwargs)
    strategy.session_set('partial_pipeline', data)

    if data and 'token' in data:
        strategy.session_set('partial_token', data['token'])