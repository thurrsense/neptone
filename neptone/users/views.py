from .models import User, Follow
from django.views.decorators.http import require_POST
from django.shortcuts import get_object_or_404, redirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.renderers import JSONRenderer
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import login
from captcha.models import CaptchaStore
from captcha.helpers import captcha_image_url
from .serializers import RegisterSerializer, LoginSerializer, UserSerializer
from rest_framework.permissions import IsAuthenticated
from django_otp.plugins.otp_totp.models import TOTPDevice
from .serializers import TOTPSetupSerializer, TOTPVerifySerializer, TOTPLoginSerializer
from django.shortcuts import redirect, render, get_object_or_404
from django.contrib.auth.decorators import login_required
from .forms import RegistrationForm, ProfileForm
from django.contrib.auth import get_user_model
from tracks.models import Track
from tracks.forms import TrackForm
from django.core.paginator import Paginator
from django.contrib import messages
from django.http import HttpResponseBadRequest
from django.contrib.sessions.models import Session
from django.views import View
from django.views.decorators.csrf import csrf_protect
from django import forms
from django.contrib.auth import authenticate, login as auth_login
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.contrib.auth.forms import AuthenticationForm
from django.utils.decorators import method_decorator
from django.conf import settings


# --- Форма для ввода OTP (session flow) ---
class OTPForm(forms.Form):
    token = forms.CharField(max_length=6, min_length=6, widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "123456"}))


# --- Two-step login view (session-based) ---
class TwoFactorLoginView(View):
    """
    Принимает username+password. Если user.otp_enabled -> сохраняет временный user_id в сессии
    и редиректит на /login/verify/ ; иначе — логинит и редиректит как обычно.
    """
    template_name = "users/login.html"
    form_class = AuthenticationForm

    def get(self, request):
        form = self.form_class(request=request)
        return render(request, self.template_name, {"form": form})

    def post(self, request):
        form = self.form_class(request=request, data=request.POST)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form})

        # аутентифицированный user (но ещё не залогинен)
        user = form.get_user()

        if getattr(user, "otp_enabled", False):
            # сохраним ID в сессии и перенаправим на ввод токена
            request.session['pre_2fa_user_id'] = user.pk
            # не логиним пользователя пока не пройдёт OTP
            return redirect("twofactor_verify")
        else:
            # обычный логин
            auth_login(request, user)
            return redirect(settings.LOGIN_REDIRECT_URL)

# --- view для ввода токена после пароля ---
def twofactor_verify(request):
    user_id = request.session.get('pre_2fa_user_id')
    if not user_id:
        return redirect("login")

    user = get_object_or_404(User, pk=user_id)

    if request.method == "POST":
        form = OTPForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data['token']
            device = user.get_totp_device()
            if device and device.verify_token(token):
                # логиним (создаём сессию)
                auth_login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                # удаляем временные данные безопасно
                request.session.pop('pre_2fa_user_id', None)
                return redirect(settings.LOGIN_REDIRECT_URL)
            else:
                form.add_error("token", "Неверный токен 2FA")
    else:
        form = OTPForm()

    return render(request, "users/twofactor_verify.html", {"form": form, "user": user})


@csrf_protect
def social_twofactor_verify(request):
    # пробуем сначала из GET/POST, затем из сессии
    partial_token = (
        request.GET.get('partial_token')
        or request.POST.get('partial_token')
        or request.session.get('partial_token')
    )
    if not partial_token:
        return HttpResponseBadRequest("Missing partial_token")

    user_id = request.session.get('pre_2fa_user_id')
    backend = request.session.get('partial_backend')
    if not (user_id and backend):
        messages.error(request, "2FA-сессия истекла. Попробуйте ещё раз.")
        return redirect("login")

    user = get_object_or_404(User, pk=user_id)

    if request.method == "POST":
        token = (request.POST.get('token') or "").strip()
        device = user.get_totp_device()
        if device and device.verify_token(token):
            request.session['social_2fa_ok'] = True
            complete_url = reverse("social:complete", args=[backend])
            # можно подчистить partial_token из сессии
            request.session.pop('partial_token', None)
            return redirect(f"{complete_url}?partial_token={partial_token}")
        else:
            messages.error(request, "Неверный код 2FA")

    return render(request, "users/social_twofactor_verify.html", {
        "partial_token": partial_token,
        "backend": backend,
        "user_obj": user,
    })


# --- settings: страница настройки 2FA (генерация QR + ввод токена для подтверждения) ---
@method_decorator(login_required, name='dispatch')
class TOTPSetupPageView(View):
    """
    GET: генерирует устройство+QR (с помощью сериализатора TOTPSetupSerializer) и показывает QR.
    POST: принимает token и подтверждает устройство (подобно TOTPVerifySerializer) — сохраняет флаги.
    """
    template_name = "users/settings_2fa_setup.html"

    def get(self, request):
        # если уже включено — ничего генерировать не надо
        if request.user.otp_enabled:
            return redirect("settings_profile")

        from .serializers import TOTPSetupSerializer
        serializer = TOTPSetupSerializer(data={}, context={'request': request})
        serializer.is_valid(raise_exception=True)
        data = serializer.save()
        # data содержит qr_code (base64), secret, config_url
        request.session['pending_totp_device_name'] = data.get('secret_key')  # не обязательно, но можно хранить
        return render(request, self.template_name, {"qr": data.get('qr_code'), "config_url": data.get('config_url')})

    def post(self, request):
        token = request.POST.get('token')
        if not token:
            messages.error(request, "Введите токен из приложения.")
            return redirect("settings_2fa_setup")

        # ищем неподтверждённое устройство
        try:
            device = TOTPDevice.objects.get(user=request.user, confirmed=False)
        except TOTPDevice.DoesNotExist:
            messages.error(request, "Устройство не найдено. Попробуйте ещё раз.")
            return redirect("settings_2fa_setup")

        if device.verify_token(token):
            device.confirmed = True
            device.save()
            request.user.otp_enabled = True
            request.user.otp_verified = True
            request.user.save()
            messages.success(request, "2FA успешно включена.")
            return redirect("settings_profile")
        else:
            messages.error(request, "Неверный токен.")
            return redirect("settings_2fa_setup")
        
        
# --- отключение 2FA ---
@login_required
def TOTPDisableView(request):
    if request.method == "POST":
        # удаляем все TOTP устройства у пользователя и снимаем флаги
        TOTPDevice.objects.filter(user=request.user).delete()
        request.user.otp_enabled = False
        request.user.otp_verified = False
        request.user.save()
        messages.success(request, "2FA отключена.")
    return redirect("settings_profile")


class TOTPSetupView(APIView):
    """Настройка 2FA"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.otp_enabled:
            return Response({'error': '2FA уже включена'}, status=400)

        serializer = TOTPSetupSerializer(
            data={},
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        result = serializer.save()

        return Response(result)


class TOTPVerifyView(APIView):
    """Верификация 2FA"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = TOTPVerifySerializer(
            data=request.data,
            context={'request': request}
        )

        if serializer.is_valid():
            return Response({'success': '2FA успешно включена'})
        return Response(serializer.errors, status=400)


class TOTPLoginView(APIView):
    """Логин с 2FA"""

    def post(self, request):
        # Сначала обычная аутентификация
        auth_serializer = LoginSerializer(data=request.data)
        if not auth_serializer.is_valid():
            return Response(auth_serializer.errors, status=400)

        user = auth_serializer.validated_data['user']

        # Если у пользователя включена 2FA
        if user.otp_enabled:
            # Проверяем OTP токен
            otp_serializer = TOTPLoginSerializer(
                data=request.data,
                context={'request': request, 'user': user}
            )

            if otp_serializer.is_valid():
                # Генерируем JWT токены
                refresh = RefreshToken.for_user(user)
                return Response({
                    'user': UserSerializer(user).data,
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                })
            else:
                return Response(otp_serializer.errors, status=400)
        else:
            # Обычный логин без 2FA
            refresh = RefreshToken.for_user(user)
            return Response({
                'user': UserSerializer(user).data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })


class CaptchaGenerateView(APIView):
    renderer_classes = [JSONRenderer]

    def get(self, request):
        key = CaptchaStore.generate_key()
        image_url = captcha_image_url(key)

        # Для отладки - посмотрим что генерируется
        captcha = CaptchaStore.objects.get(hashkey=key)
        print(
            f"DEBUG: Generated captcha - Key: {key}, Response: {captcha.response}")

        return Response({
            'key': key,
            'image_url': request.build_absolute_uri(image_url),
            'debug_response': captcha.response  # Убрать в продакшене!
        })


class CaptchaVerifyView(APIView):  # ДОБАВЬТЕ ЭТОТ КЛАСС
    renderer_classes = [JSONRenderer]

    def post(self, request):
        key = request.data.get('key')
        response = request.data.get('response')

        try:
            captcha = CaptchaStore.objects.get(hashkey=key)
            print(
                f"DEBUG: Expected captcha: {captcha.response}, Got: {response}")

            # Сравниваем без учета регистра
            if captcha.response.lower() != response.lower():
                return Response({'valid': False}, status=status.HTTP_400_BAD_REQUEST)

            captcha.delete()
            return Response({'valid': True})

        except CaptchaStore.DoesNotExist:
            return Response({'error': 'Invalid key'}, status=status.HTTP_400_BAD_REQUEST)


class RegisterAPIView(APIView):
    renderer_classes = [JSONRenderer]

    def post(self, request):
        print(f"DEBUG: Request data: {request.data}")

        # Сначала проверяем капчу
        captcha_key = request.data.get('captcha_key')
        captcha_response = request.data.get('captcha_response')

        if not captcha_key or not captcha_response:
            return Response(
                {'error': 'Капча обязательна'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            captcha = CaptchaStore.objects.get(hashkey=captcha_key)
            if captcha.response.lower() != captcha_response.lower():
                return Response(
                    {'error': 'Неверная капча'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            captcha.delete()
        except CaptchaStore.DoesNotExist:
            return Response(
                {'error': 'Неверный ключ капчи'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Теперь валидируем остальные данные
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            return Response({
                'user': UserSerializer(user).data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_201_CREATED)

        print(f"DEBUG: Validation errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(APIView):
    renderer_classes = [JSONRenderer]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            refresh = RefreshToken.for_user(user)

            # Опционально: логиним пользователя в сессии
            login(request, user)

            return Response({
                'user': UserSerializer(user).data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Старые view для совместимости


def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)           # залогиним сразу
            return redirect('my_profile')   # и ведём в профиль
    else:
        form = RegistrationForm()
    return render(request, 'users/register.html', {'form': form})


User = get_user_model()


def artist_profile(request, username):
    artist = get_object_or_404(User, username=username)
    tracks = getattr(artist, "track_set", None)
    tracks = tracks.all().order_by('-created_at') if tracks else []

    is_following = False
    if request.user.is_authenticated and request.user != artist:
        is_following = artist.pk in request.user.following.values_list(
            'pk', flat=True)

    return render(request, "users/artist_profile.html", {
        "artist": artist,
        "tracks": tracks,
        "is_following": is_following,
    })


@login_required
def my_profile_redirect(request):
    return redirect("artist_profile", username=request.user.username)


@login_required
def settings_profile(request):
    form = ProfileForm(instance=request.user)
    upload_form = TrackForm()

    if request.method == "POST":
        # Fallback: если кнопка не передалась (нажали Enter), используем hidden action
        is_profile_submit = (
            "submit_profile" in request.POST
            or request.POST.get("action") == "save_profile"
        )
        is_upload_submit = (
            "submit_upload" in request.POST
            or request.POST.get("action") == "upload_track"
        )

        if is_profile_submit:
            form = ProfileForm(request.POST, request.FILES, instance=request.user)
            if form.is_valid():
                form.save()
                messages.success(request, "Профиль обновлён.")
                return redirect("settings_profile")
            else:
                print("PROFILE FORM ERRORS:", form.errors)

        elif is_upload_submit:
            upload_form = TrackForm(request.POST, request.FILES)
            if upload_form.is_valid():
                t = upload_form.save(commit=False)
                t.owner = request.user
                t.save()
                messages.success(request, "Трек загружен.")
                return redirect("settings_profile")
            else:
                print("UPLOAD FORM ERRORS:", upload_form.errors)

    return render(request, "users/settings_profile.html", {
        "form": form,
        "upload_form": upload_form,
    })

@login_required
def deactivate_sessions(request):
    if request.method == "POST":
        current_key = request.session.session_key
        for s in Session.objects.all():
            if s.session_key != current_key:
                s.delete()
        messages.success(request, "Активные сессии деактивированы.")
    return redirect("settings_profile")


@login_required
def delete_account(request):
    if request.method == "POST":
        request.user.delete()
        return redirect("home")
    return redirect("settings_profile")


@login_required
def delete_my_track(request, pk):
    t = get_object_or_404(Track, pk=pk, owner=request.user)
    if request.method == "POST":
        t.delete()
        messages.success(request, "Трек удалён.")
    return redirect("settings_profile")


@require_POST
@login_required
def follow_toggle(request, username):
    target = get_object_or_404(User, username=username)
    if target == request.user:
        messages.info(request, "Нельзя подписаться на себя 🙂")
        return redirect("artist_profile", username=username)

    rel, created = Follow.objects.get_or_create(
        follower=request.user,
        following=target,
    )
    if created:
        messages.success(request, f"Вы подписались на {target.username}")
    else:
        rel.delete()
        messages.info(request, f"Вы отписались от {target.username}")
    return redirect("artist_profile", username=username)
