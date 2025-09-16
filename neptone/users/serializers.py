from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User
from captcha.models import CaptchaStore
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp import login as otp_login
import base64
import qrcode
import io


class TOTPSetupSerializer(serializers.Serializer):
    """Сериализатор для настройки TOTP"""

    def validate(self, attrs):
        user = self.context['request'].user
        if user.otp_enabled:
            raise serializers.ValidationError("2FA уже включена")
        return attrs

    def create(self, validated_data):
        user = self.context['request'].user

        # Удаляем старые устройства
        TOTPDevice.objects.filter(user=user).delete()

        # Создаем новое устройство
        device = TOTPDevice.objects.create(
            user=user,
            name=f"{user.username}'s Authenticator",
            confirmed=False
        )

        # Генерируем QR код
        config_url = device.config_url
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(config_url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()

        return {
            'secret_key': device.bin_key.hex(),
            'qr_code': f"data:image/png;base64,{qr_code_base64}",
            'config_url': config_url
        }


class TOTPVerifySerializer(serializers.Serializer):
    """Сериализатор для верификации TOTP"""
    token = serializers.CharField(max_length=6, min_length=6)

    def validate(self, attrs):
        user = self.context['request'].user
        token = attrs['token']

        try:
            device = TOTPDevice.objects.get(user=user, confirmed=False)
            if device.verify_token(token):
                device.confirmed = True
                device.save()
                user.otp_enabled = True
                user.otp_verified = True
                user.save()

                # Логиним пользователя с OTP
                otp_login(self.context['request'], device)

                return attrs
            else:
                raise serializers.ValidationError("Неверный токен")
        except TOTPDevice.DoesNotExist:
            raise serializers.ValidationError("Устройство не найдено")


class TOTPLoginSerializer(serializers.Serializer):
    """Сериализатор для входа с 2FA"""
    token = serializers.CharField(max_length=6, min_length=6)

    def validate(self, attrs):
        user = self.context['request'].user
        token = attrs['token']

        device = user.get_totp_device()
        if device and device.verify_token(token):
            otp_login(self.context['request'], device)
            return attrs
        else:
            raise serializers.ValidationError("Неверный токен 2FA")


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name',
                  'last_name', 'bio', 'birth_date']


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    captcha_key = serializers.CharField(write_only=True)
    captcha_response = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password',
                  'password_confirm', 'captcha_key', 'captcha_response']

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Пароли не совпадают")

        # Убираем проверку капчи здесь, так как она уже проверена отдельно
        # или будет проверена во view
        attrs.pop('captcha_key')
        attrs.pop('captcha_response')

        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()
    captcha_key = serializers.CharField(required=False)
    captcha_response = serializers.CharField(required=False)

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        user = authenticate(username=username, password=password)

        if not user:
            # Если аутентификация не удалась, требуем капчу
            if not attrs.get('captcha_key') or not attrs.get('captcha_response'):
                raise serializers.ValidationError(
                    "Требуется капча после неудачной попытки входа")

            # Проверяем капчу
            try:
                captcha = CaptchaStore.objects.get(
                    hashkey=attrs['captcha_key'])
                if captcha.response != attrs['captcha_response'].lower():
                    raise serializers.ValidationError("Неверная капча")
                captcha.delete()
            except CaptchaStore.DoesNotExist:
                raise serializers.ValidationError("Неверный ключ капчи")

            raise serializers.ValidationError("Неверные учетные данные")

        attrs['user'] = user
        return attrs
