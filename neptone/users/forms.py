from django import forms
from django.contrib.auth.forms import UserChangeForm, UserCreationForm
from .models import User
from captcha.fields import CaptchaField


class RegistrationForm(UserCreationForm):
    captcha = CaptchaField()

    class Meta:
        model = User
        fields = ['username', 'email', 'bio',
                  'birth_date', 'password1', 'password2']
        fields = ['username', 'email', 'bio', 'birth_date',
                  'password1', 'password2', 'captcha']


class ProfileForm(UserChangeForm):
    password = None

    class Meta:
        model = User
        fields = ['username', 'email', 'bio',
                  'birth_date', 'first_name', 'last_name']
