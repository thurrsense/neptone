from django import forms
from django.contrib.auth.forms import UserChangeForm, UserCreationForm
from .models import User
from captcha.fields import CaptchaField


class RegistrationForm(UserCreationForm):
    """
    Регистрация с капчей.
    """
    captcha = CaptchaField(label="Введите символы с картинки")

    class Meta:
        model = User
        fields = [
            "username",
            "email",
            "bio",
            "birth_date",
            "password1",
            "password2",
            "captcha",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # делаем поля красивыми по умолчанию (Bootstrap)
        for name, field in self.fields.items():
            css = field.widget.attrs.get("class", "")
            field.widget.attrs["class"] = (css + " form-control").strip()

        # тип даты и плейсхолдеры
        self.fields["birth_date"].widget.attrs.update({"type": "date"})
        self.fields["username"].widget.attrs.update(
            {"placeholder": "Username"})
        self.fields["email"].widget.attrs.update({"placeholder": "Email"})
        self.fields["password1"].widget.attrs.update(
            {"placeholder": "Password"})
        self.fields["password2"].widget.attrs.update(
            {"placeholder": "Confirm password"})


class ProfileForm(UserChangeForm):
    """
    Редактирование профиля, включая аватар. Поле password скрываем.
    """
    password = None  # убираем отображение password hash

    class Meta:
        model = User
        fields = ["username", "email", "bio", "birth_date",
                  "first_name", "last_name", "avatar"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name, field in self.fields.items():
            css = field.widget.attrs.get("class", "")
            field.widget.attrs["class"] = (css + " form-control").strip()
        # для файла — тот же класс ок
        self.fields["avatar"].widget.attrs["class"] = "form-control"
        # дата
        self.fields["birth_date"].widget.attrs.update({"type": "date"})

    def clean_avatar(self):
        f = self.cleaned_data.get("avatar")
        if not f:
            return f
        # базовая проверка размера, можно подправить лимит
        if f.size > 5 * 1024 * 1024:
            raise forms.ValidationError("Аватар не должен превышать 5 МБ.")
        return f
