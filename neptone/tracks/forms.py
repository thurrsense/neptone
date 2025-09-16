from django import forms
from .models import Track


class TrackForm(forms.ModelForm):
    class Meta:
        model = Track
        fields = ["title", "audio", "cover", "is_public"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for f in self.fields.values():
            css = f.widget.attrs.get("class", "")
            f.widget.attrs["class"] = (css + " form-control").strip()
        self.fields["audio"].widget.attrs["class"] = "form-control"
        self.fields["cover"].widget.attrs["class"] = "form-control"

    def clean_audio(self):
        f = self.cleaned_data.get("audio")
        if not f:
            return f
        if f.size > 50 * 1024 * 1024:  # 50MB
            raise forms.ValidationError(
                "Файл аудио не должен превышать 50 МБ.")
        # простая проверка по расширению/типу
        valid_mimes = {"audio/mpeg", "audio/mp3", "audio/wav",
                       "audio/x-wav", "audio/ogg", "audio/webm", "audio/flac"}
        if getattr(f, "content_type", "") and f.content_type not in valid_mimes:
            raise forms.ValidationError(
                "Поддерживаются mp3/wav/ogg/webm/flac.")
        return f
