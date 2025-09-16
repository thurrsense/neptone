from django.shortcuts import render
from django.core.paginator import Paginator
from tracks.models import Track


def home(request):
    # Гость видит лендинг
    if not request.user.is_authenticated:
        return render(request, "core/landing.html")

    # Авторизованный видит ленту публичных треков
    qs = Track.objects.filter(is_public=True).select_related(
        "owner").order_by("-created_at")
    page_obj = Paginator(qs, 10).get_page(request.GET.get("page"))
    return render(request, "core/home.html", {"page_obj": page_obj})


def handle_404(request, exception):
    return render(request, "404.html", status=404)


def handle_500(request):
    return render(request, "500.html", status=500)
