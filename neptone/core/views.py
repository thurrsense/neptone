from django.shortcuts import render


def home(request):
    return render(request, 'core/home.html')


def handle_404(request, exception):
    return render(request, "404.html", status=404)


def handle_500(request):
    return render(request, "500.html", status=500)
