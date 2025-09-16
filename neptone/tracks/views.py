from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponseForbidden
from .models import Track
from .forms import TrackForm


@login_required
def my_tracks(request):
    qs = Track.objects.filter(owner=request.user)
    return render(request, "tracks/my_tracks.html", {"tracks": qs})


@login_required
def upload_track(request):
    if request.method == "POST":
        form = TrackForm(request.POST, request.FILES)
        if form.is_valid():
            track = form.save(commit=False)
            track.owner = request.user
            track.save()
            return redirect("my_tracks")
    else:
        form = TrackForm()
    return render(request, "tracks/upload.html", {"form": form})


def track_detail(request, pk):
    track = get_object_or_404(Track, pk=pk)
    if not track.is_public and (not request.user.is_authenticated or request.user != track.owner):
        return HttpResponseForbidden("This track is private.")
    return render(request, "tracks/detail.html", {"track": track})


@login_required
def delete_track(request, pk):
    track = get_object_or_404(Track, pk=pk)
    if track.owner != request.user:
        return HttpResponseForbidden()
    if request.method == "POST":
        track.delete()
        return redirect("my_tracks")
    return render(request, "tracks/delete_confirm.html", {"track": track})
