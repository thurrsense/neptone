FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore


# системные пакеты (ffmpeg пригодится для "кил-фичи")
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl ffmpeg netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR ./app

# зависимости
COPY requirements.txt /app/
RUN pip install --upgrade pip && pip install -r requirements.txt

# проект
COPY ./neptone /app/neptone

# entrypoint
COPY docker/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

ENV DJANGO_SETTINGS_MODULE=neptone.settings \
    PYTHONPATH=/app

# gunicorn по умолчанию; в dev будем переопределять команду
CMD ["/entrypoint.sh"]
