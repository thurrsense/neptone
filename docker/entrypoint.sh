#!/bin/sh
set -e

echo "Waiting for Postgres at ${DB_HOST}:${DB_PORT}..."
until nc -z -v -w30 "${DB_HOST}" "${DB_PORT}"; do
  echo "Postgres is unavailable - sleeping"
  sleep 1
done
echo "Postgres is up!"

# ---- locate manage.py ----
if [ -f /app/neptone/manage.py ]; then
  PROJ_DIR=/app/neptone
elif [ -f /app/neptone/neptone/manage.py ]; then
  PROJ_DIR=/app/neptone/neptone
else
  echo "manage.py not found under /app/neptone. Contents:"
  ls -la /app/neptone || true
  exit 1
fi
cd "$PROJ_DIR"

# sanity-check, чтобы дать понятную ошибку, если что
python manage.py check

# миграции и статика
python manage.py migrate --noinput
if [ "${DJANGO_COLLECTSTATIC:-1}" = "1" ]; then
  python manage.py collectstatic --noinput || true
fi

# запуск
if [ "${DJANGO_DEBUG}" = "1" ]; then
  exec python manage.py runserver 0.0.0.0:8000
else
  exec gunicorn neptone.wsgi:application --bind 0.0.0.0:8000 --workers 3 --threads 2 --timeout 60
fi
