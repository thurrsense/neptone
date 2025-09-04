cd docker
sudo docker-compose up --build -d
sudo docker-compose logs -f web
# если нужно — создай суперпользователя:
sudo docker-compose exec web bash -lc "python manage.py createsuperuser"
