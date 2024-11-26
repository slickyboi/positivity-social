web: gunicorn app_simple:app
worker: celery -A app.celery worker --loglevel=info
