# VulnScan Pro — application image (shared by the web and celery-worker services).
FROM python:3.11-slim

# Keep Python lean and unbuffered so logs stream immediately.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application source (see .dockerignore for what is excluded — notably
# .env, venv/, instance/*.db, so no secrets or local DB end up in the image).
COPY . .

EXPOSE 5000

# Default command runs the web server (Flask + Socket.IO on eventlet). The worker
# service in docker-compose.yml overrides this to run the Celery worker instead.
CMD ["python", "backend_app.py"]
