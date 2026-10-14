FROM python:3.14-slim

# Slim base image: fewer packages, smaller attack surface.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

# Dependencies first, so Docker reuses this layer when only the code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Run as an ordinary user: a bug in the app does not get root in the container.
RUN useradd --create-home appuser
USER appuser

# Cloud Run chooses the port and passes it in $PORT.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
