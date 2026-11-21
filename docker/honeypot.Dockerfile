FROM python:3.11-slim

WORKDIR /app

# Install system dependencies if needed (e.g. gcc for psycopg2 if building from source, but psycopg2-binary is used)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared models and honeypot application
COPY shared/ shared/
COPY honeypot/ honeypot/

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV PORT=5000

EXPOSE 5000

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 2 --timeout 30 honeypot.app:app"]
