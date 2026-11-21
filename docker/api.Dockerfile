FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared code, pipeline worker, AI client, and API
COPY shared/ shared/
COPY pipeline/ pipeline/
COPY ai/ ai/
COPY api/ api/

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV PORT=5001
ENV RUN_WORKER=true

EXPOSE 5001

# Single worker with 4 threads ensures exactly 1 background pipeline worker loop
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5001} --workers 1 --threads 4 --timeout 30 api.app:app"]
