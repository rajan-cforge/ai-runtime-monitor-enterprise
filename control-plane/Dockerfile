FROM python:3.12-slim

WORKDIR /app

# Install system deps for psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cp/ cp/
COPY migrations/ migrations/
COPY fleet_dashboard.html .

EXPOSE 9090

CMD ["uvicorn", "cp.app:app", "--host", "0.0.0.0", "--port", "9090"]
