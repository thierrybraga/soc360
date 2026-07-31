FROM apache/airflow:2.10.5-python3.11

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libpq-dev curl && \
    rm -rf /var/lib/apt/lists/*

USER airflow
COPY requirements.txt /requirements.txt
RUN pip install --no-cache-dir -r /requirements.txt

# Health check para Airflow webserver
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
    CMD curl -sf http://localhost:8080/health || exit 1
