FROM python:3.11-slim

WORKDIR /app
ENV PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/trustee_monitor/requirements.txt
RUN pip install --no-cache-dir -r /app/trustee_monitor/requirements.txt

COPY . /app/trustee_monitor/

WORKDIR /app/trustee_monitor

CMD ["python", "main.py", "--daemon"]
