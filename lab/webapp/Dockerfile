FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN pip install --no-cache-dir flask psycopg2-binary

COPY app/ /app/app/
RUN mkdir -p /app/docs && echo "ACME portal readme. Internal use only." > /app/docs/readme.txt

EXPOSE 5000
# entrypoint is overridden by compose to set the gateway route first
CMD ["python", "app/app.py"]
