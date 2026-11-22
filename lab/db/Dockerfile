FROM postgres:16-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

# init.sql runs automatically on first start (empty data dir).
COPY init.sql /docker-entrypoint-initdb.d/10-init.sql
