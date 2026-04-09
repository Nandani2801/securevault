FROM python:3.11-slim-bookworm AS build

WORKDIR /opt/securevault

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
        libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

COPY securevault/requirements.txt /opt/securevault/requirements.txt
RUN pip install --no-cache-dir -r /opt/securevault/requirements.txt


# -------- RELEASE --------

FROM python:3.11-slim-bookworm AS release

WORKDIR /opt/securevault

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libffi8 \
        libssl3 \
        libpq5 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --chown=1001:1001 securevault/ /opt/securevault/
COPY --chown=1001:1001 docker-entrypoint.sh /opt/docker-entrypoint.sh

RUN useradd \
    --no-log-init \
    --shell /bin/bash \
    -u 1001 \
    securevault \
    && mkdir -p /var/log/securevault \
    && chown -R 1001:1001 /var/log/securevault /opt/securevault \
    && chmod +x /opt/docker-entrypoint.sh

COPY --chown=1001:1001 --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /opt/securevault
ENV PYTHONPATH=/opt/securevault
ENV FLASK_APP=run.py

USER 1001

EXPOSE 8000

ENTRYPOINT ["/opt/docker-entrypoint.sh"]
