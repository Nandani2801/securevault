FROM python:3.11-slim-bookworm AS build

WORKDIR /opt/CTFd

# Install build dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
        git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

# Copy entire repo (IMPORTANT)
COPY . /opt/CTFd

# Move into actual app directory
WORKDIR /opt/CTFd/CTFd

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt \
    && for d in plugins/*; do \
        if [ -f "$d/requirements.txt" ]; then \
            pip install --no-cache-dir -r "$d/requirements.txt";\
        fi; \
    done;


# ---------------- RELEASE STAGE ----------------

FROM python:3.11-slim-bookworm AS release

WORKDIR /opt/CTFd

# Install runtime deps
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libffi8 \
        libssl3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy full repo (IMPORTANT FIX)
COPY --chown=1001:1001 . /opt/CTFd

# Set correct working directory
WORKDIR /opt/CTFd/CTFd

# Create user + permissions
RUN useradd \
    --no-log-init \
    --shell /bin/bash \
    -u 1001 \
    ctfd \
    && mkdir -p /var/log/CTFd /var/uploads \
    && chown -R 1001:1001 /var/log/CTFd /var/uploads /opt/CTFd \
    && chmod +x /opt/CTFd/docker-entrypoint.sh

# Copy virtual environment
COPY --chown=1001:1001 --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# 🔥 CRITICAL FIX
ENV FLASK_APP=CTFd

USER 1001

EXPOSE 8000

ENTRYPOINT ["/opt/CTFd/docker-entrypoint.sh"]
