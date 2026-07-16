# syntax=docker/dockerfile:1

# =====================================================================
# Builder: the DHI -dev variant has a shell, apk and build tools, and
# runs as root, so we use it only to install dependencies. Nothing from
# this stage ships except the venv and a few data files copied below.
# =====================================================================
FROM dhi.io/python:3.14.6-alpine3.24-dev AS builder

USER root

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Toolchain + libs as a fallback for any dependency that lacks a
# musllinux wheel (cryptography, pydantic-core, etc. normally ship them).
# tzdata/ca-certificates are harvested for the shell-less runtime stage.
RUN apk add --no-cache \
      build-base \
      libffi-dev \
      openssl-dev \
      cargo \
      rust \
      ca-certificates \
      tzdata

# Install Python deps into an isolated venv we can copy wholesale.
COPY requirements.txt /tmp/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m venv /opt/venv \
 && /opt/venv/bin/python -m pip install --upgrade pip setuptools wheel \
 && /opt/venv/bin/pip install -r /tmp/requirements.txt

# Empty skeleton used to materialize /config in the runtime stage with
# nonroot ownership (the runtime stage has no shell to chown).
RUN mkdir -p /config-skel

# =====================================================================
# Runtime: the hardened DHI image has no shell, no package manager, and
# runs as a fixed nonroot user. Only COPY/ENV/metadata are possible here
# -- no RUN. Dependencies and data are brought in from the builder.
# =====================================================================
FROM dhi.io/python:3.14.6-alpine3.24

LABEL org.opencontainers.image.description="One brain for all your media syncs A single place to configure everything."

# Baked in by CI (jabrown93/.github/docker-release.yml passes
# --build-arg APP_VERSION=v<version>); api/versionAPI.py reads this via
# os.getenv("APP_VERSION", ...) to report the real release instead of the
# hardcoded fallback. Defaults to "dev" for a local `docker build` without it.
ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH=/opt/venv/bin:$PATH \
    TZ=Europe/Amsterdam \
    RUNTIME_DIR=/config \
    WEB_HOST=0.0.0.0 \
    WEB_PORT=8787 \
    WEBINTERFACE=yes

WORKDIR /app

# Python dependencies (venv shares the same base CPython as this image).
COPY --from=builder /opt/venv /opt/venv

# Timezone database and CA bundle (no apk available in this stage).
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs /etc/ssl/certs

# Application code (.dockerignore keeps .git/__pycache__/.venv/tests out).
COPY . /app

# Writable runtime dir owned by the nonroot runtime user. Named volumes
# inherit this ownership on first use; bind mounts must be chowned on the
# host to the nonroot UID, since this image cannot remap UIDs at runtime.
COPY --chown=nonroot:nonroot --from=builder /config-skel/ /config/

HEALTHCHECK --interval=30s --timeout=5s --retries=5 \
  CMD ["python","-c","import os,socket,sys; s=socket.socket(); s.settimeout(2); p=int(os.environ.get('WEB_PORT','8787')); sys.exit(0 if s.connect_ex(('127.0.0.1',p))==0 else 1)"]

EXPOSE 8787
VOLUME ["/config"]

USER nonroot

# crosswatch ignores argv and always binds 0.0.0.0:8787; the bash
# entrypoint (dynamic PUID/PGID + privilege drop) is not possible on a
# shell-less, nonroot hardened image and has been removed.
ENTRYPOINT ["python", "-m", "crosswatch"]
