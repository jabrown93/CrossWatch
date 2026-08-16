# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

# =====================================================================
# Builder: the DHI -dev variant has a shell, apk and build tools, and
# runs as root, so we use it only to install dependencies. Nothing from
# this stage ships except the venv and a few data files copied below.
# =====================================================================
FROM dhi.io/python:3.14.7-alpine3.24-dev@sha256:38fe0b5eb1b87c1b73303ea8570f3bf85b1be189ff7b4e6998ff991db43aad4e AS builder

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
FROM dhi.io/python:3.14.7-alpine3.24@sha256:b395f3c5fae824a8a024dbc6f446f1e307bbf56e8aed7df5c9e284b5ce3ea963

# Section 11 of the CrossWatch Source Available License forbids implying that a
# modified version is endorsed by the Copyright Holder, so the description says
# up front that this is an unofficial fork. The licenses label is the SPDX-style
# hint scanners read; NOTICE (copied in with the app below) carries the
# Section 6.3 statement of material modifications.
LABEL org.opencontainers.image.title="CrossWatch (unofficial fork)" \
      org.opencontainers.image.description="Unofficial fork of cenodude/CrossWatch. One brain for all your media syncs, a single place to configure everything. Not endorsed by the upstream Copyright Holder." \
      org.opencontainers.image.source="https://github.com/jabrown93/CrossWatch" \
      org.opencontainers.image.licenses="LicenseRef-CrossWatch-Source-Available-1.0"

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
# LICENSE and NOTICE ride along deliberately: License Section 6 requires every
# distributed copy to carry the copyright notice, the full license text, and a
# clear notice of material modifications. Do not add either to .dockerignore.
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
