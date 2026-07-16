# cmcc-cloud-alive Docker image (J1 / J1FIX)
# Build from repo root:
#   docker build -f docker/Dockerfile -t cmcc-cloud-alive:local .
#   docker compose -f docker/docker-compose.yml up -d --build
#
# Offline install: pre-vendored wheels in docker/wheels (cp311 manylinux).
# No network required at `pip install` time (J1FIX).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/data \
    CMCC_ALIVE_HOME=/data \
    CMCC_WEBUI_HOST=0.0.0.0 \
    CMCC_WEBUI_PORT=8080

# Non-root runtime user (uid 10001); compose may override to host uid
RUN groupadd --system --gid 10001 cmcc \
    && useradd --system --uid 10001 --gid cmcc --home-dir /data --shell /usr/sbin/nologin cmcc \
    && mkdir -p /data /app \
    && chown -R cmcc:cmcc /data

WORKDIR /app

# Offline wheels (pre-downloaded on build host for py3.11/manylinux) + project
COPY docker/wheels /tmp/wheels
COPY pyproject.toml README.md ./
COPY cmcc_cloud_alive ./cmcc_cloud_alive
COPY docker/__init__.py docker/entrypoint.sh docker/webui_placeholder.py ./docker/

# Non-editable install (J1FIX option C): avoids hatchling/editables extras.
# setuptools backend builds from local tree using only --find-links wheels.
RUN pip install --no-index --find-links=/tmp/wheels --upgrade pip setuptools wheel \
    && pip install --no-index --find-links=/tmp/wheels ".[web]" \
    && chmod +x /app/docker/entrypoint.sh \
    && rm -rf /tmp/wheels \
    && chown -R cmcc:cmcc /app

USER cmcc
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["webui"]
