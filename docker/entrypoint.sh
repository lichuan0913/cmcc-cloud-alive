#!/bin/sh
set -e
# Ensure durable dirs exist on volume (X2 D6 HOME=/data → unified X8 root)
# Canonical data root: $HOME/.cmcc-cloud-alive (matches CLI core + WebUI).
# CMCC_DATA_DIR may override; if it already ends with .cmcc-cloud-alive use as-is.
_ROOT="${CMCC_DATA_DIR:-${HOME:-/data}/.cmcc-cloud-alive}"
case "$_ROOT" in
  */.cmcc-cloud-alive) : ;;
  *) _ROOT="${_ROOT}/.cmcc-cloud-alive" ;;
esac
mkdir -p "${_ROOT}/profiles" \
         "${_ROOT}/locks" \
         "${_ROOT}/run" \
         "${_ROOT}/jobs" \
         "${HOME:-/data}/logs" 2>/dev/null || true
# Compat: keep legacy /data/profiles readable; WebUI migrates into unified root.
mkdir -p "${HOME:-/data}/profiles" 2>/dev/null || true

if [ "$1" = "web" ] || [ "$1" = "webui" ]; then
  shift || true
  HOST="${CMCC_WEBUI_HOST:-0.0.0.0}"
  PORT="${CMCC_WEBUI_PORT:-8080}"
  export PYTHONPATH="/app${PYTHONPATH:+:$PYTHONPATH}"
  # Prefer real app when J3 lands; fall back to image placeholder
  if python -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('cmcc_cloud_alive.webui.app') else 1)" 2>/dev/null; then
    exec uvicorn cmcc_cloud_alive.webui.app:app --host "$HOST" --port "$PORT"
  fi
  exec uvicorn docker.webui_placeholder:app --host "$HOST" --port "$PORT"
fi

if [ "$1" = "cmcc-cloud-alive" ]; then
  shift
  exec cmcc-cloud-alive "$@"
fi

exec "$@"
