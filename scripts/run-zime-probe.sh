#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${ZIME_PROBE_MODE:-low}"
CPP_INTERPOSE="${ZIME_PROBE_CPP_INTERPOSE:-0}"
TRANSPORT_INTERPOSE="${ZIME_PROBE_TRANSPORT_INTERPOSE:-0}"
case "${MODE}" in
  low)
    : "${ZIME_PROBE_CAPTURE_TRANSPORT:=0}"
    : "${ZIME_PROBE_WRAP_CALLBACKS:=0}"
    ;;
  transport)
    : "${ZIME_PROBE_CAPTURE_TRANSPORT:=1}"
    : "${ZIME_PROBE_WRAP_CALLBACKS:=0}"
    TRANSPORT_INTERPOSE=1
    ;;
  auth)
    : "${ZIME_PROBE_CAPTURE_TRANSPORT:=1}"
    : "${ZIME_PROBE_WRAP_CALLBACKS:=0}"
    : "${ZIME_PROBE_AUTH_FOCUS:=1}"
    : "${ZIME_PROBE_MAX_BYTES:=256}"
    TRANSPORT_INTERPOSE=1
    ;;
  callback)
    : "${ZIME_PROBE_CAPTURE_TRANSPORT:=0}"
    : "${ZIME_PROBE_WRAP_CALLBACKS:=1}"
    ;;
  full)
    : "${ZIME_PROBE_CAPTURE_TRANSPORT:=1}"
    : "${ZIME_PROBE_WRAP_CALLBACKS:=1}"
    TRANSPORT_INTERPOSE=1
    ;;
  cpp)
    : "${ZIME_PROBE_CAPTURE_TRANSPORT:=1}"
    : "${ZIME_PROBE_WRAP_CALLBACKS:=1}"
    TRANSPORT_INTERPOSE=1
    CPP_INTERPOSE=1
    ;;
  *)
    echo "Unknown ZIME_PROBE_MODE=${MODE}; use low, transport, auth, callback, full, or cpp" >&2
    exit 2
    ;;
esac

case "${CPP_INTERPOSE}" in
  1|true|TRUE|yes|YES|on|ON) CPP_INTERPOSE=1 ;;
  *) CPP_INTERPOSE=0 ;;
esac

case "${TRANSPORT_INTERPOSE}" in
  1|true|TRUE|yes|YES|on|ON) TRANSPORT_INTERPOSE=1 ;;
  *) TRANSPORT_INTERPOSE=0 ;;
esac

case "${ZIME_PROBE_CAPTURE_TRANSPORT}" in
  1|true|TRUE|yes|YES|on|ON) TRANSPORT_INTERPOSE=1 ;;
esac

if [[ "${CPP_INTERPOSE}" == "1" ]]; then
  TRANSPORT_INTERPOSE=1
fi

export ZIME_PROBE_CPP_INTERPOSE="${CPP_INTERPOSE}"
export ZIME_PROBE_TRANSPORT_INTERPOSE="${TRANSPORT_INTERPOSE}"
if [[ "${CPP_INTERPOSE}" == "1" ]]; then
  SO="${ROOT}/build/research/zime-probe-cpp.so"
elif [[ "${TRANSPORT_INTERPOSE}" == "1" ]]; then
  SO="${ROOT}/build/research/zime-probe-transport.so"
else
  SO="${ROOT}/build/research/zime-probe.so"
fi
LOG="${ZIME_PROBE_LOG:-${ROOT}/reports/zime-probe-$(date +%Y%m%d-%H%M%S).jsonl}"

if [[ ! -f "${SO}" || "${ROOT}/research/zime-probe.c" -nt "${SO}" ]]; then
  "${ROOT}/scripts/build-zime-probe.sh" >/dev/null
fi

if [[ "$#" -eq 0 ]]; then
  cat >&2 <<EOF
Usage:
  ZIME_PROBE_LOG=reports/zime-official.jsonl scripts/run-zime-probe.sh -- <official-client-or-sdk-command>

Examples:
  scripts/run-zime-probe.sh -- /opt/yidongyun/client/opt/chuanyun-vdi-client/cmcc-jtydn
  ZIME_PROBE_MODE=transport scripts/run-zime-probe.sh -- /opt/yidongyun/client/opt/chuanyun-vdi-client/cmcc-jtydn
  ZIME_PROBE_MODE=auth scripts/run-zime-probe.sh -- /opt/yidongyun/client/opt/chuanyun-vdi-client/cmcc-jtydn
  ZIME_PROBE_MODE=callback scripts/run-zime-probe.sh -- /opt/yidongyun/client/opt/chuanyun-vdi-client/cmcc-jtydn
  scripts/run-zime-probe.sh -- /usr/local/bin/yidongyun-keepalive-legacy.sh

Modes:
  low        default; log ZIME C API/struct boundaries only
  transport  low + libc socket/read/write/send/recv and SSL buffers
  auth       transport-only focus for AUTH_HEAD_ACK cause analysis; captures KCP auth packet metadata and authFocus stack hints
  callback   low + ZIME callback table wrapping
  full       transport + callback
  cpp        full + compile-time C++ callback symbol interpose

The probe does not modify return values or inject keepalive behavior. Default
process filtering only logs uSmartView; override with ZIME_PROBE_PROCESS_FILTER.
EOF
  exit 2
fi

if [[ "${1:-}" == "--" ]]; then
  shift
fi

mkdir -p "$(dirname "${LOG}")"
export ZIME_PROBE_LOG="${LOG}"
export ZIME_PROBE_MAX_BYTES="${ZIME_PROBE_MAX_BYTES:-4096}"
export ZIME_PROBE_CAPTURE_TRANSPORT
export ZIME_PROBE_WRAP_CALLBACKS
export ZIME_PROBE_AUTH_FOCUS="${ZIME_PROBE_AUTH_FOCUS:-0}"
export ZIME_PROBE_PROCESS_FILTER="${ZIME_PROBE_PROCESS_FILTER:-uSmartView}"
export LD_PRELOAD="${SO}${LD_PRELOAD:+:${LD_PRELOAD}}"

echo "ZIME probe log: ${LOG}" >&2
echo "ZIME probe mode: ${MODE}; captureTransport=${ZIME_PROBE_CAPTURE_TRANSPORT}; wrapCallbacks=${ZIME_PROBE_WRAP_CALLBACKS}; authFocus=${ZIME_PROBE_AUTH_FOCUS}; transportInterpose=${ZIME_PROBE_TRANSPORT_INTERPOSE}; cppInterpose=${ZIME_PROBE_CPP_INTERPOSE}; processFilter=${ZIME_PROBE_PROCESS_FILTER}" >&2
exec "$@"
