#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${ROOT}/research/zime-probe.c"
CPP_INTERPOSE="${ZIME_PROBE_CPP_INTERPOSE:-0}"
TRANSPORT_INTERPOSE="${ZIME_PROBE_TRANSPORT_INTERPOSE:-0}"

case "${CPP_INTERPOSE}" in
  1|true|TRUE|yes|YES|on|ON)
    CPP_INTERPOSE=1
    ;;
  *)
    CPP_INTERPOSE=0
    ;;
esac

case "${TRANSPORT_INTERPOSE}" in
  1|true|TRUE|yes|YES|on|ON) TRANSPORT_INTERPOSE=1 ;;
  *) TRANSPORT_INTERPOSE=0 ;;
esac

if [[ "${CPP_INTERPOSE}" == "1" ]]; then
  TRANSPORT_INTERPOSE=1
  DEFAULT_OUT="${ROOT}/build/research/zime-probe-cpp.so"
elif [[ "${TRANSPORT_INTERPOSE}" == "1" ]]; then
  DEFAULT_OUT="${ROOT}/build/research/zime-probe-transport.so"
else
  DEFAULT_OUT="${ROOT}/build/research/zime-probe.so"
fi

OUT="${ZIME_PROBE_OUT:-${DEFAULT_OUT}}"

mkdir -p "$(dirname "${OUT}")"
gcc -shared -fPIC -O2 -Wall -Wextra \
  -DZIME_PROBE_ENABLE_CPP_INTERPOSE="${CPP_INTERPOSE}" \
  -DZIME_PROBE_ENABLE_TRANSPORT_INTERPOSE="${TRANSPORT_INTERPOSE}" \
  -o "${OUT}" "${SRC}" -ldl -pthread
echo "${OUT}"
