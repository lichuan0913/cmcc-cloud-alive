"""terminalprobe.soho.komect.com request helpers observed in the HAR."""

import base64
import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.request

from . import core
from .device_info import collect_device_info


PROBE_TERMINAL_URL = "https://terminalprobe.soho.komect.com"


def _json(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _pkcs7_pad(data):
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]


def _sub_bytes(state):
    for row in range(4):
        for col in range(4):
            state[row][col] = core.SBOX[state[row][col]]


def _mix_columns(state):
    for col in range(4):
        s0, s1, s2, s3 = [state[row][col] for row in range(4)]
        state[0][col] = core.gf_mul(s0, 2) ^ core.gf_mul(s1, 3) ^ s2 ^ s3
        state[1][col] = s0 ^ core.gf_mul(s1, 2) ^ core.gf_mul(s2, 3) ^ s3
        state[2][col] = s0 ^ s1 ^ core.gf_mul(s2, 2) ^ core.gf_mul(s3, 3)
        state[3][col] = core.gf_mul(s0, 3) ^ s1 ^ s2 ^ core.gf_mul(s3, 2)


def _aes_encrypt_block(block, round_keys, nr):
    state = [[block[row + 4 * col] for col in range(4)] for row in range(4)]
    core.add_round_key(state, round_keys[0])
    for round_index in range(1, nr):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        core.add_round_key(state, round_keys[round_index])
    _sub_bytes(state)
    _shift_rows(state)
    core.add_round_key(state, round_keys[nr])
    return bytes(state[row][col] for col in range(4) for row in range(4))


def aes_128_ecb_encrypt_base64(text, key):
    raw = _pkcs7_pad(str(text).encode("utf-8"))
    round_keys, nr = core.key_expansion(key)
    encrypted = b"".join(_aes_encrypt_block(raw[i:i + 16], round_keys, nr) for i in range(0, len(raw), 16))
    return base64.b64encode(encrypted).decode("ascii")


def probe_aes_key(state):
    cfg = core.client_config(state)
    device_id = core.profile_device_id(state, cfg).lower()
    seed = f"{cfg['app_secret_hex'].lower()}{device_id}"
    return hashlib.md5(seed.encode("utf-8")).hexdigest()[:16].lower().encode("utf-8")


def encrypt_phone_for_probe(state):
    phone = state.get("phone") or ""
    if not phone:
        return ""
    return aes_128_ecb_encrypt_base64(phone, probe_aes_key(state))


def _probe_headers(state, path, body):
    cfg = core.client_config(state)
    device_id = core.profile_device_id(state, cfg)
    header = {
        "X-SOHO-AppKey": cfg["app_key"],
        "X-SOHO-AppType": core.profile_app_type(state, cfg, device_id),
        "X-SOHO-ClientVersion": cfg["version"],
        "X-SOHO-DeviceId": device_id,
        "X-SOHO-RomVersion": core.profile_rom_version(state, cfg),
        "X-SOHO-SohoToken": state.get("sohoToken") or "",
        "X-SOHO-Timestamp": str(int(time.time() * 1000)),
        "X-SOHO-UserId": state.get("userId") or "",
        "X-SOHO-Uuid": core.rand_id(32),
        "X-SOHO-VersionNum": cfg["version_num"],
    }
    signing = f"POST&{path}&" + "&".join(f"{k}={v}" for k, v in header.items() if v)
    if body:
        signing += f"&body={_json(body)}"
    signature = core.hmac.new(bytes.fromhex(cfg["app_secret_hex"]), signing.encode("utf-8"), core.hashlib.sha256).hexdigest()
    result = {
        "Content-Type": "application/json",
        "User-Agent": core.profile_user_agent(state, cfg),
    }
    result.update(header)
    result["X-SOHO-Signature"] = signature
    return result


def probe_request(path, body, state_path=None, timeout=20):
    args = core.argparse.Namespace(state=state_path)
    state = core.load_state(args)
    payload = _json(body).encode("utf-8")
    req = urllib.request.Request(PROBE_TERMINAL_URL + "/sc/probe-terminal-portal" + path, data=payload, method="POST")
    for key, value in _probe_headers(state, path, body).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as res:
            raw = res.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8", errors="replace")
        raise core.CmccError(f"probe HTTP {err.code}: {raw[:300]}")
    except urllib.error.URLError as err:
        raise core.CmccError(f"probe network failed: {err.reason}")
    return json.loads(raw)


def performance_payload(vm_id, trace_id, spu_code, state_path=None):
    args = core.argparse.Namespace(state=state_path)
    state = core.load_state(args)
    info = collect_device_info()
    metrics = [
        {"name": "cpuUsage", "value": info["cpuUsageRate"].rstrip("%") or "0"},
        {"name": "memUsage", "value": info["memoryUsageRate"].rstrip("%") or "0"},
        {"name": "diskUsage", "value": info["storageUsageRate"].rstrip("%") or "0"},
    ]
    return {
        "labels": {
            "phone": encrypt_phone_for_probe(state),
            "vmId": vm_id,
            "traceId": trace_id,
            "spuCode": spu_code,
        },
        "monitorInfoList": [{
            "collectTime": int(time.time() * 1000),
            "metricList": metrics,
        }],
    }


def send_performance(vm_id, trace_id, spu_code, state_path=None):
    return probe_request("/performance/send/v1", performance_payload(vm_id, trace_id, spu_code, state_path), state_path)


def base_payload(state_path=None):
    args = core.argparse.Namespace(state=state_path)
    state = core.load_state(args)
    info = collect_device_info()
    return {
        "phone": encrypt_phone_for_probe(state),
        "firmwareEdition": f"{os.uname().sysname}-{os.uname().release}",
        "sdkVersion": [{"sc-cloud-pc": "unknown"}, {"zte-cloud-pc": "unknown"}],
        "cpuModel": info["cpuModel"],
        "cpuCore": os.cpu_count() or 1,
        "cpuClockSpeed": 0,
        "memSize": info["memory"].rstrip("GB"),
        "diskSize": info["storage"].rstrip("GB"),
        "localIp": info["deviceIp"],
        "mac": "00:00:00:00:00:00",
        "systemRes": info["deviceResolutionRatio"],
        "displayRes": [{"name": "显示器1", "size": info["deviceResolutionRatio"], "rate": 60}],
    }


def send_base(state_path=None):
    return probe_request("/base/send/v1", base_payload(state_path), state_path)
