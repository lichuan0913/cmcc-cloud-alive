"""Official point/custom event reporting."""

import http.client
import json

from . import core


def point_event(event_name, data=None, state_path=None):
    args = core.argparse.Namespace(state=state_path)
    state = core.load_state(args)
    payload_data = {
        "clientTime": core.shanghai_now().strftime("%Y-%m-%d %H:%M:%S"),
        "phone": state.get("phone") or "",
        "Account": state.get("username") or "",
        "Account_type": "Sub_account" if state.get("isSubAccount") else "Main_account",
    }
    payload_data.update(data or {})
    body = {
        "eventName": event_name,
        "data": json.dumps(payload_data, ensure_ascii=False, separators=(",", ":")),
    }
    if not state.get("publicKey"):
        core.ensure_public_key(args)
        state = core.load_state(args)
    encrypted = core.rsa_encrypt_body(body, state["publicKey"])
    method = "POST"
    path = "/custom/cc/v1"
    headers = core.headers(state, path, method, encrypted)
    payload = core.json_dumps_compact(encrypted).encode("utf-8")
    headers["Content-Length"] = str(len(payload))
    # point.soho.komect.com is case-sensitive for X-SOHO-ClientVersion.
    conn = http.client.HTTPSConnection("point.soho.komect.com", 443, timeout=20)
    conn.request(method, "/point" + path, body=payload, headers=headers)
    res = conn.getresponse()
    raw = res.read().decode("utf-8", errors="replace")
    return json.loads(raw)
