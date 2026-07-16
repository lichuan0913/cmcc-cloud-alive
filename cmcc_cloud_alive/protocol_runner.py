"""Protocol-level SPICE/RAP desktop runner.

This module is intentionally small and stdlib-only: it obtains/accepts a
family-cloud ``connectStr`` and drives the minimum Chuanyun-framed SPICE display
channel handshake that the offline codec already models.
"""

import socket
import time
import urllib.parse

from . import cloud, core, spice_protocol


DEFAULT_PORT = 9000
PUBLIC_CONNECT_ARG_KEYS = {
    "h",
    "p",
    "type",
    "server-type",
    "vmport",
    "vmportv6",
    "stream",
    "quic-enable",
    "trace-level",
    "netchecktime",
}
SENSITIVE_CONNECT_ARG_KEYS = {
    "accessToken",
    "cpsid",
    "k",
    "pass-through",
    "token",
    "t",
}


def _first_connect_arg_value(value):
    text = urllib.parse.unquote(str(value or "")).strip().strip('"').strip("'")
    if not text:
        return ""
    for part in text.replace(",", ";").split(";"):
        part = part.strip()
        if part:
            return part
    return ""


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def connect_info_from_connect_str(connect_str):
    """Parse official connectStr into normalized runner connection info."""
    plain = plain_connect_str(connect_str)
    parsed = core.parse_connect_str_args(plain or "")
    host = parsed.get("h") or parsed.get("host") or parsed.get("ag")
    base_port = parsed.get("p") or parsed.get("port") or parsed.get("ag-port")
    vm_host = _first_connect_arg_value(parsed.get("vmip") or parsed.get("vm_ip"))
    vm_host_v6 = _first_connect_arg_value(parsed.get("vmipv6") or parsed.get("vm_ipv6"))
    vm_port = _int_or_none(parsed.get("vmport") or parsed.get("vm_port"))
    vm_port_v6 = _int_or_none(parsed.get("vmportv6") or parsed.get("vm_portv6"))
    protocol = parsed.get("type") or parsed.get("protocol") or "rap"
    proxy_port = parsed.get("proxy-port") or parsed.get("proxy_port")
    proxy_sport = parsed.get("proxy-sport") or parsed.get("proxy_sport")
    selected_port = base_port
    port_source = "p"
    udp_ssl = False
    if str(protocol).lower() != "ice":
        if proxy_port:
            selected_port = proxy_port
            port_source = "proxy-port"
        if proxy_sport:
            selected_port = proxy_sport
            port_source = "proxy-sport"
            udp_ssl = True
    info = {
        "connectStr": plain,
        "host": host,
        "port": int(selected_port or DEFAULT_PORT),
        "gatewayPort": int(base_port or DEFAULT_PORT),
        "udpPortSource": port_source,
        "udpSsl": udp_ssl,
        "vmid": parsed.get("vmid") or parsed.get("vmId"),
        "vmHost": vm_host or None,
        "vmPort": vm_port,
        "vmHostV6": vm_host_v6 or None,
        "vmPortV6": vm_port_v6,
        "type": protocol,
        "accessToken": parsed.get("accessToken") or parsed.get("k") or parsed.get("token"),
        "cpsid": parsed.get("cpsid") or parsed.get("cpsId") or parsed.get("serviceId"),
        "rawArgs": parsed,
    }
    if not info["host"]:
        raise core.CmccError("connectStr does not contain a gateway host")
    return info


def plain_connect_str(connect_str):
    """Return plaintext CAG connectStr args.

    CAG returns connectStr as CSAP-encrypted hex, while tests and manual CLI
    experiments often pass the already-decoded command line.  Keep the raw
    encrypted value out of reports/state and only normalize it in memory.
    """
    text = str(connect_str or "").strip()
    if not text:
        return ""
    try:
        return core.decode_csap_connect_str(text)
    except Exception:
        return text


def _decoded_connect_str(decoded):
    info = core.get_decoded_connect_info(decoded)
    if not isinstance(info, dict) or not info.get("connectStr"):
        raise core.CmccError("CAG response did not contain connectStr")
    return info["connectStr"]


def public_connect_info(connect_info):
    raw_args = connect_info.get("rawArgs") or {}
    public_args = {key: raw_args.get(key) for key in sorted(PUBLIC_CONNECT_ARG_KEYS) if key in raw_args}
    sensitive_present = {
        key: bool(raw_args.get(key) or connect_info.get(key))
        for key in sorted(SENSITIVE_CONNECT_ARG_KEYS)
        if key in raw_args or key in connect_info
    }
    return {
        "host": connect_info.get("host"),
        "port": connect_info.get("port"),
        "gatewayPortPresent": bool(connect_info.get("gatewayPort")),
        "udpPortSource": connect_info.get("udpPortSource"),
        "udpSsl": bool(connect_info.get("udpSsl")),
        "vmHostPresent": bool(connect_info.get("vmHost")),
        "vmPortPresent": bool(connect_info.get("vmPort")),
        "vmHostV6Present": bool(connect_info.get("vmHostV6")),
        "vmPortV6Present": bool(connect_info.get("vmPortV6")),
        "type": connect_info.get("type"),
        "accessTokenPresent": bool(connect_info.get("accessToken") or raw_args.get("accessToken") or raw_args.get("k")),
        "cpsidPresent": bool(connect_info.get("cpsid") or raw_args.get("cpsid")),
        "rawArgKeys": sorted(key for key in raw_args.keys() if key != "_"),
        "publicArgs": public_args,
        "sensitiveArgPresent": sensitive_present,
    }


def _runner_cag_args(user_service_id=None, state_path=None, boot_wait=180, timeout=30):
    return core.argparse.Namespace(
        state=state_path,
        user_service_id=cloud.selected_user_service_id(state_path, user_service_id),
        boot_wait=boot_wait,
        timeout=timeout,
        version="V7.25.40-HY",
        client_ip="",
        mac="",
        host_name="",
    )


def _wait_for_raw_connect_decoded(auth, initial_decoded, args):
    info = core.get_decoded_connect_info(initial_decoded)
    if isinstance(info, dict) and info.get("connectStr"):
        return initial_decoded
    token_info = initial_decoded.get("tokenInfo") if isinstance(initial_decoded, dict) else {}
    if not ((info or {}).get("accessToken") or (token_info or {}).get("accessToken")):
        return initial_decoded

    max_wait = max(0, int(getattr(args, "boot_wait", 180)))
    started = time.time()
    decoded = initial_decoded
    while time.time() - started < max_wait:
        current = core.get_decoded_connect_info(decoded) or info or {}
        wait_for = max(1, int(current.get("asyncQueryTimeInterval") or 5))
        time.sleep(min(wait_for, max(0, max_wait - (time.time() - started))))
        if time.time() - started >= max_wait:
            break
        response = core.cag_https_request(
            auth,
            core.create_cag_async_query_path(auth, initial_decoded),
            "",
            timeout=int(getattr(args, "timeout", 15)),
        )
        _summary, decoded = core.summarize_cag_response(response)
        current = core.get_decoded_connect_info(decoded)
        if isinstance(current, dict) and current.get("connectStr"):
            return decoded
    return decoded


def _fetch_cag_auth_connect_str(user_service_id=None, state_path=None, boot_wait=180, timeout=30):
    args = _runner_cag_args(user_service_id, state_path, boot_wait=boot_wait, timeout=timeout)
    auth = core.get_firm_auth(args)
    if not auth.get("cagIp") or not auth.get("cagPort"):
        raise core.CmccError("selected desktop does not expose CAG HTTPS material")
    username = auth.get("vmUserName")
    if not username or not auth.get("vmPassword"):
        raise core.CmccError("firm-auth response is missing vmUserName/vmPassword")

    sys_path = f"/cs/cs_sysConfig.action?version={core.urllib.parse.quote(args.version)}&language=zh&requestFrom=5&name={core.urllib.parse.quote(str(username))}&RspSecurity=1"
    sys_response = core.cag_https_request(auth, sys_path, "", timeout=int(timeout))
    _sys_summary, sys_decoded = core.summarize_cag_response(sys_response)
    rsa_public_key = (sys_decoded or {}).get("rsapub")
    if not rsa_public_key:
        raise core.CmccError("CAG sysConfig did not include rsapub")

    connect_payload = core.create_cag_connect_desktop_body(auth, rsa_public_key, args)
    connect_response = core.cag_https_request(
        auth,
        "/cs/cs_connectDesktop.action",
        core.json_dumps_compact(connect_payload["body"]),
        timeout=int(timeout),
    )
    _connect_summary, connect_decoded = core.summarize_cag_response(connect_response)
    decoded = _wait_for_raw_connect_decoded(auth, connect_decoded, args) if connect_decoded else connect_decoded
    return auth, _decoded_connect_str(decoded)


def _fetch_cag_connect_str(user_service_id=None, state_path=None, boot_wait=180, timeout=30):
    return _fetch_cag_auth_connect_str(user_service_id, state_path, boot_wait=boot_wait, timeout=timeout)[1]


def fetch_cag_auth_connect_info(user_service_id=None, state_path=None, boot_wait=180, timeout=30):
    """Return fresh in-memory CAG auth material plus normalized connect info.

    The returned ``auth`` and ``connectInfo`` dictionaries may contain live
    session secrets and must not be written directly to reports.
    """
    auth, raw = _fetch_cag_auth_connect_str(user_service_id, state_path, boot_wait=boot_wait, timeout=timeout)
    info = connect_info_from_connect_str(raw)
    return {
        "auth": auth,
        "connectInfo": info,
        "publicConnectInfo": public_connect_info(info),
    }


def fetch_connect_info(user_service_id=None, state_path=None, boot_wait=180, timeout=30, connect_str=None):
    """Return normalized connection info, booting/refreshing through CAG if needed."""
    if connect_str:
        return connect_info_from_connect_str(connect_str)
    raw = _fetch_cag_connect_str(user_service_id, state_path, boot_wait=boot_wait, timeout=timeout)
    return connect_info_from_connect_str(raw)


class ProtocolSession:
    """Minimal blocking Chuanyun/SPICE display channel session."""

    def __init__(self, sock, session_id=0, channel_id=spice_protocol.SpiceChannel.DISPLAY):
        self.sock = sock
        self.session_id = session_id
        self.channel_id = channel_id
        self.buffer = b""
        self.progress = spice_protocol.create_protocol_progress()
        self.frames_received = 0
        self.messages_received = 0
        self.responses_sent = 0

    def send_payload(self, payload):
        frame = spice_protocol.encode_chuanyun_frame(
            payload,
            session_id=self.session_id,
            channel_id=self.channel_id,
        )
        self.sock.sendall(frame)
        self.responses_sent += 1

    def start_display(self):
        self.send_payload(spice_protocol.encode_display_init())
        self.progress = spice_protocol.apply_protocol_event(
            self.progress,
            spice_protocol.ProtocolStage.DISPLAY_INIT_SENT,
        )

    def _handle_message(self, payload):
        message = spice_protocol.decode_data_message(payload)
        message_type = message["header"]["type"]
        if message_type == spice_protocol.SpiceMessage.SET_ACK:
            ack = spice_protocol.decode_set_ack_payload(message["payload"])
            self.progress = spice_protocol.apply_protocol_event(
                self.progress,
                spice_protocol.ProtocolStage.SET_ACK_RECEIVED,
            )
            self.send_payload(spice_protocol.encode_ack_sync(ack["generation"]))
            self.progress = spice_protocol.apply_protocol_event(
                self.progress,
                spice_protocol.ProtocolStage.ACK_SYNC_SENT,
            )
        elif message_type == spice_protocol.SpiceMessage.PING:
            self.progress = spice_protocol.apply_protocol_event(
                self.progress,
                spice_protocol.ProtocolStage.PING_RECEIVED,
            )
            self.send_payload(spice_protocol.encode_pong(message["payload"]))
            self.progress = spice_protocol.apply_protocol_event(
                self.progress,
                spice_protocol.ProtocolStage.PONG_SENT,
            )
        elif message_type == spice_protocol.SpiceMessage.SURFACE_CREATE:
            self.progress = spice_protocol.apply_protocol_event(
                self.progress,
                spice_protocol.ProtocolStage.SURFACE_CREATE_RECEIVED,
            )
            self.send_payload(spice_protocol.encode_ack())
        elif message_type == spice_protocol.SpiceMessage.DRAW_COPY:
            self.progress = spice_protocol.apply_protocol_event(
                self.progress,
                spice_protocol.ProtocolStage.DRAW_COPY_RECEIVED,
            )
            self.send_payload(spice_protocol.encode_ack())
        elif message_type == spice_protocol.SpiceMessage.MARK:
            self.progress = spice_protocol.apply_protocol_event(
                self.progress,
                spice_protocol.ProtocolStage.MARK_RECEIVED,
            )
            self.send_payload(spice_protocol.encode_ack())
        return message

    def pump_once(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise ConnectionError("protocol peer closed the socket")
        self.buffer += chunk
        handled = []
        while len(self.buffer) >= spice_protocol.CHUANYUN_HEAD_SIZE:
            head = spice_protocol.decode_chuanyun_head(self.buffer)
            total = spice_protocol.CHUANYUN_HEAD_SIZE + head["payloadLength"]
            if len(self.buffer) < total:
                break
            frame = spice_protocol.decode_chuanyun_frame(self.buffer[:total])
            self.buffer = self.buffer[total:]
            self.frames_received += 1
            if frame["payload"]:
                handled.append(self._handle_message(frame["payload"]))
                self.messages_received += 1
        return handled

    def report(self, error=None):
        return {
            "progress": self.progress,
            "success": spice_protocol.is_protocol_keepalive_success(self.progress),
            "framesReceived": self.frames_received,
            "messagesReceived": self.messages_received,
            "responsesSent": self.responses_sent,
            "error": error,
        }

    def run(self, run_seconds=2400, success_only=False):
        """Run the already-open protocol session and return a progress report."""
        started = time.time()
        deadline = started + max(0, run_seconds)
        error = None
        try:
            self.start_display()
            while run_seconds <= 0 or time.time() < deadline:
                self.pump_once()
                if success_only and spice_protocol.is_protocol_keepalive_success(self.progress):
                    break
        except Exception as err:
            error = f"{type(err).__name__}: {err}"
        result = self.report(error=error)
        result["startedAt"] = started
        result["endedAt"] = time.time()
        result["elapsedSeconds"] = int(result["endedAt"] - started)
        return result


def run_connect_info(connect_info, run_seconds=2400, timeout=15, success_only=False):
    """Connect to gateway and run the minimum protocol loop."""
    started = time.time()
    transport_type = str(connect_info.get("type") or "").lower()
    deadline = started + max(0, run_seconds)
    report = {
        "connectInfo": public_connect_info(connect_info),
        "startedAt": started,
        "transportType": transport_type or "unknown",
        "progress": spice_protocol.create_protocol_progress(),
        "success": False,
        "desktopKeepaliveProven": False,
        "framesReceived": 0,
        "messagesReceived": 0,
        "responsesSent": 0,
        "error": None,
    }
    if transport_type == "rap":
        report["error"] = (
            "rap_zime_spice_runner_not_implemented: family Linux connectStr uses "
            "RAP/ZIME UDP, not direct TCP Chuanyun frames. Use analyze-rap-zime "
            "and rap-zime-udp-probe to parameterize the remaining transport work."
        )
        report["requiredProtocolPath"] = [
            "RAP/ZIME channel creation",
            "SPICE main link/auth",
            "SPICE display link/auth",
            "DISPLAY_INIT",
            "SET_ACK/ACK_SYNC and PING/PONG",
        ]
        report["endedAt"] = time.time()
        report["elapsedSeconds"] = int(report["endedAt"] - started)
        return report
    try:
        with socket.create_connection((connect_info["host"], int(connect_info["port"])), timeout=timeout) as sock:
            sock.settimeout(timeout)
            session = ProtocolSession(sock)
            session.start_display()
            while run_seconds <= 0 or time.time() < deadline:
                session.pump_once()
                report.update({
                    "progress": session.progress,
                    "success": spice_protocol.is_protocol_keepalive_success(session.progress),
                    "framesReceived": session.frames_received,
                    "messagesReceived": session.messages_received,
                    "responsesSent": session.responses_sent,
                })
                if success_only and report["success"]:
                    break
    except Exception as err:  # keep report-oriented CLI behavior
        report["error"] = f"{type(err).__name__}: {err}"
    report["endedAt"] = time.time()
    report["elapsedSeconds"] = int(report["endedAt"] - started)
    return report


def run(user_service_id=None, state_path=None, connect_str=None, run_seconds=2400, boot_wait=180, timeout=30, success_only=False):
    """Fetch material if necessary, then execute protocol session."""
    info = fetch_connect_info(user_service_id, state_path, boot_wait=boot_wait, timeout=timeout, connect_str=connect_str)
    return run_connect_info(info, run_seconds=run_seconds, timeout=timeout, success_only=success_only)
