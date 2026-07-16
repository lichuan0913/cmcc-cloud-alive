"""MQTT long-connection keepalive research module (T3-C line).

The official UOS family-cloud client opens a persistent MQTT link to
``ssl://alive.soho.komect.com`` after a desktop session starts.  The broker
credentials are returned in cleartext by ``/terminal/system/mqttConnect/v1``
(a signed, body-less POST).  This module fetches that configuration and opens a
minimal MQTT 3.1.1 over TLS connection, subscribes to the advertised topics,
and keeps the link alive with PINGREQ packets for a short smoke window.

Design constraints (mirroring the rest of the package):
* Pure standard library only — no paho-mqtt dependency.
* Reports are redacted: the JWT / userName / clientId are never written to
  disk; only lengths and SHA-256 fingerprints are recorded.
* Smoke runs are capped at a short duration by default to avoid long tests.
"""

import hashlib
import json
import os
import socket
import ssl
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from . import core


MQTT_CONNECT_PATH = "/system/mqttConnect/v1"
DEFAULT_SMOKE_SECONDS = 90
MAX_SMOKE_SECONDS = 120
DEFAULT_KEEPALIVE_SECONDS = 60  # MQTT CONNECT keep-alive field (wire)


class MqttKeepaliveError(core.CmccError):
    """Raised when the MQTT keepalive research step cannot complete."""


# ---------------------------------------------------------------------------
# MQTT 3.1.1 codec (minimal subset: CONNECT / CONNACK / SUBSCRIBE / SUBACK /
# PINGREQ / PINGRESP / DISCONNECT).
# ---------------------------------------------------------------------------

def _encode_remaining_length(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value % 128
        value //= 128
        if value:
            byte |= 0x80
        out.append(byte)
        if not value:
            break
    return bytes(out)


def _decode_remaining_length(sock: socket.socket) -> int:
    multiplier = 1
    value = 0
    for _ in range(4):
        raw = sock.recv(1)
        if not raw:
            raise MqttKeepaliveError("connection closed while reading remaining length")
        byte = raw[0]
        value += (byte & 0x7F) * multiplier
        if not (byte & 0x80):
            return value
        multiplier *= 128
    raise MqttKeepaliveError("malformed remaining length")


def _encode_string(text: str) -> bytes:
    data = text.encode("utf-8")
    return struct.pack(">H", len(data)) + data


def build_connect_packet(
    client_id: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    keep_alive: int = DEFAULT_KEEPALIVE_SECONDS,
) -> bytes:
    """Build an MQTT 3.1.1 CONNECT packet."""
    # Variable header: protocol name, level, connect flags, keep-alive.
    protocol_name = _encode_string("MQTT")
    level = struct.pack("B", 4)  # MQTT 3.1.1
    flags = 0x02  # clean session
    payload = _encode_string(client_id)
    if username:
        flags |= 0x80
        payload += _encode_string(username)
    if password:
        flags |= 0x40
        payload += _encode_string(password)
    connect_flags = struct.pack("B", flags)
    keep_alive_field = struct.pack(">H", keep_alive)
    variable_header = protocol_name + level + connect_flags + keep_alive_field
    body = variable_header + payload
    return bytes([0x10]) + _encode_remaining_length(len(body)) + body


def build_subscribe_packet(packet_id: int, topics: List[str]) -> bytes:
    """Build an MQTT SUBSCRIBE packet (QoS 0 for every topic)."""
    variable_header = struct.pack(">H", packet_id)
    payload = b""
    for topic in topics:
        payload += _encode_string(topic) + struct.pack("B", 0)  # QoS 0
    body = variable_header + payload
    return bytes([0x82]) + _encode_remaining_length(len(body)) + body


def build_pingreq_packet() -> bytes:
    return bytes([0xC0, 0x00])


def build_disconnect_packet() -> bytes:
    return bytes([0xE0, 0x00])


def read_packet(sock: socket.socket) -> Tuple[int, bytes]:
    """Read one MQTT packet, returning (packet_type, payload)."""
    header = sock.recv(1)
    if not header:
        raise MqttKeepaliveError("connection closed before packet header")
    packet_type = header[0] >> 4
    remaining = _decode_remaining_length(sock)
    payload = b""
    while len(payload) < remaining:
        chunk = sock.recv(remaining - len(payload))
        if not chunk:
            raise MqttKeepaliveError("connection closed mid-payload")
        payload += chunk
    return packet_type, payload


# ---------------------------------------------------------------------------
# Configuration fetch + redaction helpers.
# ---------------------------------------------------------------------------

def fetch_mqtt_config(args=None, state_override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Call ``/terminal/system/mqttConnect/v1`` and return the parsed data."""
    response = core.api_request(MQTT_CONNECT_PATH, data=None, args=args, state_override=state_override)
    if not isinstance(response, dict):
        raise MqttKeepaliveError(f"unexpected mqttConnect response type: {type(response).__name__}")
    code = response.get("code")
    if code != 2000:
        raise MqttKeepaliveError(f"mqttConnect failed: code={code} msg={response.get('msg')}")
    data = response.get("data") or {}
    if not data.get("url") or not data.get("clientId"):
        raise MqttKeepaliveError("mqttConnect response missing url/clientId")
    return data


def _fingerprint(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def redact_config(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a report-safe summary of the broker config (no secrets)."""
    topics = data.get("subTopics")
    if isinstance(topics, str):
        topic_list = [t for t in topics.split(",") if t]
    elif isinstance(topics, list):
        topic_list = [str(t) for t in topics]
    else:
        topic_list = []
    return {
        "url": data.get("url"),
        "clientIdFingerprint": _fingerprint(data.get("clientId")),
        "clientIdLength": len(str(data.get("clientId") or "")),
        "userNameFingerprint": _fingerprint(data.get("userName")),
        "userNameLength": len(str(data.get("userName") or "")),
        "jwtFingerprint": _fingerprint(data.get("jwt")),
        "jwtLength": len(str(data.get("jwt") or "")),
        "subTopics": topic_list,
        "extraKeys": sorted(k for k in data.keys() if k not in {"url", "clientId", "userName", "jwt", "subTopics"}),
    }


def parse_broker_url(url: str) -> Tuple[str, str, int]:
    """Parse ``ssl://host`` / ``mqtt://host:port`` into (scheme, host, port)."""
    if "://" not in url:
        raise MqttKeepaliveError(f"unsupported broker url: {url}")
    scheme, rest = url.split("://", 1)
    scheme = scheme.lower()
    if ":" in rest:
        host, port_str = rest.rsplit(":", 1)
        port = int(port_str)
    else:
        host = rest
        port = 8883 if scheme in ("ssl", "mqtts") else 1883
    return scheme, host, port


# ---------------------------------------------------------------------------
# Smoke run.
# ---------------------------------------------------------------------------

def smoke(
    args=None,
    state_override: Optional[Dict[str, Any]] = None,
    duration_seconds: int = DEFAULT_SMOKE_SECONDS,
    report_file: str = "",
    ping_interval_seconds: int = 30,
    allow_long_run: bool = False,
) -> Dict[str, Any]:
    """Open an MQTT-over-TLS link and keep it alive for a smoke window."""
    long_run_confirmed = allow_long_run or os.environ.get("CMCC_MQTT_ALLOW_LONG_RUN") == "1"
    if int(duration_seconds) > MAX_SMOKE_SECONDS and not long_run_confirmed:
        raise MqttKeepaliveError(f"smoke duration exceeds {MAX_SMOKE_SECONDS}s cap")
    started = time.time()
    report: Dict[str, Any] = {
        "accepted": False,
        "mqttKeepaliveProven": False,
        "experimental": True,
        "stage": "init",
        "duration": 0,
        "broker": None,
        "connect": None,
        "subscribe": None,
        "pingIntervalSeconds": int(ping_interval_seconds),
        "pings": 0,
        "pingResps": 0,
        "messagesReceived": 0,
        "error": None,
    }
    sock: Optional[socket.socket] = None
    try:
        data = fetch_mqtt_config(args=args, state_override=state_override)
        report["broker"] = redact_config(data)
        scheme, host, port = parse_broker_url(data["url"])
        if scheme not in ("ssl", "mqtts"):
            raise MqttKeepaliveError(f"non-TLS broker scheme not supported for smoke: {scheme}")

        report["stage"] = "tcp-connect"
        raw = socket.create_connection((host, port), timeout=15)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(raw, server_hostname=host)
        sock.settimeout(5)

        report["stage"] = "mqtt-connect"
        connect_packet = build_connect_packet(
            client_id=data["clientId"],
            username=data.get("userName"),
            password=data.get("jwt"),
            keep_alive=DEFAULT_KEEPALIVE_SECONDS,
        )
        sock.sendall(connect_packet)
        packet_type, payload = read_packet(sock)
        if packet_type != 0x02:  # CONNACK
            raise MqttKeepaliveError(f"expected CONNACK, got packet type {packet_type:#x}")
        return_code = payload[1] if len(payload) >= 2 else None
        report["connect"] = {"connack": return_code, "accepted": return_code == 0}
        if return_code != 0:
            raise MqttKeepaliveError(f"MQTT CONNECT rejected with code {return_code}")
        report["accepted"] = True

        report["stage"] = "subscribe"
        topics = report["broker"]["subTopics"]
        if topics:
            sub_packet = build_subscribe_packet(packet_id=1, topics=topics)
            sock.sendall(sub_packet)
            packet_type, payload = read_packet(sock)
            granted = list(payload[2:]) if len(payload) > 2 else []
            report["subscribe"] = {"packetType": packet_type, "grantedQos": granted}
            if packet_type != 0x09:  # SUBACK
                raise MqttKeepaliveError(f"expected SUBACK, got packet type {packet_type:#x}")

        report["stage"] = "ping-loop"
        deadline = started + max(1, int(duration_seconds))
        ping_interval = max(5, int(ping_interval_seconds))
        next_ping = time.time()
        while time.time() < deadline:
            now = time.time()
            if now >= next_ping:
                sock.sendall(build_pingreq_packet())
                report["pings"] += 1
                next_ping = now + ping_interval
            try:
                packet_type, payload = read_packet(sock)
            except socket.timeout:
                continue
            if packet_type == 0x0D:  # PINGRESP
                report["pingResps"] += 1
            elif packet_type == 0x30:  # PUBLISH
                report["messagesReceived"] += 1
            # other packet types are tolerated but not parsed
        report["mqttKeepaliveProven"] = report["pings"] > 0 and report["pingResps"] > 0
        report["stage"] = "done"
    except Exception as exc:  # noqa: BLE001 - research harness reports all failures
        report["error"] = f"{type(exc).__name__}: {exc}"
        report["stage"] = report.get("stage") or "error"
    finally:
        if sock is not None:
            try:
                sock.sendall(build_disconnect_packet())
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
    report["duration"] = round(time.time() - started, 2)
    core.write_private_json_report(report, report_file)
    return report
