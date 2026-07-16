"""Research-only ctypes bridge for libZIMEDataEngine.so.

This module is deliberately not the production keepalive path.  It gives the
runner work a controlled way to ask the native ZIME/lsquic engine to produce
packet-out callbacks for known SPICE payloads, so the protected payload layer can
be studied without guessing or replaying captured bytes.
"""

import ctypes
import json
import os
import socket
import time
from pathlib import Path

from . import core, rap_zime, zime_probe


DEFAULT_ZIME_LIB = Path(
    "/opt/chuanyun-vdi-client/resources/app.asar.unpacked/"
    "node_modules/chuanyunAddOn-zte/ccsdk/lib/libZIMEDataEngine.so"
)
REQUIRED_EXPORTS = [
    "ZIME_CreateDataEngine",
    "ZIME_Init",
    "ZIME_SetDataChannelCallback",
    "ZIME_SetDataExternalTransport",
    "ZIME_CreateDataChannel",
    "ZIME_CreateDataStream",
    "ZIME_SendData",
    "ZIME_ReceiveData",
    "ZIME_DataChannelProcess2",
]
OPTIONAL_EXPORTS = [
    "DefaultZIMEInitParam",
    "DefaultZIMEChannelContext",
    "DefaultZIMEStreamParam",
    "ZIME_GetInfoByErrno",
    "ZIME_SendData2",
    "ZIME_DestroyDataChannel",
    "ZIME_DestroyDataStream",
]
DEFAULT_BASE_MTU = 1452
DEFAULT_STREAM_ID = 1
DEFAULT_PROCESS_TICKS = 4
DEFAULT_WAIT_CHANNEL_CREATED_TICKS = 20
DEFAULT_UDP_READ_TIMEOUT = 0.2
DEFAULT_UDP_RECEIVE_LIMIT = 8
DEFAULT_UDP_PROCESS_TICKS_AFTER_RECEIVE = 2
RAP_PAYLOAD_ENVELOPE_RAW = "raw"
RAP_PAYLOAD_ENVELOPE_LEN16 = "len16"
RAP_PAYLOAD_ENVELOPE_STRIP_RESERVE4_LEN16 = "strip-reserve4-len16"
RAP_PAYLOAD_ENVELOPES = {
    RAP_PAYLOAD_ENVELOPE_RAW,
    RAP_PAYLOAD_ENVELOPE_LEN16,
    RAP_PAYLOAD_ENVELOPE_STRIP_RESERVE4_LEN16,
}
PACKET_OUT_IOV_MODE_CONCAT = "concat"
PACKET_OUT_IOV_MODE_SPLIT = "split"
PACKET_OUT_IOV_MODES = {
    PACKET_OUT_IOV_MODE_CONCAT,
    PACKET_OUT_IOV_MODE_SPLIT,
}
RAP_TEMPLATE_MODE_AUTO = "auto"
RAP_TEMPLATE_MODE_STATIC = "static"
RAP_TEMPLATE_MODE_SEQUENCE = "sequence"
RAP_TEMPLATE_MODE_PAYLOAD_KIND = "payload-kind"
RAP_TEMPLATE_MODES = {
    RAP_TEMPLATE_MODE_AUTO,
    RAP_TEMPLATE_MODE_STATIC,
    RAP_TEMPLATE_MODE_SEQUENCE,
    RAP_TEMPLATE_MODE_PAYLOAD_KIND,
}


class ZimeInitParam(ctypes.Structure):
    _fields_ = [
        ("eZIMEDCRole", ctypes.c_uint32),
        ("_pad04", ctypes.c_ubyte * 52),
        ("eZIMESupportDCProtocol", ctypes.c_uint32),
        ("bUDPPayloadReserve4Bytes", ctypes.c_uint8),
        ("_pad61", ctypes.c_ubyte * 3),
    ]


class ZimeSocketParam(ctypes.Structure):
    _fields_ = [
        ("pLocalAddr", ctypes.c_void_p),
        ("pRemoteAddr", ctypes.c_void_p),
        ("opaque", ctypes.c_ubyte * 64),
        ("nOpaqueLen", ctypes.c_uint32),
        ("_pad84", ctypes.c_uint32),
    ]


class ZimeChannelContext(ctypes.Structure):
    _fields_ = [
        ("eDCProtocol", ctypes.c_uint32),
        ("_pad04", ctypes.c_uint32),
        ("socketParam", ZimeSocketParam),
        ("u16BaseMTU", ctypes.c_uint16),
        ("bSavePcap", ctypes.c_uint8),
        ("bOpenStat", ctypes.c_uint8),
        ("eBusinessType", ctypes.c_uint32),
    ]


class ZimeStreamParam(ctypes.Structure):
    _fields_ = [
        ("mode", ctypes.c_uint32),
        ("supportDropData", ctypes.c_uint8),
        ("_pad05", ctypes.c_ubyte * 3),
        ("latencyThreshMs", ctypes.c_uint32),
        ("u8Priority", ctypes.c_uint8),
        ("_pad13", ctypes.c_ubyte * 3),
        ("u32MaxBandwidth", ctypes.c_uint32),
        ("u32StreamUnsendBytes", ctypes.c_uint32),
        ("bHasUnackData", ctypes.c_uint8),
        ("_pad25", ctypes.c_ubyte * 3),
        ("s32BitrateKbps", ctypes.c_int32),
        ("s32NetLost", ctypes.c_int32),
        ("s32NetNetRttAvg", ctypes.c_int32),
        ("payloadType", ctypes.c_ubyte * 32),
    ]


class SockaddrIn(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_uint32),
        ("sin_zero", ctypes.c_ubyte * 8),
    ]


class Iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_size_t),
    ]


TransportSendCallback = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_long, ctypes.c_void_p, ctypes.c_uint)
TransportBatchCallback = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t)
ChannelDataCallback = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_uint)
ChannelCreatedCallback = ctypes.CFUNCTYPE(None, ctypes.c_long, ctypes.c_ulong, ctypes.c_int, ctypes.c_int, ctypes.c_int)
ChannelDestroyedCallback = ctypes.CFUNCTYPE(None, ctypes.c_long, ctypes.c_int, ctypes.c_int)
ChannelStreamBlockedCallback = ctypes.CFUNCTYPE(None, ctypes.c_long, ctypes.c_long, ctypes.c_ubyte, ctypes.c_uint)


def _resolve_lib_path(lib_path=None):
    value = lib_path or os.environ.get("CMCC_ZIME_LIB") or str(DEFAULT_ZIME_LIB)
    return Path(os.path.expanduser(str(value)))


def _ptr_value(value):
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    return int(ctypes.cast(value, ctypes.c_void_p).value or 0)


def _ptr_text(value):
    return f"0x{_ptr_value(value):x}"


def _payload_kind(data):
    return zime_probe.classify_payload(bytes(data or b""), allow_short_mini=True)


def _parse_udp_target(target):
    if target in (None, ""):
        return None
    if isinstance(target, tuple) and len(target) >= 2:
        return str(target[0]), int(target[1])
    text = str(target).strip()
    if text.startswith("udp://"):
        text = text[6:]
    host, sep, port = text.rpartition(":")
    if not sep or not host or not port:
        raise core.CmccError(f"invalid UDP transport target: {target}")
    return host, int(port)


def _format_udp_target(target):
    parsed = _parse_udp_target(target)
    if not parsed:
        return None
    return f"{parsed[0]}:{parsed[1]}"


def _fixed_hex_or_bytes(value, size, field_name):
    if value is None:
        return b"\x00" * size
    if isinstance(value, str):
        raw = bytes.fromhex(value) if value else b""
    else:
        raw = bytes(value)
    if len(raw) != size:
        raise core.CmccError(f"{field_name} must be exactly {size} bytes")
    return raw


def _normalize_rap_payload_envelope(value):
    mode = str(value or RAP_PAYLOAD_ENVELOPE_RAW).strip().lower()
    if mode not in RAP_PAYLOAD_ENVELOPES:
        raise core.CmccError(f"unsupported RAP payload envelope: {value}")
    return mode


def _normalize_packet_out_iov_mode(value):
    mode = str(value or PACKET_OUT_IOV_MODE_CONCAT).strip().lower()
    if mode not in PACKET_OUT_IOV_MODES:
        raise core.CmccError(f"unsupported packet-out iov mode: {value}")
    return mode


def _normalize_rap_template_mode(value):
    mode = str(value or RAP_TEMPLATE_MODE_AUTO).strip().lower()
    if mode not in RAP_TEMPLATE_MODES:
        raise core.CmccError(f"unsupported RAP template mode: {value}")
    return mode


def _template_int(template, name, default=0):
    value = (template or {}).get(name, default)
    if value in (None, ""):
        return int(default)
    return int(value, 0) if isinstance(value, str) else int(value)


def _normalize_rap_send_templates(templates):
    normalized = []
    for index, item in enumerate(list(templates or [])):
        if not isinstance(item, dict):
            continue
        normalized.append({
            "index": int(item.get("index", item.get("sampleIndex", index)) or index),
            "frameType": _template_int(item, "frameType", 0x81),
            "flags": _template_int(item, "flags", 0),
            "field06": _template_int(item, "field06", 0),
            "word08": _template_int(item, "word08", 0),
            "word12": _template_int(item, "word12", 0),
            "header16Prefix": _fixed_hex_or_bytes(item.get("header16PrefixHex"), 3, "RAP template header16 prefix"),
            "postLength": _fixed_hex_or_bytes(item.get("postLengthHex"), 3, "RAP template post-length bytes"),
            "header16PrefixHex": _fixed_hex_or_bytes(item.get("header16PrefixHex"), 3, "RAP template header16 prefix").hex(),
            "postLengthHex": _fixed_hex_or_bytes(item.get("postLengthHex"), 3, "RAP template post-length bytes").hex(),
            "payloadKind": item.get("payloadKind"),
            "payloadLength": item.get("payloadLength"),
            "zimePayloadEnvelopeObserved": bool(item.get("zimePayloadEnvelopeObserved")),
            "traceOnly": True,
        })
    return normalized


def _len16_prefixed(payload, field_name="RAP payload envelope"):
    payload = bytes(payload or b"")
    if len(payload) > 0xFFFF:
        raise core.CmccError(f"{field_name} exceeds 65535 bytes")
    return len(payload).to_bytes(2, "little") + payload


def _payload_kind_template_candidates(kind):
    values = []
    if kind:
        values.append(kind)
    prefix = "zime-udp-reserved4:"
    if isinstance(kind, str) and kind.startswith(prefix):
        values.append(kind[len(prefix):])
    return values


def _has_export(lib, name):
    try:
        getattr(lib, name)
    except AttributeError:
        return False
    return True


def structure_layout():
    """Return the ABI offsets used by the research bridge."""
    result = {}
    for cls in (ZimeInitParam, ZimeSocketParam, ZimeChannelContext, ZimeStreamParam, SockaddrIn):
        fields = {}
        for name, _ctype in cls._fields_:
            if name.startswith("_pad"):
                continue
            fields[name] = getattr(cls, name).offset
        result[cls.__name__] = {
            "size": ctypes.sizeof(cls),
            "fields": fields,
        }
    result["source"] = "inferred_from_probe_and_disassembly"
    result["traceOnly"] = True
    return result


def make_sockaddr_in(host="127.0.0.1", port=0):
    packed = socket.inet_aton(str(host))
    addr = SockaddrIn()
    addr.sin_family = socket.AF_INET
    addr.sin_port = socket.htons(int(port))
    addr.sin_addr = int.from_bytes(packed, "little")
    return addr


def make_init_param(role=0, support_protocol=0, reserve_udp_payload_4bytes=1):
    param = ZimeInitParam()
    param.eZIMEDCRole = int(role)
    param.eZIMESupportDCProtocol = int(support_protocol)
    param.bUDPPayloadReserve4Bytes = int(reserve_udp_payload_4bytes)
    return param


def make_channel_context(
    *,
    local_host="0.0.0.0",
    local_port=0,
    remote_host="127.0.0.1",
    remote_port=0,
    opaque=b"\x00\x00\x00\x00",
    protocol=0,
    mtu=DEFAULT_BASE_MTU,
    save_pcap=0,
    open_stat=1,
    business_type=1,
):
    opaque = bytes(opaque or b"")
    local = make_sockaddr_in(local_host, local_port)
    remote = make_sockaddr_in(remote_host, remote_port)
    context = ZimeChannelContext()
    context.eDCProtocol = int(protocol)
    context.socketParam.pLocalAddr = ctypes.addressof(local)
    context.socketParam.pRemoteAddr = ctypes.addressof(remote)
    if len(opaque) > len(context.socketParam.opaque):
        raise core.CmccError("ZIME channel opaque data is longer than 64 bytes")
    for index, value in enumerate(opaque):
        context.socketParam.opaque[index] = value
    context.socketParam.nOpaqueLen = len(opaque)
    context.u16BaseMTU = int(mtu)
    context.bSavePcap = int(save_pcap)
    context.bOpenStat = int(open_stat)
    context.eBusinessType = int(business_type)
    return context, [local, remote]


def make_stream_param(mode=1, support_drop_data=0, priority=0x7F, max_bandwidth=0xFFFFFFFF, payload_type=b""):
    param = ZimeStreamParam()
    param.mode = int(mode)
    param.supportDropData = int(support_drop_data)
    param.u8Priority = int(priority)
    param.u32MaxBandwidth = int(max_bandwidth)
    payload_type = bytes(payload_type or b"")
    if len(payload_type) >= len(param.payloadType):
        raise core.CmccError("ZIME stream payload type must fit in the 32-byte C string field")
    for index, value in enumerate(payload_type):
        param.payloadType[index] = value
    return param


def inspect_library(lib_path=None, loader=ctypes.CDLL):
    """Inspect native library availability without calling any ZIME functions."""
    path = _resolve_lib_path(lib_path)
    report = {
        "ok": False,
        "researchOnly": True,
        "nativeRun": False,
        "libPath": str(path),
        "exists": path.exists(),
        "requiredExports": {},
        "optionalExports": {},
        "structLayout": structure_layout(),
        "error": None,
    }
    if not path.exists():
        report["error"] = "library_not_found"
        return report
    try:
        lib = loader(str(path))
    except OSError as err:
        report["error"] = f"library_load_failed: {err}"
        return report
    for name in REQUIRED_EXPORTS:
        report["requiredExports"][name] = _has_export(lib, name)
    for name in OPTIONAL_EXPORTS:
        report["optionalExports"][name] = _has_export(lib, name)
    missing = [name for name, present in report["requiredExports"].items() if not present]
    report["ok"] = not missing
    if missing:
        report["error"] = "missing_required_exports: " + ",".join(missing)
    report["nextStep"] = (
        "Use --allow-native-run with a fake external transport only after "
        "confirming the struct layout against a fresh official-client trace."
    )
    return report


def _bind_library(lib):
    lib.ZIME_CreateDataEngine.restype = ctypes.c_void_p

    lib.ZIME_Init.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.ZIME_Init.restype = ctypes.c_int

    lib.ZIME_SetDataChannelCallback.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.ZIME_SetDataChannelCallback.restype = ctypes.c_int

    lib.ZIME_SetDataExternalTransport.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.ZIME_SetDataExternalTransport.restype = ctypes.c_int

    lib.ZIME_CreateDataChannel.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_long)]
    lib.ZIME_CreateDataChannel.restype = ctypes.c_int

    lib.ZIME_CreateDataStream.argtypes = [ctypes.c_void_p, ctypes.c_long, ctypes.POINTER(ctypes.c_long), ctypes.c_void_p]
    lib.ZIME_CreateDataStream.restype = ctypes.c_int

    lib.ZIME_SendData.argtypes = [ctypes.c_void_p, ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_uint]
    lib.ZIME_SendData.restype = ctypes.c_int

    lib.ZIME_ReceiveData.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]
    lib.ZIME_ReceiveData.restype = ctypes.c_int

    if getattr(lib, "ZIME_DataChannelProcess2", None):
        lib.ZIME_DataChannelProcess2.argtypes = [ctypes.c_void_p, ctypes.c_long, ctypes.POINTER(ctypes.c_uint)]
        lib.ZIME_DataChannelProcess2.restype = ctypes.c_int
    if getattr(lib, "ZIME_GetInfoByErrno", None):
        lib.ZIME_GetInfoByErrno.argtypes = [ctypes.c_int]
        lib.ZIME_GetInfoByErrno.restype = ctypes.c_char_p
    return lib


def _error_info(lib, code):
    try:
        fn = lib.ZIME_GetInfoByErrno
    except AttributeError:
        return None
    try:
        value = fn(int(code))
    except Exception:
        return None
    if not value:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def native_bridge_milestones(report):
    """Summarize native bridge progress without treating it as keepalive proof."""
    report = report or {}
    calls = list(report.get("calls") or [])
    records = list(report.get("callbackRecords") or [])
    payloads = list(report.get("payloads") or [])
    udp = report.get("udpTransport") or {}

    def call_ok(name):
        return any(item.get("function") == name and int(item.get("ret") or 0) == 0 for item in calls)

    def call_seen(name):
        return any(item.get("function") == name for item in calls)

    def event_seen(name):
        return any(item.get("event") == name for item in records)

    channel_created_records = [item for item in records if item.get("event") == "native_channel_created"]
    stream_create_records = [item for item in calls if item.get("function") == "ZIME_CreateDataStream"]
    display_payloads = [item for item in payloads if item.get("payloadKind") == "spice-display-init"]
    packet_out_seen = event_seen("native_transport_send") or event_seen("native_transport_batch")
    udp_enabled = bool(udp.get("enabled"))
    milestones = {
        "desktopKeepaliveProven": False,
        "channelCreateCalled": call_seen("ZIME_CreateDataChannel"),
        "channelCreateOk": call_ok("ZIME_CreateDataChannel"),
        "nativePacketOutSeen": packet_out_seen,
        "nativeUdpTransportEnabled": udp_enabled,
        "nativeUdpSent": event_seen("native_udp_send") or int(udp.get("sentPackets") or 0) > 0,
        "nativeUdpReceived": event_seen("native_udp_receive") or int(udp.get("receivedPackets") or 0) > 0,
        "receiveDataCalled": call_seen("ZIME_ReceiveData"),
        "receiveDataOk": call_ok("ZIME_ReceiveData"),
        "nativeChannelCreated": bool(channel_created_records),
        "nativeChannelCreatedOk": any(
            int(item.get("status") or 0) == 0 and int(item.get("err") or 0) == 0
            for item in channel_created_records
        ),
        "streamCreateCalled": bool(stream_create_records),
        "streamCreateOk": any(int(item.get("ret") or 0) == 0 for item in stream_create_records),
        "displayInitSendAttempted": bool(display_payloads),
        "displayInitSendOk": any(int(item.get("ret") or 0) == 0 for item in display_payloads),
        "displayPathObserved": False,
        "verifiedRunPassed": False,
    }
    if not milestones["channelCreateOk"]:
        stage = "channel_create_pending"
        next_step = "Fix or validate native ZIME channel context until ZIME_CreateDataChannel returns 0."
    elif not milestones["nativePacketOutSeen"]:
        stage = "packet_out_pending"
        next_step = "Run ZIME_DataChannelProcess2 until native packet-out callbacks appear."
    elif udp_enabled and not milestones["nativeUdpSent"]:
        stage = "udp_send_pending"
        next_step = "Send the native packet-out through the configured UDP transport."
    elif udp_enabled and not milestones["nativeUdpReceived"]:
        stage = "udp_response_pending"
        next_step = "Wait for a real RAP/ZIME UDP response and verify the wrapper/target parameters."
    elif milestones["nativeUdpReceived"] and not milestones["receiveDataOk"]:
        stage = "receive_data_pending"
        next_step = "Feed the received datagram through ZIME_ReceiveData and continue DataChannelProcess2."
    elif not milestones["nativeChannelCreated"]:
        stage = "native_channel_created_pending"
        next_step = "Continue the ZIME handshake until native_channel_created callback is observed."
    elif not milestones["streamCreateOk"]:
        stage = "stream_create_pending"
        next_step = "Create a user stream after the native channel is active."
    elif not milestones["displayInitSendOk"]:
        stage = "display_init_pending"
        next_step = "Send SPICE DISPLAY_INIT on the active user stream."
    else:
        stage = "display_path_pending"
        next_step = "Observe SURFACE_CREATE/DRAW_COPY/MARK and prove the run with verified-run."
    milestones["stage"] = stage
    milestones["nextRequiredMilestone"] = next_step
    return milestones


class NativeUdpTransport:
    """Optional UDP bridge for native packet-out callbacks.

    This is still research plumbing.  It lets the native ZIME engine own packet
    protection while Python supplies the external datagram transport.
    """

    def __init__(
        self,
        target=None,
        *,
        read_timeout=DEFAULT_UDP_READ_TIMEOUT,
        receive_limit=DEFAULT_UDP_RECEIVE_LIMIT,
        payload_mode="raw",
        rap_tunnel_id=None,
        rap_frame_type=0x81,
        rap_flags=0,
        rap_field06=0,
        rap_word08=0,
        rap_word12=0,
        rap_header16_prefix=None,
        rap_post_length=None,
        rap_payload_envelope=RAP_PAYLOAD_ENVELOPE_RAW,
        rap_send_templates=None,
        rap_template_mode=RAP_TEMPLATE_MODE_AUTO,
        packet_out_iov_mode=PACKET_OUT_IOV_MODE_CONCAT,
        ztec_prime=False,
        ztec_host=None,
        ztec_port=None,
        ztec_timeout=None,
        ztec_marker=0x04A0,
    ):
        self.target = _parse_udp_target(target)
        self.enabled = self.target is not None
        self.read_timeout = float(read_timeout)
        self.receive_limit = int(receive_limit)
        self.payload_mode = str(payload_mode or "raw").lower()
        self.rap_frame_type = int(rap_frame_type)
        self.rap_flags = int(rap_flags)
        self.rap_field06 = int(rap_field06)
        self.rap_word08 = int(rap_word08)
        self.rap_word12 = int(rap_word12)
        self.rap_header16_prefix = _fixed_hex_or_bytes(rap_header16_prefix, 3, "RAP header16 prefix")
        self.rap_post_length = _fixed_hex_or_bytes(rap_post_length, 3, "RAP post-length bytes")
        self.rap_payload_envelope = _normalize_rap_payload_envelope(rap_payload_envelope)
        self.rap_send_templates = _normalize_rap_send_templates(rap_send_templates)
        self.rap_template_mode = _normalize_rap_template_mode(rap_template_mode)
        self._rap_template_cursor = 0
        self._rap_template_kind_cursors = {}
        self.packet_out_iov_mode = _normalize_packet_out_iov_mode(packet_out_iov_mode)
        self.ztec_prime = bool(ztec_prime)
        self.ztec_host = ztec_host
        self.ztec_port = int(ztec_port) if ztec_port is not None else None
        self.ztec_timeout = self.read_timeout if ztec_timeout is None else float(ztec_timeout)
        self.ztec_marker = int(ztec_marker)
        self.rap_tunnel_id = None
        self.sock = None
        self.sent_packets = 0
        self.received_packets = 0
        self.ztec_sent = 0
        self.ztec_ack_received = 0
        if self.payload_mode not in {"raw", "rap"}:
            raise core.CmccError(f"unsupported UDP transport payload mode: {payload_mode}")
        if self.payload_mode == "rap":
            if not rap_tunnel_id:
                raise core.CmccError("--udp-rap-tunnel-id is required when --udp-transport-mode=rap")
            try:
                self.rap_tunnel_id = bytes.fromhex(str(rap_tunnel_id)) if isinstance(rap_tunnel_id, str) else bytes(rap_tunnel_id)
            except ValueError as err:
                raise core.CmccError(f"invalid RAP tunnel id: {rap_tunnel_id}") from err
            if len(self.rap_tunnel_id) != 4:
                raise core.CmccError("RAP tunnel id must be exactly 4 bytes")
        if self.enabled:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(self.read_timeout)

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def summary(self):
        return {
            "enabled": self.enabled,
            "target": _format_udp_target(self.target) if self.enabled else None,
            "payloadMode": self.payload_mode,
            "rapTunnelIdHex": self.rap_tunnel_id.hex() if self.rap_tunnel_id else None,
            "rapFrameType": self.rap_frame_type,
            "rapFlags": self.rap_flags,
            "rapField06": self.rap_field06,
            "rapWord08": self.rap_word08,
            "rapWord12": self.rap_word12,
            "rapHeader16PrefixHex": self.rap_header16_prefix.hex(),
            "rapPostLengthHex": self.rap_post_length.hex(),
            "rapPayloadEnvelope": self.rap_payload_envelope,
            "rapTemplateMode": self.rap_template_mode,
            "rapSendTemplateCount": len(self.rap_send_templates),
            "packetOutIovMode": self.packet_out_iov_mode,
            "readTimeout": self.read_timeout,
            "receiveLimit": self.receive_limit,
            "ztecPrime": self.ztec_prime,
            "ztecHostPresent": bool(self.ztec_host),
            "ztecPortPresent": self.ztec_port is not None,
            "ztecSent": self.ztec_sent,
            "ztecAckReceived": self.ztec_ack_received,
            "sentPackets": self.sent_packets,
            "receivedPackets": self.received_packets,
            "proof": "transport_plumbing_only",
        }

    def prime_ztec_keepalive(self, records, *, phase="udp_ztec_prime"):
        if not self.enabled or not self.ztec_prime:
            return None
        host = self.ztec_host or self.target[0]
        port = int(self.ztec_port or self.target[1])
        sequence = self.ztec_sent & 0xFFFF
        nonce = time.time_ns() & 0xFFFF
        tail = (time.time_ns() >> 16) & 0xFFFFFFFF
        record = {
            "event": "native_udp_ztec_prime",
            "phase": phase,
            "target": _format_udp_target(self.target),
            "ztecHostPresent": bool(host),
            "ztecPortPresent": True,
            "ackReceived": False,
            "traceOnly": True,
        }
        try:
            request = rap_zime.encode_ztec_keepalive_request(
                host,
                port,
                sequence,
                nonce,
                marker=self.ztec_marker,
                tail=tail,
            )
            sent = self.sock.sendto(request, self.target)
            self.ztec_sent += 1
            record["bytesSent"] = sent
        except Exception as err:
            record["error"] = f"{type(err).__name__}: {err}"
            records.append(record)
            return record
        old_timeout = self.sock.gettimeout()
        self.sock.settimeout(self.ztec_timeout)
        try:
            response, remote = self.sock.recvfrom(65535)
        except socket.timeout:
            record["error"] = "timeout waiting for ZTEC ack"
        except OSError as err:
            record["error"] = f"{type(err).__name__}: {err}"
        else:
            record.update({
                "responseRemote": f"{remote[0]}:{remote[1]}",
                "responseBytes": len(response),
                "responseKind": rap_zime.classify_payload(response),
                "responseHexPrefix": response[:80].hex(),
            })
            if rap_zime.looks_like_ztec_ack(response):
                self.ztec_ack_received += 1
                record["ackReceived"] = True
        finally:
            self.sock.settimeout(old_timeout)
        records.append(record)
        return record

    def _rap_payload_from_native(self, payload):
        payload = bytes(payload or b"")
        summary = {
            "mode": self.rap_payload_envelope,
            "inputLen": len(payload),
            "reserve4Stripped": False,
            "reserve4ReaddedOnReceive": False,
        }
        if self.rap_payload_envelope == RAP_PAYLOAD_ENVELOPE_RAW:
            summary["wirePayloadLen"] = len(payload)
            return payload, summary
        if self.rap_payload_envelope == RAP_PAYLOAD_ENVELOPE_LEN16:
            wire_payload = _len16_prefixed(payload)
            summary.update({
                "declaredLen": len(payload),
                "wirePayloadLen": len(wire_payload),
            })
            return wire_payload, summary
        if self.rap_payload_envelope == RAP_PAYLOAD_ENVELOPE_STRIP_RESERVE4_LEN16:
            if len(payload) < 4:
                raise core.CmccError("strip-reserve4-len16 requires a native payload of at least 4 bytes")
            stripped = payload[4:]
            wire_payload = _len16_prefixed(stripped)
            summary.update({
                "reserve4Stripped": True,
                "declaredLen": len(stripped),
                "wirePayloadLen": len(wire_payload),
            })
            return wire_payload, summary
        raise core.CmccError(f"unsupported RAP payload envelope: {self.rap_payload_envelope}")

    def _native_payload_from_rap_payload(self, payload):
        payload = bytes(payload or b"")
        summary = {
            "mode": self.rap_payload_envelope,
            "inputLen": len(payload),
            "reserve4Stripped": False,
            "reserve4ReaddedOnReceive": False,
        }
        if self.rap_payload_envelope == RAP_PAYLOAD_ENVELOPE_RAW:
            summary["nativePayloadLen"] = len(payload)
            return payload, summary
        if len(payload) < 2:
            raise core.CmccError("RAP payload envelope is incomplete")
        declared = int.from_bytes(payload[:2], "little")
        protected = payload[2:]
        if declared > len(protected):
            raise core.CmccError("RAP payload envelope length exceeds protected payload")
        if self.rap_payload_envelope == RAP_PAYLOAD_ENVELOPE_LEN16:
            summary.update({
                "declaredLen": declared,
                "protectedPayloadLen": len(protected),
                "overheadBytes": len(protected) - declared,
                "nativePayloadLen": len(protected),
            })
            return protected, summary
        if self.rap_payload_envelope == RAP_PAYLOAD_ENVELOPE_STRIP_RESERVE4_LEN16:
            native_payload = b"\x00\x00\x00\x00" + protected
            summary.update({
                "reserve4Stripped": True,
                "reserve4ReaddedOnReceive": True,
                "declaredLen": declared,
                "protectedPayloadLen": len(protected),
                "overheadBytes": len(protected) - declared,
                "nativePayloadLen": len(native_payload),
            })
            return native_payload, summary
        raise core.CmccError(f"unsupported RAP payload envelope: {self.rap_payload_envelope}")

    def _select_rap_template(self, payload):
        if self.payload_mode != "rap" or not self.rap_send_templates:
            return None, {
                "mode": RAP_TEMPLATE_MODE_STATIC,
                "source": "static",
                "payloadKind": _payload_kind(payload),
            }
        requested_mode = self.rap_template_mode
        mode = RAP_TEMPLATE_MODE_PAYLOAD_KIND if requested_mode == RAP_TEMPLATE_MODE_AUTO else requested_mode
        payload_kind = _payload_kind(payload)
        payload_kind_candidates = _payload_kind_template_candidates(payload_kind)
        template_index = None
        if mode == RAP_TEMPLATE_MODE_STATIC:
            return None, {
                "mode": requested_mode,
                "source": "static",
                "payloadKind": payload_kind,
            }
        if mode == RAP_TEMPLATE_MODE_PAYLOAD_KIND:
            matches = [
                index for index, template in enumerate(self.rap_send_templates)
                if template.get("payloadKind") in payload_kind_candidates
            ]
            if matches:
                cursor = self._rap_template_kind_cursors.get(payload_kind, 0)
                template_index = matches[cursor % len(matches)]
                self._rap_template_kind_cursors[payload_kind] = cursor + 1
        if template_index is None:
            template_index = self._rap_template_cursor % len(self.rap_send_templates)
            self._rap_template_cursor += 1
        template = self.rap_send_templates[template_index]
        return template, {
            "mode": requested_mode,
            "effectiveMode": mode,
            "source": "runnerInput.rapDataFrameSendTemplates",
            "templateListIndex": template_index,
            "templateSampleIndex": template.get("index"),
            "payloadKind": payload_kind,
            "payloadKindCandidates": payload_kind_candidates,
            "templatePayloadKind": template.get("payloadKind"),
            "templatePayloadLength": template.get("payloadLength"),
            "zimePayloadEnvelopeObserved": template.get("zimePayloadEnvelopeObserved"),
            "flags": template.get("flags"),
            "field06": template.get("field06"),
            "word08": template.get("word08"),
            "word12": template.get("word12"),
            "header16PrefixHex": template.get("header16PrefixHex"),
            "postLengthHex": template.get("postLengthHex"),
            "traceOnly": True,
        }

    def _wire_payload(self, payload):
        payload = bytes(payload or b"")
        if self.payload_mode == "raw":
            return payload, payload, {
                "mode": RAP_PAYLOAD_ENVELOPE_RAW,
                "inputLen": len(payload),
                "wirePayloadLen": len(payload),
                "nativePayloadLen": len(payload),
            }
        rap_payload, envelope = self._rap_payload_from_native(payload)
        template, template_selection = self._select_rap_template(payload)
        frame_type = self.rap_frame_type
        flags = self.rap_flags
        field06 = self.rap_field06
        word08 = self.rap_word08
        word12 = self.rap_word12
        header16_prefix = self.rap_header16_prefix
        post_length = self.rap_post_length
        if template:
            frame_type = template["frameType"]
            flags = template["flags"]
            field06 = template["field06"]
            word08 = template["word08"]
            word12 = template["word12"]
            header16_prefix = template["header16Prefix"]
            post_length = template["postLength"]
        envelope["rapTemplateSelection"] = template_selection
        wire = rap_zime.encode_rap_data_frame(
            self.rap_tunnel_id,
            frame_type,
            flags,
            field06,
            word08,
            word12,
            header16_prefix,
            payload=rap_payload,
            post_length=post_length,
        )
        return wire, rap_payload, envelope

    def _native_payloads_from_wire(self, packet):
        packet = bytes(packet or b"")
        if self.payload_mode == "raw":
            return [{"payload": packet, "summary": None}]
        frames = rap_zime.decode_rap_frames(packet)
        items = []
        for frame in frames:
            rap_payload = frame.get("payload") or b""
            native_payload, envelope = self._native_payload_from_rap_payload(rap_payload)
            items.append({
                "payload": native_payload,
                "summary": {
                    "tunnelIdHex": frame.get("tunnelIdHex"),
                    "frameType": frame.get("frameType"),
                    "payloadLength": frame.get("payloadLength"),
                    "payloadKind": rap_zime.classify_payload(rap_payload),
                    "rapPayloadEnvelope": envelope,
                },
            })
        return items

    def send_payload(self, payload, records, *, source_event, channel_id=None, spec_index=None, segment_index=None, segment_count=None):
        if not self.enabled:
            return None
        payload = bytes(payload or b"")
        try:
            wire, wire_payload, envelope = self._wire_payload(payload)
            sent = self.sock.sendto(wire, self.target)
            self.sent_packets += 1
            record = {
                "event": "native_udp_send",
                "sourceEvent": source_event,
                "channelId": int(channel_id) if channel_id is not None else None,
                "specIndex": spec_index,
                "segmentIndex": segment_index,
                "segmentCount": segment_count,
                "target": _format_udp_target(self.target),
                "payloadMode": self.payload_mode,
                "rapPayloadEnvelope": self.rap_payload_envelope if self.payload_mode == "rap" else None,
                "rapTemplateSelection": (envelope or {}).get("rapTemplateSelection"),
                "payloadEnvelope": envelope,
                "payloadLen": len(payload),
                "wirePayloadLen": len(wire_payload),
                "wireLen": len(wire),
                "bytesSent": sent,
                "payloadKind": _payload_kind(payload),
                "wirePayloadKind": _payload_kind(wire_payload),
                "wireKind": rap_zime.classify_payload(wire) if self.payload_mode == "rap" else _payload_kind(wire),
                "payloadHexPrefix": payload[:80].hex(),
                "traceOnly": True,
            }
        except Exception as err:
            record = {
                "event": "native_udp_send_error",
                "sourceEvent": source_event,
                "channelId": int(channel_id) if channel_id is not None else None,
                "specIndex": spec_index,
                "segmentIndex": segment_index,
                "segmentCount": segment_count,
                "target": _format_udp_target(self.target),
                "payloadMode": self.payload_mode,
                "rapPayloadEnvelope": self.rap_payload_envelope if self.payload_mode == "rap" else None,
                "error": f"{type(err).__name__}: {err}",
                "traceOnly": True,
            }
        records.append(record)
        return record

    def receive_native_payloads(self, records, *, phase):
        if not self.enabled:
            return []
        received = []
        for _index in range(max(0, self.receive_limit)):
            try:
                packet, remote = self.sock.recvfrom(65535)
            except socket.timeout:
                break
            except OSError as err:
                records.append({
                    "event": "native_udp_receive_error",
                    "phase": phase,
                    "error": f"{type(err).__name__}: {err}",
                    "traceOnly": True,
                })
                break
            self.received_packets += 1
            base_record = {
                "event": "native_udp_receive",
                "phase": phase,
                "remote": f"{remote[0]}:{remote[1]}",
                "payloadMode": self.payload_mode,
                "rapPayloadEnvelope": self.rap_payload_envelope if self.payload_mode == "rap" else None,
                "wireLen": len(packet),
                "wireKind": rap_zime.classify_payload(packet) if self.payload_mode == "rap" else _payload_kind(packet),
                "wireHexPrefix": packet[:80].hex(),
                "traceOnly": True,
            }
            try:
                native_items = self._native_payloads_from_wire(packet)
            except Exception as err:
                base_record["error"] = f"{type(err).__name__}: {err}"
                records.append(base_record)
                continue
            if not native_items:
                base_record["nativePayloadCount"] = 0
                records.append(base_record)
                continue
            for item_index, item in enumerate(native_items):
                payload = item["payload"]
                record = dict(base_record)
                record.update({
                    "nativePayloadIndex": item_index,
                    "nativePayloadCount": len(native_items),
                    "payloadLen": len(payload),
                    "payloadKind": _payload_kind(payload),
                    "payloadHexPrefix": payload[:80].hex(),
                })
                if item.get("summary"):
                    record["rapFrame"] = item["summary"]
                records.append(record)
                received.append(payload)
        return received


class ZimeNativeCallbacks:
    def __init__(self, *, max_dump=4096, read_iov_payload=False, udp_transport=None):
        self.max_dump = int(max_dump)
        self.read_iov_payload = bool(read_iov_payload)
        self.udp_transport = udp_transport
        self.records = []
        self._transport_send = TransportSendCallback(self._on_transport_send)
        self._transport_batch = TransportBatchCallback(self._on_transport_batch)
        self._channel_data = ChannelDataCallback(self._on_channel_data)
        self._channel_created = ChannelCreatedCallback(self._on_channel_created)
        self._channel_destroyed = ChannelDestroyedCallback(self._on_channel_destroyed)
        self._channel_stream_blocked = ChannelStreamBlockedCallback(self._on_channel_stream_blocked)
        self.transport_table = (ctypes.c_void_p * 8)()
        self.transport_table[0] = ctypes.cast(self._transport_send, ctypes.c_void_p).value
        self.transport_table[1] = ctypes.cast(self._transport_batch, ctypes.c_void_p).value
        self.callback_table = (ctypes.c_void_p * 8)()
        self.callback_table[0] = ctypes.cast(self._channel_data, ctypes.c_void_p).value
        self.callback_table[1] = ctypes.cast(self._channel_created, ctypes.c_void_p).value
        self.callback_table[2] = ctypes.cast(self._channel_destroyed, ctypes.c_void_p).value
        self.callback_table[5] = ctypes.cast(self._channel_stream_blocked, ctypes.c_void_p).value

    def _dump_ptr(self, ptr, length):
        ptr_value = _ptr_value(ptr)
        length = int(length or 0)
        if not ptr_value or length <= 0:
            return b""
        return ctypes.string_at(ptr_value, min(length, self.max_dump))

    def _augment_iov_payload(self, specs):
        if not self.read_iov_payload:
            return specs
        iov_size = ctypes.sizeof(Iovec)
        for spec in specs:
            try:
                iov_ptr = int(str(spec.get("iov") or "0"), 16)
                iov_count = int(spec.get("iovCount") or 0)
            except (TypeError, ValueError):
                continue
            if not iov_ptr or iov_count <= 0 or iov_count > 64:
                continue
            first = Iovec.from_address(iov_ptr)
            prefix = self._dump_ptr(first.iov_base, first.iov_len)
            spec["firstIovBase"] = _ptr_text(first.iov_base)
            spec["firstIovLen"] = int(first.iov_len)
            spec["firstIovPayloadKind"] = _payload_kind(prefix)
            spec["firstIovHexPrefix"] = prefix[: self.max_dump].hex()
            captured = bytearray()
            total_len = 0
            for index in range(iov_count):
                iov = Iovec.from_address(iov_ptr + index * iov_size)
                iov_len = int(iov.iov_len or 0)
                total_len += max(0, iov_len)
                if len(captured) >= self.max_dump:
                    continue
                chunk = self._dump_ptr(iov.iov_base, min(iov_len, self.max_dump - len(captured)))
                captured.extend(chunk)
            spec["iovTotalLen"] = total_len
            spec["iovPayloadCapturedLen"] = len(captured)
            spec["iovPayloadTruncated"] = len(captured) < total_len
            spec["iovPayloadKind"] = _payload_kind(captured)
            spec["iovPayloadHex"] = bytes(captured).hex()
            segments = []
            captured_so_far = 0
            for index in range(iov_count):
                iov = Iovec.from_address(iov_ptr + index * iov_size)
                iov_len = max(0, int(iov.iov_len or 0))
                remaining = max(0, self.max_dump - captured_so_far)
                capture_len = min(iov_len, remaining)
                chunk = self._dump_ptr(iov.iov_base, capture_len)
                captured_so_far += len(chunk)
                segments.append({
                    "index": index,
                    "len": iov_len,
                    "capturedLen": len(chunk),
                    "truncated": len(chunk) < iov_len,
                    "payloadKind": _payload_kind(chunk),
                    "payloadHex": chunk.hex() if len(chunk) == iov_len else "",
                    "traceOnly": True,
                })
            spec["iovPayloadSegments"] = segments
        return specs

    def _on_transport_send(self, socket_param, channel_id, buf, length):
        data = self._dump_ptr(buf, length)
        self.records.append({
            "event": "native_transport_send",
            "channelId": int(channel_id),
            "len": int(length),
            "payloadKind": _payload_kind(data),
            "hexPrefix": data.hex(),
            "traceOnly": True,
        })
        if self.udp_transport and self.udp_transport.enabled:
            self.udp_transport.send_payload(
                data,
                self.records,
                source_event="native_transport_send",
                channel_id=channel_id,
            )
        return 0

    def _on_transport_batch(self, packet_specs, count):
        count_int = int(count or 0)
        raw = self._dump_ptr(packet_specs, count_int * zime_probe.ZIME_PACKET_OUT_SPEC_SIZE)
        specs = zime_probe.decode_zime_packet_specs(raw, count=count_int, base_ptr=_ptr_text(packet_specs))
        specs = self._augment_iov_payload(specs)
        self.records.append({
            "event": "native_transport_batch",
            "count": count_int,
            "packetSpecs": specs,
            "traceOnly": True,
        })
        if self.udp_transport and self.udp_transport.enabled:
            for spec in specs:
                if self.udp_transport.packet_out_iov_mode == PACKET_OUT_IOV_MODE_SPLIT:
                    segments = list(spec.get("iovPayloadSegments") or [])
                    if not segments:
                        self.records.append({
                            "event": "native_udp_send_skipped",
                            "sourceEvent": "native_transport_batch",
                            "specIndex": spec.get("index"),
                            "reason": "iov segments not captured",
                            "traceOnly": True,
                        })
                        continue
                    for segment in segments:
                        if segment.get("truncated"):
                            self.records.append({
                                "event": "native_udp_send_skipped",
                                "sourceEvent": "native_transport_batch",
                                "specIndex": spec.get("index"),
                                "segmentIndex": segment.get("index"),
                                "reason": "iov segment payload truncated",
                                "traceOnly": True,
                            })
                            continue
                        hex_value = segment.get("payloadHex")
                        if not hex_value:
                            self.records.append({
                                "event": "native_udp_send_skipped",
                                "sourceEvent": "native_transport_batch",
                                "specIndex": spec.get("index"),
                                "segmentIndex": segment.get("index"),
                                "reason": "iov segment payload not captured",
                                "traceOnly": True,
                            })
                            continue
                        try:
                            payload = bytes.fromhex(hex_value)
                        except ValueError:
                            self.records.append({
                                "event": "native_udp_send_skipped",
                                "sourceEvent": "native_transport_batch",
                                "specIndex": spec.get("index"),
                                "segmentIndex": segment.get("index"),
                                "reason": "invalid iov segment payload hex",
                                "traceOnly": True,
                            })
                            continue
                        self.udp_transport.send_payload(
                            payload,
                            self.records,
                            source_event="native_transport_batch",
                            spec_index=spec.get("index"),
                            segment_index=segment.get("index"),
                            segment_count=len(segments),
                        )
                    continue
                if spec.get("iovPayloadTruncated"):
                    self.records.append({
                        "event": "native_udp_send_skipped",
                        "sourceEvent": "native_transport_batch",
                        "specIndex": spec.get("index"),
                        "reason": "iov payload truncated",
                        "traceOnly": True,
                    })
                    continue
                hex_value = spec.get("iovPayloadHex")
                if not hex_value:
                    self.records.append({
                        "event": "native_udp_send_skipped",
                        "sourceEvent": "native_transport_batch",
                        "specIndex": spec.get("index"),
                        "reason": "iov payload not captured",
                        "traceOnly": True,
                    })
                    continue
                try:
                    payload = bytes.fromhex(hex_value)
                except ValueError:
                    self.records.append({
                        "event": "native_udp_send_skipped",
                        "sourceEvent": "native_transport_batch",
                        "specIndex": spec.get("index"),
                        "reason": "invalid iov payload hex",
                        "traceOnly": True,
                    })
                    continue
                self.udp_transport.send_payload(
                    payload,
                    self.records,
                    source_event="native_transport_batch",
                    spec_index=spec.get("index"),
                )
        return 0

    def _on_channel_data(self, channel_id, stream_id, buf, length):
        data = self._dump_ptr(buf, length)
        self.records.append({
            "event": "native_channel_data_received",
            "channelId": int(channel_id),
            "streamId": int(stream_id),
            "len": int(length),
            "payloadKind": _payload_kind(data),
            "hexPrefix": data.hex(),
            "traceOnly": True,
        })
        return 0

    def _on_channel_created(self, channel_id, value, status, err, protocol):
        self.records.append({
            "event": "native_channel_created",
            "channelId": int(channel_id),
            "value": int(value),
            "status": int(status),
            "err": int(err),
            "protocol": int(protocol),
        })

    def _on_channel_destroyed(self, channel_id, status, err):
        self.records.append({
            "event": "native_channel_destroyed",
            "channelId": int(channel_id),
            "status": int(status),
            "err": int(err),
        })

    def _on_channel_stream_blocked(self, channel_id, stream_id, blocked, reason):
        self.records.append({
            "event": "native_channel_stream_blocked",
            "channelId": int(channel_id),
            "streamId": int(stream_id),
            "blocked": int(blocked),
            "reason": int(reason),
        })


class ZimeNativeBridge:
    def __init__(self, lib_path=None, loader=ctypes.CDLL):
        self.lib_path = _resolve_lib_path(lib_path)
        if not self.lib_path.exists():
            raise core.CmccError(f"ZIME native library not found: {self.lib_path}")
        self.lib = _bind_library(loader(str(self.lib_path)))

    def run_send_probe(
        self,
        payloads,
        *,
        remote_host="127.0.0.1",
        remote_port=0,
        local_host="0.0.0.0",
        local_port=0,
        opaque=b"\x00\x00\x00\x00",
        protocol=0,
        mtu=DEFAULT_BASE_MTU,
        business_type=1,
        stream_id=DEFAULT_STREAM_ID,
        process_ticks=DEFAULT_PROCESS_TICKS,
        read_iov_payload=False,
        udp_transport_target=None,
        udp_read_timeout=DEFAULT_UDP_READ_TIMEOUT,
        udp_receive_limit=DEFAULT_UDP_RECEIVE_LIMIT,
        udp_process_ticks_after_receive=DEFAULT_UDP_PROCESS_TICKS_AFTER_RECEIVE,
        udp_transport_mode="raw",
        udp_rap_tunnel_id=None,
        udp_rap_flags=0,
        udp_rap_field06=0,
        udp_rap_word08=0,
        udp_rap_word12=0,
        udp_rap_header16_prefix=None,
        udp_rap_post_length=None,
        udp_rap_payload_envelope=RAP_PAYLOAD_ENVELOPE_RAW,
        udp_rap_send_templates=None,
        udp_rap_template_mode=RAP_TEMPLATE_MODE_AUTO,
        udp_packet_out_iov_mode=PACKET_OUT_IOV_MODE_CONCAT,
        wait_channel_created_ticks=DEFAULT_WAIT_CHANNEL_CREATED_TICKS,
        udp_ztec_prime=False,
        udp_ztec_host=None,
        udp_ztec_port=None,
        udp_ztec_timeout=None,
    ):
        udp_transport = NativeUdpTransport(
            udp_transport_target,
            read_timeout=udp_read_timeout,
            receive_limit=udp_receive_limit,
            payload_mode=udp_transport_mode,
            rap_tunnel_id=udp_rap_tunnel_id,
            rap_flags=udp_rap_flags,
            rap_field06=udp_rap_field06,
            rap_word08=udp_rap_word08,
            rap_word12=udp_rap_word12,
            rap_header16_prefix=udp_rap_header16_prefix,
            rap_post_length=udp_rap_post_length,
            rap_payload_envelope=udp_rap_payload_envelope,
            rap_send_templates=udp_rap_send_templates,
            rap_template_mode=udp_rap_template_mode,
            packet_out_iov_mode=udp_packet_out_iov_mode,
            ztec_prime=udp_ztec_prime,
            ztec_host=udp_ztec_host,
            ztec_port=udp_ztec_port,
            ztec_timeout=udp_ztec_timeout,
        )
        callbacks = ZimeNativeCallbacks(
            max_dump=65535 if udp_transport.enabled else 4096,
            read_iov_payload=read_iov_payload or udp_transport.enabled,
            udp_transport=udp_transport,
        )
        calls = []
        payload_reports = []
        engine = self.lib.ZIME_CreateDataEngine()
        calls.append({"function": "ZIME_CreateDataEngine", "retPtr": _ptr_text(engine)})

        def partial_report(ok=False):
            session_owning = bool(udp_transport.enabled)
            report = {
                "ok": bool(ok),
                "researchOnly": True,
                "nativeRun": True,
                "sessionOwning": session_owning,
                "sessionOwningNote": (
                    "UDP-backed native transport may establish or replace a real "
                    "desktop session; treat it as session-owning/顶号 until proven otherwise."
                    if session_owning else None
                ),
                "libPath": str(self.lib_path),
                "calls": calls,
                "payloads": payload_reports,
                "callbackRecords": callbacks.records,
                "udpTransport": udp_transport.summary(),
                "nativeWait": {
                    "processTicks": int(process_ticks),
                    "waitChannelCreatedTicks": int(wait_channel_created_ticks),
                },
                "note": (
                    "Native bridge run used Python external transport callbacks. "
                    "This is not desktop keepalive proof until a real display path "
                    "and verified-run succeed."
                ),
            }
            report["nativeMilestones"] = native_bridge_milestones(report)
            return report

        def fail(message):
            raise core.CmccError(message, response=partial_report(ok=False))

        def process_channel(channel_value, *, phase, tick_count=1):
            if not getattr(self.lib, "ZIME_DataChannelProcess2", None):
                return
            for _index in range(max(0, int(tick_count))):
                events = ctypes.c_uint(0)
                process_ret = self.lib.ZIME_DataChannelProcess2(engine, channel_value, ctypes.byref(events))
                calls.append({
                    "function": "ZIME_DataChannelProcess2",
                    "phase": phase,
                    "ret": int(process_ret),
                    "errorInfo": _error_info(self.lib, process_ret),
                    "events": int(events.value),
                })
                if process_ret != 0:
                    break

        def drain_udp(channel_value, socket_param_ptr, *, phase):
            payloads_from_udp = udp_transport.receive_native_payloads(callbacks.records, phase=phase)
            for payload in payloads_from_udp:
                buf = ctypes.create_string_buffer(payload)
                recv_ret = self.lib.ZIME_ReceiveData(engine, socket_param_ptr, buf, len(payload))
                calls.append({
                    "function": "ZIME_ReceiveData",
                    "phase": phase,
                    "ret": int(recv_ret),
                    "errorInfo": _error_info(self.lib, recv_ret),
                    "len": len(payload),
                    "payloadKind": _payload_kind(payload),
                })
                if recv_ret == 0:
                    process_channel(
                        channel_value,
                        phase="after_udp_receive",
                        tick_count=udp_process_ticks_after_receive,
                    )

        def channel_created_ok(channel_value):
            for item in callbacks.records:
                if item.get("event") != "native_channel_created":
                    continue
                if int(item.get("channelId") or 0) != int(channel_value):
                    continue
                if int(item.get("status") or 0) == 0 and int(item.get("err") or 0) == 0:
                    return True
            return False

        def wait_for_channel_created(channel_value, socket_param_ptr):
            wait_ticks = max(0, int(wait_channel_created_ticks))
            if wait_ticks <= 0:
                calls.append({
                    "function": "wait_native_channel_created",
                    "ret": 0 if channel_created_ok(channel_value) else 1,
                    "skipped": True,
                    "channelId": int(channel_value),
                    "waitTicks": 0,
                })
                return True
            completed = channel_created_ok(channel_value)
            ticks_used = 0
            while not completed and ticks_used < wait_ticks:
                process_channel(channel_value, phase="wait_channel_created", tick_count=1)
                drain_udp(channel_value, socket_param_ptr, phase="wait_channel_created")
                ticks_used += 1
                completed = channel_created_ok(channel_value)
            calls.append({
                "function": "wait_native_channel_created",
                "ret": 0 if completed else 1,
                "channelId": int(channel_value),
                "waitTicks": ticks_used,
                "maxWaitTicks": wait_ticks,
            })
            return completed

        try:
            if not engine:
                fail("ZIME_CreateDataEngine returned NULL")

            init_param = make_init_param()
            ret = self.lib.ZIME_Init(engine, ctypes.byref(init_param))
            calls.append({"function": "ZIME_Init", "ret": int(ret)})
            if ret != 0:
                fail(f"ZIME_Init failed: {ret}")

            ret = self.lib.ZIME_SetDataChannelCallback(engine, callbacks.callback_table)
            calls.append({"function": "ZIME_SetDataChannelCallback", "ret": int(ret)})
            if ret != 0:
                fail(f"ZIME_SetDataChannelCallback failed: {ret}")

            ret = self.lib.ZIME_SetDataExternalTransport(engine, callbacks.transport_table)
            calls.append({"function": "ZIME_SetDataExternalTransport", "ret": int(ret)})
            if ret != 0:
                fail(f"ZIME_SetDataExternalTransport failed: {ret}")
            udp_transport.prime_ztec_keepalive(callbacks.records, phase="before_create_channel")

            context, keepalive = make_channel_context(
                local_host=local_host,
                local_port=local_port,
                remote_host=remote_host,
                remote_port=remote_port,
                opaque=opaque,
                protocol=protocol,
                mtu=mtu,
                business_type=business_type,
            )
            socket_param_ptr = ctypes.c_void_p(ctypes.addressof(context.socketParam))
            calls.append({
                "function": "make_channel_context",
                "local": f"{local_host}:{int(local_port)}",
                "remote": f"{remote_host}:{int(remote_port)}",
                "protocol": int(protocol),
                "mtu": int(mtu),
                "businessType": int(business_type),
                "opaqueLen": len(bytes(opaque or b"")),
                "opaqueHex": bytes(opaque or b"").hex(),
                "socketParamPtr": _ptr_text(socket_param_ptr),
            })
            channel_id = ctypes.c_long(0)
            ret = self.lib.ZIME_CreateDataChannel(engine, ctypes.byref(context), ctypes.byref(channel_id))
            calls.append({
                "function": "ZIME_CreateDataChannel",
                "ret": int(ret),
                "errorInfo": _error_info(self.lib, ret),
                "channelId": int(channel_id.value),
            })
            if ret != 0:
                fail(f"ZIME_CreateDataChannel failed: {ret}")

            for _index in range(max(0, int(process_ticks))):
                process_channel(channel_id.value, phase="after_create_channel", tick_count=1)
                drain_udp(channel_id.value, socket_param_ptr, phase="after_create_channel")

            if not wait_for_channel_created(channel_id.value, socket_param_ptr):
                fail("native_channel_created was not observed before stream creation")

            stream_param = make_stream_param()
            stream_id_ref = ctypes.c_long(int(stream_id))
            ret = self.lib.ZIME_CreateDataStream(engine, channel_id.value, ctypes.byref(stream_id_ref), ctypes.byref(stream_param))
            calls.append({
                "function": "ZIME_CreateDataStream",
                "ret": int(ret),
                "errorInfo": _error_info(self.lib, ret),
                "requestedStreamId": int(stream_id),
                "streamId": int(stream_id_ref.value),
            })
            if ret != 0:
                fail(f"ZIME_CreateDataStream failed: {ret}")

            buffers = []
            for payload in payloads:
                raw = bytes(payload)
                buf = ctypes.create_string_buffer(raw)
                buffers.append(buf)
                ret = self.lib.ZIME_SendData(engine, channel_id.value, stream_id_ref.value, buf, len(raw))
                payload_reports.append({
                    "len": len(raw),
                    "payloadKind": _payload_kind(raw),
                    "ret": int(ret),
                    "errorInfo": _error_info(self.lib, ret),
                    "hexPrefix": raw[:64].hex(),
                })
                process_channel(channel_id.value, phase="after_send_data", tick_count=1)
                drain_udp(channel_id.value, socket_param_ptr, phase="after_send_data")
            # Keep ctypes-owned sockaddr and payload buffers alive until callbacks finish.
            _keepalive = (callbacks, keepalive, buffers)
            report = partial_report(ok=True)
            report["keepaliveRefs"] = len(_keepalive)
            report["udpTransport"] = udp_transport.summary()
            report["nativeMilestones"] = native_bridge_milestones(report)
            return report
        finally:
            udp_transport.close()


def run_research_probe(
    *,
    lib_path=None,
    payloads=None,
    allow_native_run=False,
    inspect_only=False,
    remote_host="127.0.0.1",
    remote_port=0,
    local_host="0.0.0.0",
    local_port=0,
    opaque=b"\x00\x00\x00\x00",
    protocol=0,
    mtu=DEFAULT_BASE_MTU,
    business_type=1,
    stream_id=DEFAULT_STREAM_ID,
    process_ticks=DEFAULT_PROCESS_TICKS,
    read_iov_payload=False,
    udp_transport_target=None,
    udp_read_timeout=DEFAULT_UDP_READ_TIMEOUT,
    udp_receive_limit=DEFAULT_UDP_RECEIVE_LIMIT,
    udp_process_ticks_after_receive=DEFAULT_UDP_PROCESS_TICKS_AFTER_RECEIVE,
    udp_transport_mode="raw",
    udp_rap_tunnel_id=None,
    udp_rap_flags=0,
    udp_rap_field06=0,
    udp_rap_word08=0,
    udp_rap_word12=0,
    udp_rap_header16_prefix=None,
    udp_rap_post_length=None,
    udp_rap_payload_envelope=RAP_PAYLOAD_ENVELOPE_RAW,
    udp_rap_send_templates=None,
    udp_rap_template_mode=RAP_TEMPLATE_MODE_AUTO,
    udp_packet_out_iov_mode=PACKET_OUT_IOV_MODE_CONCAT,
    wait_channel_created_ticks=DEFAULT_WAIT_CHANNEL_CREATED_TICKS,
    udp_ztec_prime=False,
    udp_ztec_host=None,
    udp_ztec_port=None,
    udp_ztec_timeout=None,
    report_file=None,
):
    payloads = [bytes(item) for item in (payloads or [])]
    inspection = inspect_library(lib_path)
    report = {
        "ok": bool(inspection.get("ok")),
        "researchOnly": True,
        "nativeRun": False,
        "sessionOwning": bool(udp_transport_target),
        "sessionOwningNote": (
            "UDP-backed native transport may establish or replace a real desktop "
            "session; treat it as session-owning/顶号 until proven otherwise."
            if udp_transport_target else None
        ),
        "inspection": inspection,
        "payloadCount": len(payloads),
        "error": inspection.get("error"),
        "nextStep": (
            "Pass --allow-native-run for an offline fake-transport experiment or "
            "combine it with --udp-transport-target for explicit UDP-backed "
            "transport research. A successful bridge run still must be followed "
            "by protocol-run and verified-run."
        ),
    }
    if inspect_only or not allow_native_run or not inspection.get("ok"):
        if allow_native_run and not inspection.get("ok"):
            report["error"] = inspection.get("error") or "inspection_failed"
        elif not allow_native_run and not inspect_only:
            report["error"] = "native_run_disabled_by_default"
        _write_report(report, report_file)
        return report

    bridge = ZimeNativeBridge(lib_path)
    try:
        native_report = bridge.run_send_probe(
            payloads,
            remote_host=remote_host,
            remote_port=remote_port,
            local_host=local_host,
            local_port=local_port,
            opaque=opaque,
            protocol=protocol,
            mtu=mtu,
            business_type=business_type,
            stream_id=stream_id,
            process_ticks=process_ticks,
            read_iov_payload=read_iov_payload,
            udp_transport_target=udp_transport_target,
            udp_read_timeout=udp_read_timeout,
            udp_receive_limit=udp_receive_limit,
            udp_process_ticks_after_receive=udp_process_ticks_after_receive,
            udp_transport_mode=udp_transport_mode,
            udp_rap_tunnel_id=udp_rap_tunnel_id,
            udp_rap_flags=udp_rap_flags,
            udp_rap_field06=udp_rap_field06,
            udp_rap_word08=udp_rap_word08,
            udp_rap_word12=udp_rap_word12,
            udp_rap_header16_prefix=udp_rap_header16_prefix,
            udp_rap_post_length=udp_rap_post_length,
            udp_rap_payload_envelope=udp_rap_payload_envelope,
            udp_rap_send_templates=list(udp_rap_send_templates or []),
            udp_rap_template_mode=udp_rap_template_mode,
            udp_packet_out_iov_mode=udp_packet_out_iov_mode,
            wait_channel_created_ticks=wait_channel_created_ticks,
            udp_ztec_prime=udp_ztec_prime,
            udp_ztec_host=udp_ztec_host,
            udp_ztec_port=udp_ztec_port,
            udp_ztec_timeout=udp_ztec_timeout,
        )
        report.update(native_report)
        report.setdefault("sessionOwning", bool(udp_transport_target))
        report["error"] = None
    except core.CmccError as err:
        if isinstance(err.response, dict):
            report.update(err.response)
        report["ok"] = False
        report["nativeRun"] = True
        report["error"] = f"{type(err).__name__}: {err}"
    except Exception as err:
        report["ok"] = False
        report["nativeRun"] = True
        report["error"] = f"{type(err).__name__}: {err}"
    _write_report(report, report_file)
    return report


def _write_report(report, report_file=None):
    core.write_private_json_report(report, report_file)


def native_transport_payloads(report, *, require_complete=True):
    """Extract captured native packet-out payloads from a bridge report."""
    payloads = []
    for record in (report or {}).get("callbackRecords") or []:
        if record.get("event") != "native_transport_batch":
            continue
        for spec in record.get("packetSpecs") or []:
            if require_complete and spec.get("iovPayloadTruncated"):
                continue
            hex_value = spec.get("iovPayloadHex")
            if not hex_value:
                continue
            try:
                payloads.append(bytes.fromhex(hex_value))
            except ValueError:
                continue
    return payloads
