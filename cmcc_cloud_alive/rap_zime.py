"""RAP/ZIME transport packet helpers for the family Linux route.

These helpers are intentionally conservative.  They decode packet shapes that
were observed in the official Linux-client trace, but they do not claim the full
RAP/ZIME protocol is known yet.
"""

import json
import os
import shutil
import socket
import subprocess
from collections import Counter
from pathlib import Path
import ipaddress
import struct
import time
import urllib.parse

from . import core


ZTEC_MAGIC = b"ZTEC"
ZTEC_KEEPALIVE_REQUEST_SIZE = 26
ZTEC_KEEPALIVE_ACK_SIZE = 14
RAP_MIN_HEADER_SIZE = 22
RAP_DATA_HEADER_SIZE = 24
RAP_PAYLOAD_LENGTH_OFFSET = 19
LOCAL_SPICE_CLIENT_HEADER_SIZE = 4
FRESH_CMD26_COMMAND = 0x1A
FRESH_CMD26_CHANNEL_PREFIX = 0
FRESH_CMD26_BODY_LEN = 156
FRESH_CMD26_WIRE_LEN = FRESH_CMD26_BODY_LEN + 4
FRESH_CMD26_DEST_PORT_OFFSET = 0
FRESH_CMD26_LINK_PRIORITY_OFFSET = 2
FRESH_CMD26_LINK_TYPE_OFFSET = 3
FRESH_CMD26_DEST_IP_OFFSET = 4
FRESH_CMD26_IPV6_OFFSET = 8
FRESH_CMD26_SERIAL_NUM_OFFSET = 24
FRESH_CMD26_VM_UUID_OFFSET = 40
FRESH_CMD26_PROTOCOL_TYPE_OFFSET = 77
FRESH_CMD26_BE_EMERGENCY_OFFSET = 78
FRESH_CMD26_BW_CTRL_OFFSET = 79
FRESH_CMD26_TBW_CTRL_OFFSET = 81
FRESH_CMD26_FLAG_OFFSET = 83
FRESH_CMD26_CHANNEL_TYPE_OFFSET = 84
FRESH_CMD26_EXTEND_OFFSET = 88
FRESH_CMD26_OTLP_TRACE_ID_OFFSET = 104
FRESH_CMD26_OTLP_TRACE_ID_SIZE = 33
FRESH_CMD26_OTLP_PARENT_ID_OFFSET = 137
FRESH_CMD26_OTLP_PARENT_ID_SIZE = 17
FRESH_CMD26_CHANNEL_TYPE_ID_OFFSET = 154
FRESH_CMD26_STATUS_READ_LIMIT = 64
FRESH_CMD26_STATUS_DRAIN_TIMEOUT = 0.05
KCP_SEG_HEADER_SIZE = 21
KCP_CLIENT_SYN_CONV = 0x80000001
KCP_SYNC_ACK_CONV = 0x80000002
KCP_SYN_CONV = KCP_SYNC_ACK_CONV
KCP_AUTH_HEAD_CONV = 0x80000006
KCP_AUTH_DATA_CONV = 0x80000008
KCP_AUTH_CONVS = {KCP_AUTH_HEAD_CONV, KCP_AUTH_DATA_CONV}
KCP_AUTH_HEAD_ACK_CMD = 7
KCP_AUTH_ACK_CMD = 9
KCP_AUTH_ACK_CMDS = {KCP_AUTH_HEAD_ACK_CMD, KCP_AUTH_ACK_CMD}
OFFICIAL_AUTH_HEAD_WIRE_LEN = 199
OFFICIAL_AUTH_DATA_WIRE_LEN = 241
OFFICIAL_AUTH_HEAD_ACK_LIKE_LEN = 71
ZTEC_AUTH_HEADER_SIZE = 18
ZTEC_CAG_TYPE101 = 101
ZTEC_CAG_TYPE102 = 102
ZTEC_CAG_TYPE101_DATA_LEN = 220
ZTEC_CAG_TYPE101_BUFFER_LEN = 270
ZTEC_CAG_TYPE101_OTEL_BUFFER_LEN = 398
ZTEC_CAG_TYPE101_HEAD_LEN = ZTEC_CAG_TYPE101_BUFFER_LEN - 226
ZTEC_CAG_TYPE101_OTEL_HEAD_LEN = ZTEC_CAG_TYPE101_OTEL_BUFFER_LEN - 226
ZTEC_CAG_TYPE101_PROXY_OFFSET = ZTEC_CAG_TYPE101_HEAD_LEN + 6
ZTEC_CAG_TYPE101_OTEL_PROXY_OFFSET = ZTEC_CAG_TYPE101_OTEL_HEAD_LEN + 6
ZTEC_CAG_TYPE101_PROXY_DATA_SIZE = 220
ZTEC_CAG_TYPE101_PROXY_DEST_PORT_OFFSET = 0
ZTEC_CAG_TYPE101_PROXY_DEST_IP_OFFSET = 4
ZTEC_CAG_TYPE101_PROXY_CLIENT_UUID_OFFSET = 20
ZTEC_CAG_TYPE101_PROXY_USERNAME_OFFSET = 60
ZTEC_CAG_TYPE101_PROXY_PASSWD_OFFSET = 124
ZTEC_CAG_TYPE101_PROXY_FLAGS_OFFSET = 188
ZTEC_CAG_TYPE101_PROXY_EXTEND_OFFSET = 192
ZTEC_CAG_TYPE101_LINK_TYPE_PROXY = 11
ZTEC_CAG_TYPE101_LINK_TYPE_ICE = 139
ZTEC_CAG_TYPE101_LINK_TYPE_VM_PROXY = 140
ZTEC_CAG_TYPE102_BASE_DATA_LEN = 126
ZTEC_CAG_TYPE102_BASE_BUFFER_LEN = 176
ZTEC_CAG_TYPE102_OTEL_BASE_BUFFER_LEN = 304
ZTEC_CAG_TYPE102_HEAD_LEN = 44
ZTEC_CAG_TYPE102_OTEL_HEAD_LEN = 172
ZTEC_CAG_TYPE102_PROXY_OFFSET = ZTEC_CAG_TYPE102_HEAD_LEN + 6
ZTEC_CAG_TYPE102_OTEL_PROXY_OFFSET = ZTEC_CAG_TYPE102_OTEL_HEAD_LEN + 6
ZTEC_CAG_TYPE102_PROXY_BASE_SIZE = 126
ZTEC_CAG_TYPE102_PROXY_DEST_PORT_OFFSET = 0
ZTEC_CAG_TYPE102_PROXY_FLAG_OFFSET = 2
ZTEC_CAG_TYPE102_PROXY_DEST_IP_OFFSET = 4
ZTEC_CAG_TYPE102_PROXY_CLIENT_UUID_OFFSET = 20
ZTEC_CAG_TYPE102_PROXY_USERNAME_OFFSET = 60
ZTEC_CAG_TYPE102_PROXY_FLAGS_OFFSET = 92
ZTEC_CAG_TYPE102_PROXY_RESERVE_OFFSET = 94
ZTEC_CAG_TYPE102_PROXY_EXTEND_OFFSET = 96
ZTEC_CAG_TYPE102_PROXY_PWD_LEN_OFFSET = 124
ZTEC_CAG_TYPE102_PROXY_PASSWD_OFFSET = 126
RAP_DATA_FRAME_TYPES = {0x81}
RAP_PAYLOAD_ENVELOPE_RAW = "raw"
RAP_PAYLOAD_ENVELOPE_LEN16 = "len16"
RAP_PAYLOAD_ENVELOPE_STRIP_RESERVE4_LEN16 = "strip-reserve4-len16"
RAP_PAYLOAD_ENVELOPES = {
    RAP_PAYLOAD_ENVELOPE_RAW,
    RAP_PAYLOAD_ENVELOPE_LEN16,
    RAP_PAYLOAD_ENVELOPE_STRIP_RESERVE4_LEN16,
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

SPICE_KIND_NAMES = {
    0x0003: "spice-set-ack",
    0x0004: "spice-ping",
    0x0005: "spice-pong",
    0x0006: "spice-ack-sync",
    0x0007: "spice-ack",
    0x0065: "spice-display-init",
    0x0066: "spice-mark",
    0x0067: "spice-main-init",
    0x0068: "spice-channels-list",
    0x0130: "spice-draw-copy",
    0x013A: "spice-surface-create",
}
RAP_FRAME_TYPES = {0x81, 0x82, 0x85, 0x86, 0x89}
TLS_CONTENT_TYPES = {
    0x14: "tls-change-cipher-spec",
    0x15: "tls-alert",
    0x16: "tls-handshake",
    0x17: "tls-application-data",
}
KCP_CMD_FLAGS = {
    0x01: "ssl",
    0x02: "detect-mtu",
    0x04: "client-pack-check",
    0x08: "server-pack-check",
    0x10: "client-fec",
    0x20: "server-fec",
    0x40: "support-data-ex",
    0x80: "multi-link",
}
KCP_WND_FLAGS = {
    0x0001: "gcc",
    0x0002: "stream",
    0x0010: "outband",
    0x0020: "quic",
}


def _bytes(data):
    return bytes(data or b"")


def _u16le(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def _u32le(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def ipv4_from_little_endian(raw):
    """Return dotted IPv4 text from a 4-byte little-endian address field."""
    value = int.from_bytes(_bytes(raw), "little")
    return str(ipaddress.IPv4Address(value))


def ipv4_to_little_endian(address):
    value = int(ipaddress.IPv4Address(str(address)))
    return value.to_bytes(4, "little")


def decode_ztec_keepalive(data):
    """Decode the small ZTEC UDP probe/ack packets seen before RAP traffic.

    Request example from trace:
    ``5a54454306007f020a0a1c2700003d93a00400000000296e3613``

    Ack example from trace:
    ``00003d93a00400000000296e3613``
    """
    packet = _bytes(data)
    if len(packet) >= ZTEC_KEEPALIVE_REQUEST_SIZE and packet[:4] == ZTEC_MAGIC:
        return {
            "kind": "ztec_keepalive_request",
            "magic": packet[:4].decode("ascii"),
            "version": _u16le(packet, 4),
            "host": ipv4_from_little_endian(packet[6:10]),
            "port": _u16le(packet, 10),
            "sequence": _u16le(packet, 12),
            "nonce": _u16le(packet, 14),
            "marker": _u16le(packet, 16),
            "reserved": _u32le(packet, 18),
            "tail": _u32le(packet, 22),
            "rest": packet[ZTEC_KEEPALIVE_REQUEST_SIZE:],
        }
    if len(packet) >= ZTEC_KEEPALIVE_ACK_SIZE:
        return {
            "kind": "ztec_keepalive_ack",
            "sequence": _u16le(packet, 0),
            "nonce": _u16le(packet, 2),
            "marker": _u16le(packet, 4),
            "reserved": _u32le(packet, 6),
            "tail": _u32le(packet, 10),
            "rest": packet[ZTEC_KEEPALIVE_ACK_SIZE:],
        }
    raise ValueError("ZTEC keepalive packet is incomplete")


def encode_ztec_keepalive_request(host, port, sequence, nonce, marker=0x04A0, tail=0, reserved=0, version=6):
    return (
        ZTEC_MAGIC
        + struct.pack(
            "<HIHHHHII",
            int(version),
            int.from_bytes(ipv4_to_little_endian(host), "little"),
            int(port),
            int(sequence),
            int(nonce),
            int(marker),
            int(reserved),
            int(tail),
        )
    )


def encode_ztec_keepalive_ack(sequence, nonce, marker=0x04A0, tail=0, reserved=0):
    return struct.pack("<HHHII", int(sequence), int(nonce), int(marker), int(reserved), int(tail))


def decode_kcp_segment(data, *, be_fec=False, be_using_stream=False):
    """Decode the official Linux client's IKCPSEG wire header.

    IDA evidence:
    ``ikcp_get_seg_info`` reads a 21-byte unaligned little-endian header:
    conv, cmd, wnd, ts, sn, una, len.  ``ikcp_encode_seg`` optionally appends
    two FEC bytes and one stream id byte after that header.
    """
    packet = _bytes(data)
    if len(packet) < KCP_SEG_HEADER_SIZE:
        raise ValueError("KCP segment is incomplete")
    offset = KCP_SEG_HEADER_SIZE
    result = {
        "conv": _u32le(packet, 0),
        "cmd": packet[4],
        "wnd": _u16le(packet, 5),
        "ts": _u32le(packet, 7),
        "sn": _u32le(packet, 11),
        "una": _u32le(packet, 15),
        "len": _u16le(packet, 19),
        "headerSize": KCP_SEG_HEADER_SIZE,
        "cmdFlags": [name for bit, name in KCP_CMD_FLAGS.items() if packet[4] & bit],
        "wndFlags": [name for bit, name in KCP_WND_FLAGS.items() if _u16le(packet, 5) & bit],
        "clientSynConv": _u32le(packet, 0) == KCP_CLIENT_SYN_CONV,
        "syncAckConv": _u32le(packet, 0) == KCP_SYNC_ACK_CONV,
        "synConv": _u32le(packet, 0) == KCP_SYNC_ACK_CONV,
        "authHeadConv": _u32le(packet, 0) == KCP_AUTH_HEAD_CONV,
        "authDataConv": _u32le(packet, 0) == KCP_AUTH_DATA_CONV,
        "authConv": _u32le(packet, 0) in KCP_AUTH_CONVS,
        "authHeadAckCmd": packet[4] == KCP_AUTH_HEAD_ACK_CMD,
        "authAckCmd": packet[4] == KCP_AUTH_ACK_CMD,
        "authAckCmdAny": packet[4] in KCP_AUTH_ACK_CMDS,
        "payload": b"",
        "rest": b"",
    }
    if be_fec:
        if len(packet) < offset + 2:
            raise ValueError("KCP FEC header is incomplete")
        result["totalPos"] = _u16le(packet, offset)
        offset += 2
    if be_using_stream:
        if len(packet) < offset + 1:
            raise ValueError("KCP stream header is incomplete")
        result["streamId"] = packet[offset]
        offset += 1
    payload_end = offset + result["len"]
    result["headerSize"] = offset
    result["payload"] = packet[offset:min(len(packet), payload_end)]
    result["payloadLengthMatches"] = payload_end <= len(packet)
    result["rest"] = packet[payload_end:] if payload_end <= len(packet) else b""
    return result


def encode_kcp_segment(
    *,
    conv,
    cmd=0,
    wnd=0,
    ts=0,
    sn=0,
    una=0,
    payload=b"",
    declared_len=None,
    fec_total_pos=None,
    stream_id=None,
):
    payload = _bytes(payload)
    if len(payload) > 0xFFFF:
        raise ValueError("KCP segment payload is too large")
    if declared_len is None:
        declared_len = len(payload)
    if not 0 <= int(declared_len) <= 0xFFFF:
        raise ValueError("KCP segment declared length is out of range")
    header = struct.pack(
        "<IBHIIIH",
        int(conv) & 0xFFFFFFFF,
        int(cmd) & 0xFF,
        int(wnd) & 0xFFFF,
        int(ts) & 0xFFFFFFFF,
        int(sn) & 0xFFFFFFFF,
        int(una) & 0xFFFFFFFF,
        int(declared_len),
    )
    if fec_total_pos is not None:
        header += struct.pack("<H", int(fec_total_pos) & 0xFFFF)
    if stream_id is not None:
        header += bytes([int(stream_id) & 0xFF])
    return header + payload


def build_kcp_auth_segment(
    *,
    payload,
    auth_head=True,
    conv=0,
    syn_id=0,
    current=0,
    declare_payload_len=True,
):
    """Build the KCP auth preflight segment shape recovered from IDA.

    ``ikcp_set_auth_data`` sends auth head/data before ``ikcp_send_link_sync``.
    The caller must supply fresh session auth bytes; this helper only encodes
    the non-secret KCP envelope and is not used automatically by live probes.
    """
    payload = _bytes(payload)
    if len(payload) > 0xFFFF:
        raise ValueError("KCP auth payload is too large")
    return encode_kcp_segment(
        conv=KCP_AUTH_HEAD_CONV if auth_head else KCP_AUTH_DATA_CONV,
        cmd=0,
        wnd=0,
        ts=current,
        sn=syn_id,
        una=conv,
        payload=payload,
        declared_len=len(payload) if declare_payload_len else 0,
    )


def _kcp_segment_auth_bytes(segment):
    if not segment:
        return b""
    payload = _bytes(segment.get("payload"))
    rest = _bytes(segment.get("rest"))
    return payload if payload else rest


def _redacted_ztec_auth_head_summary(auth_bytes):
    data = _bytes(auth_bytes)
    if len(data) < ZTEC_AUTH_HEADER_SIZE or data[:4] != ZTEC_MAGIC:
        return {
            "present": False,
            "len": len(data),
            "payloadStoredInReport": False,
        }
    header_len_field = _u16le(data, 4)
    auth_head_len = header_len_field + 6
    buffer_type = _u32le(data, 6)
    random_c = _u32le(data, 10)
    auth_data_len = _u32le(data, 14)
    serial = data[18:34] if len(data) >= 34 else b""
    extend0 = _u32le(data, 34) if len(data) >= 38 else None
    opentelemetry = header_len_field in {ZTEC_CAG_TYPE101_OTEL_HEAD_LEN, ZTEC_CAG_TYPE102_OTEL_HEAD_LEN}
    trace_region = data[50:114] if opentelemetry and len(data) >= 114 else b""
    span_region = data[114:178] if opentelemetry and len(data) >= 178 else b""
    summary = {
        "present": True,
        "magic": "ZTEC",
        "len": len(data),
        "headerLenField": header_len_field,
        "authHeadLenFromHeader": auth_head_len,
        "authHeadLenMatchesObserved": auth_head_len == len(data),
        "bufferType": buffer_type,
        "bufferTypeName": {
            ZTEC_CAG_TYPE101: "cag-password-auth",
            ZTEC_CAG_TYPE102: "cag-uac-token-auth",
        }.get(buffer_type, "unknown"),
        "randomPresent": bool(random_c),
        "authDataLenField": auth_data_len,
        "serialPresent": bool(serial and any(serial)),
        "extend0Present": extend0 is not None,
        "opentelemetry": bool(opentelemetry),
        "payloadStoredInReport": False,
    }
    if extend0 is not None:
        summary["extend0LowByteFlags"] = {
            "otelBit": bool(extend0 & 0x04),
        }
        summary["linkTypeFromExtendLow16"] = (extend0 >> 16) & 0xFFFF
        summary["linkTypeFromExtendHigh7"] = (extend0 >> 24) & 0x7F
    if opentelemetry:
        summary["otelTraceIdRegion"] = {
            "len": len(trace_region),
            "nonZeroBytes": sum(1 for item in trace_region if item),
            "allZero": bool(trace_region and not any(trace_region)),
            "payloadStoredInReport": False,
        }
        summary["otelSpanIdRegion"] = {
            "len": len(span_region),
            "nonZeroBytes": sum(1 for item in span_region if item),
            "allZero": bool(span_region and not any(span_region)),
            "payloadStoredInReport": False,
        }
    return summary


def redacted_kcp_auth_wire_summary(data):
    packet = _bytes(data)
    try:
        segment = decode_kcp_segment(packet)
    except ValueError:
        return {
            "present": False,
            "wireLen": len(packet),
            "payloadStoredInReport": False,
        }
    auth_bytes = _kcp_segment_auth_bytes(segment)
    return {
        "present": True,
        "wireLen": len(packet),
        "conv": segment.get("conv"),
        "cmd": segment.get("cmd"),
        "wnd": segment.get("wnd"),
        "declaredLen": segment.get("len"),
        "declaredPayloadBytes": len(_bytes(segment.get("payload"))),
        "tailBytesAfterDeclaredPayload": len(_bytes(segment.get("rest"))),
        "authBytesPlacement": "declared_payload" if segment.get("payload") else ("tail_after_zero_declared_len" if auth_bytes else "none"),
        "tsPresent": bool(segment.get("ts")),
        "snPresent": bool(segment.get("sn")),
        "unaPresent": bool(segment.get("una")),
        "authHeadConv": bool(segment.get("authHeadConv")),
        "authDataConv": bool(segment.get("authDataConv")),
        "ztecAuthHead": _redacted_ztec_auth_head_summary(auth_bytes) if segment.get("authHeadConv") else None,
        "authTailBytesStoredInReport": False,
        "payloadStoredInReport": False,
    }


def _redacted_local_proxy_frame_summary(data):
    packet = _bytes(data)
    if len(packet) < 4:
        return {
            "present": False,
            "len": len(packet),
            "payloadStoredInReport": False,
        }
    body = packet[4:]
    return {
        "present": True,
        "len": len(packet),
        "frameHeader": {
            "u16Type": _u16le(packet, 0),
            "u16BodyLen": _u16le(packet, 2),
            "totalLenMatchesHeader": len(packet) == _u16le(packet, 2) + 4,
            "commandByte": packet[0],
            "channelOrIdByte": packet[1],
            "lenAtOffset2": _u16le(packet, 2),
            "commandByteSchemaMatches": bool(packet[0] == 26 and packet[1] == 0 and len(packet) == _u16le(packet, 2) + 4),
            "sendTunnelLinkMessageDirectShape": bool(packet[0] == 26 and packet[1] != 0 and _u16le(packet, 2) == 154 and len(packet) == 158),
            "sendTunnelLinkMessageDirectShapeExcluded": bool(packet[0] == 26 and packet[1] == 0 and _u16le(packet, 2) == 156 and len(packet) == 160),
        },
        "bodyLen": len(body),
        "bodyNonZeroBytes": sum(1 for item in body if item),
        "bodyZeroBytes": body.count(0),
        "payloadStoredInReport": False,
    }


def _local_proxy_writer_chain_evidence():
    return {
        "conclusion": "fresh_160_byte_cmd26_frame_not_created_by_writer_rewrap",
        "freshFrameShape": {
            "commandByte": 26,
            "channelOrIdByte": 0,
            "lenAtOffset2": 156,
            "wireLen": 160,
        },
        "sendTunnelLinkMessageDirectShape": {
            "commandByte": 26,
            "channelOrIdByte": "nonzero link/channel id",
            "lenAtOffset2": 154,
            "wireLen": 158,
        },
        "unlinkedOutbandReaderEvidence": {
            "reader": "deal_unlinked_outband_local_data",
            "appliesWhen": "check_spice_proxy_protocol_header rejects the first 4-byte local proxy header and data_buf[224] is set to 2",
            "maxProxyIncomingHeaderPos": "0x74",
            "maxStreamBytesReadBeforeSendTunnelAddLink": 116,
            "frameToDataBufMapping": "data_buf[100 + frame_offset]",
            "coveredFrameOffsets": "0..115",
            "coveredBodyOffsets": "0..111",
            "tailBodyOffsetsNotConsumedByThisReader": ["137..152", "155..155"],
            "opentelemetryArgumentOffsets": {
                "traceCandidateDataBuf": "data_buf[118]",
                "spanCandidateDataBuf": "data_buf[151]",
                "traceCandidateFrameOffset": 18,
                "traceCandidateBodyOffset": 14,
                "spanCandidateFrameOffset": 51,
                "spanCandidateBodyOffset": 47,
                "mapsBeforeTail": True,
            },
            "channelLinkSocketExMemcpyEvidence": [
                {
                    "source": "data_buf[118]",
                    "sourceFrameOffset": 18,
                    "sourceBodyOffset": 14,
                    "destination": "ChannelLinkSocketEx + 0x68",
                    "destinationCapacity": 33,
                    "sourceLengthArgument": 33,
                },
                {
                    "source": "data_buf[151]",
                    "sourceFrameOffset": 51,
                    "sourceBodyOffset": 47,
                    "destination": "ChannelLinkSocketEx + 0x89",
                    "destinationCapacity": 17,
                    "sourceLengthArgument": 33,
                },
            ],
            "conclusion": "body[137:152]/body[155] are outside the recovered unlinked outband reader and are not explained by the data_buf[118]/data_buf[151] OpenTelemetry arguments",
            "payloadStoredInReport": False,
        },
        "freshCmd26HeaderPathEvidence": {
            "checkFunction": "check_spice_proxy_protocol_header",
            "acceptedCommandBytes": [26, 10, 42],
            "freshCommandByte": 26,
            "freshHeaderAccepted": True,
            "linkTypeAfterHeader": 1,
            "firstDispatcherAfterHeader": "deal_local_link_proxy_create",
            "outbandType2PathUsedForFreshCmd26": False,
            "officialTraceLoopbackPairs": [
                {
                    "clientFd": 89,
                    "acceptedFd": 91,
                    "clientSendLen": 160,
                    "acceptedHeaderRecvLen": 4,
                    "acceptedBodyRecvLen": 156,
                    "acceptedStatusSendLen": 1,
                    "clientStatusRecvLen": 1,
                },
                {
                    "clientFd": 110,
                    "acceptedFd": 111,
                    "clientSendLen": 160,
                    "acceptedHeaderRecvLen": 4,
                    "acceptedBodyRecvLen": 156,
                    "acceptedStatusSendLen": 1,
                    "clientStatusRecvLen": 1,
                },
            ],
            "conclusion": "for the fresh cmd26 local proxy frame, the official recv len=4 is the accepted-side read of the 4-byte local proxy header; the later accepted-side recv len=156 is the body, and the command handler status observed back on the client side is len=1",
            "payloadStoredInReport": False,
        },
        "freshCmd26BodyPathEvidence": {
            "bodyReadFunction": "deal_local_spice_proxy_head",
            "bodyReadSource": "fd_session_async_read_tcp_data",
            "bodyBuffer": "in_sock + 0x9b0",
            "bodyLenSource": "ProxyProtolHeader.u16BodyLen",
            "officialBodyLen": 156,
            "bodyProgressOffset": "in_sock + 0x194",
            "progressResetAfterDispatch": True,
            "cmd26Dispatcher": "deal_local_recved_cmd_link",
            "cmd26BodyConsumer": "send_tunnel_add_link(in_sock, in_sock + 0x9b0)",
            "bodyOffsetMappings": [
                {
                    "bodyOffset": 2,
                    "field": "link_priority",
                    "consumer": "set_clt_fd_session_priority",
                },
                {
                    "bodyOffsetRange": "104..135",
                    "hexOffsetRange": "0x68..0x87",
                    "field": "opentelemetry trace candidate",
                    "copy": "ZXStrncopy(channel_manage + 0x6a, channel_link_info + 0x68, size=0x21, copyLen=0x20)",
                },
                {
                    "bodyOffsetRange": "137..152",
                    "hexOffsetRange": "0x89..0x98",
                    "field": "opentelemetry span candidate",
                    "copy": "ZXStrncopy(channel_manage + 0x8b, channel_link_info + 0x89, size=0x11, copyLen=0x10)",
                },
                {
                    "bodyOffsetRange": "154..155",
                    "hexOffsetRange": "0x9a..0x9b",
                    "field": "channel_type_id word",
                    "consumer": "send_tunnel_add_link derives channel_type=(word>>8)&0x7f and channel_id=word&0xff",
                },
                {
                    "bodyOffset": 155,
                    "hexOffset": "0x9b",
                    "field": "channel_type_id high byte",
                    "consumer": "channel_type component used by set_sock_bw_ctrl_type and port-channel handling",
                },
            ],
            "tailBodyOffsetsExplained": ["137..152", "155..155"],
            "linkedTailReaderNeededForFreshCmd26Tail": False,
            "conclusion": "fresh cmd26 consumes the full 156-byte body through deal_local_spice_proxy_head -> deal_local_recved_cmd_link -> send_tunnel_add_link; body[137:152] maps to the second OpenTelemetry ZXStrncopy source and body[155] maps to the high byte of channel_type_id",
            "payloadStoredInReport": False,
        },
        "freshCmd26MinimalSynthesisSchema": {
            "schemaStatus": "static_layout_known_value_synthesis_not_closed",
            "officialTraceFields": [
                "loopback client send len=160",
                "accepted-side recv len=4 local proxy header",
                "accepted-side recv len=156 ChannelLinkSocketEx body",
                "client-side status recv len=1",
                "external AUTH_HEAD len=199 follows the bootstrap cycle",
            ],
            "dwarfStructEvidence": {
                "source": "readelf --debug-dump=info libspice-client-glib-zte-2.0.so.8.5.0",
                "ChannelLinkSocketEx": {
                    "byteSize": 156,
                    "members": [
                        {"field": "info", "offset": 0, "type": "ChannelLinkInfoEx"},
                        {"field": "channel_type_id", "offset": 154, "size": 2},
                    ],
                },
                "ChannelLinkInfoEx": {
                    "byteSize": 154,
                    "members": [
                        {"field": "dest_port", "offset": 0, "size": 2},
                        {"field": "link_priority", "offset": 2, "size": 1},
                        {"field": "link_type", "offset": 3, "size": 1},
                        {"field": "dest_ip", "offset": 4, "size": 4},
                        {"field": "ipv6", "offset": 8, "size": 16},
                        {"field": "serial_num", "offset": 24, "size": 16},
                        {"field": "vm_uuid", "offset": 40, "size": 37},
                        {"field": "protocol_type", "offset": 77, "size": 1},
                        {"field": "be_emergency", "offset": 78, "size": 1},
                        {"field": "bw_ctrl", "offset": 79, "size": 2},
                        {"field": "tbw_ctrl", "offset": 81, "size": 2},
                        {"field": "flag", "offset": 83, "size": 1},
                        {"field": "channel_type", "offset": 84, "size": 4},
                        {"field": "extend", "offset": 88, "size": 16},
                        {"field": "otlp_trace_id", "offset": 104, "size": 33},
                        {"field": "otlp_parent_id", "offset": 137, "size": 17},
                    ],
                },
                "payloadStoredInReport": False,
            },
            "bodyContract": {
                "wireHeader": "cmd=26, channel/id byte=0, u16BodyLen=156",
                "bodyObject": "ChannelLinkSocketEx",
                "bodyLen": 156,
                "consumer": "send_tunnel_add_link",
                "payloadStoredInReport": False,
            },
            "fieldConsumption": [
                {
                    "bodyOffsetRange": "0..1",
                    "field": "info.dest_port",
                    "role": "copied into ProxyChannelManage.link_info.dest_port",
                    "requiredForMinimalSynthesis": True,
                },
                {
                    "bodyOffset": 2,
                    "field": "info.link_priority",
                    "role": "sets client fd session priority before stream creation",
                    "requiredForMinimalSynthesis": True,
                },
                {
                    "bodyOffset": 3,
                    "field": "info.link_type",
                    "role": "copied into ProxyChannelManage.link_info.link_type",
                    "requiredForMinimalSynthesis": True,
                },
                {
                    "bodyOffsetRange": "4..7",
                    "field": "info.dest_ip",
                    "role": "selects IPv4 vs IPv6 copy/log branch and is copied into ProxyChannelManage.link_info",
                    "requiredForMinimalSynthesis": True,
                },
                {
                    "bodyOffsetRange": "8..23",
                    "field": "info.ipv6",
                    "role": "copied when info.dest_ip is zero and IPv6 branch is used",
                    "requiredForMinimalSynthesis": "depends_on_dest_ip_zero",
                },
                {
                    "bodyOffsetRange": "24..39",
                    "field": "info.serial_num",
                    "role": "serial/process-track material carried in the local link info",
                    "requiredForMinimalSynthesis": "required_to_match_official_bootstrap_shape_but_not_auth_payload",
                },
                {
                    "bodyOffsetRange": "40..76",
                    "field": "info.vm_uuid",
                    "role": "VM/client uuid material carried in the local link info",
                    "requiredForMinimalSynthesis": "required_to_match_official_bootstrap_shape_but_not_auth_payload",
                },
                {
                    "bodyOffset": 77,
                    "field": "info.protocol_type",
                    "role": "protocol discriminator carried in ChannelLinkInfoEx",
                    "requiredForMinimalSynthesis": "value_source_not_closed",
                },
                {
                    "bodyOffset": 78,
                    "field": "info.be_emergency",
                    "role": "emergency-mode flag carried in ChannelLinkInfoEx",
                    "requiredForMinimalSynthesis": "value_source_not_closed",
                },
                {
                    "bodyOffsetRange": "79..82",
                    "field": "info.bw_ctrl/info.tbw_ctrl",
                    "role": "bandwidth-control inputs carried before flag/channel_type",
                    "requiredForMinimalSynthesis": "value_source_not_closed",
                },
                {
                    "bodyOffset": 83,
                    "field": "info.flag/info.channel_type",
                    "role": "flag at 83 and channel_type at 84..87 are used after in_sock->data_buf[224] selects the SPICE link-type branch",
                    "requiredForMinimalSynthesis": "depends_on_sock_link_type",
                },
                {
                    "bodyOffsetRange": "88..103",
                    "field": "info.extend",
                    "role": "opaque local link-info extension before OpenTelemetry fields",
                    "requiredForMinimalSynthesis": "value_source_not_closed",
                },
                {
                    "bodyOffsetRange": "104..135",
                    "field": "info.otlp_trace_id",
                    "role": "copied to channel manage after stream creation succeeds",
                    "requiredForMinimalSynthesis": "required_to_match_official_bootstrap_shape_but_not_auth_payload",
                },
                {
                    "bodyOffsetRange": "137..152",
                    "field": "info.otlp_parent_id",
                    "role": "copied to channel manage after stream creation succeeds",
                    "requiredForMinimalSynthesis": "required_to_match_official_bootstrap_shape_but_not_auth_payload",
                },
                {
                    "bodyOffsetRange": "154..155",
                    "field": "channel_type_id",
                    "role": "derives channel_type/channel_id, drives bandwidth control, port-channel branch, and QUIC stream metadata",
                    "requiredForMinimalSynthesis": True,
                },
            ],
            "requiredSessionSideEffects": [
                "deal_local_link_proxy_create maps in_sock->data_buf[224] through get_proxy_type_by_link_type before body dispatch",
                "deal_create_proxy_fd_session creates the proxy fd session when missing and stores proxy_sock->data_buf[224]",
                "init_local_rw_sock_pair/init_local_rw_sock_pair_udp pairs local and proxy/UDP sessions before external AUTH_HEAD",
                "QUIC_create_data_stream requires session QUIC_engine, QUIC_inited, and a matching QUIC channel manage",
                "QUIC_set_streams_pay_load_type maps sock_link_type=2 to SPICE_OUTBAND and sock_link_type=1 through SPICE channel type names",
            ],
            "valueSourceStaticEvidence": {
                "freshCmd26LinkRoute": {
                    "headerEffect": "accepted cmd=26 header sets in_sock->data_buf[224] to link_type 1",
                    "proxyTypeRoute": "get_proxy_type_by_link_type(session, 1) returns proxy_type_ex=6 because link_type != 2",
                    "proxySockLinkFlag": "deal_create_proxy_fd_session(fd_type_ex=6) keeps default link_type=1 and writes proxy_sock->data_buf[224]=1",
                    "outbandProxyType5ExcludedForFreshCmd26": True,
                    "outbandProxyType5Condition": "only possible for link_type=2 when rap/downward-bw-control conditions allow it",
                },
                "kcpDestinationRoute": {
                    "functionEvidence": "init_local_rw_sock_pair_udp calls get_proxy_kcp_dst_ip/port(session, proxy_sock->cag_client_key)",
                    "nonMultiTcpWithCag": "ag_ip/ag_port source class",
                    "nonMultiTcpWithoutCag": "host/get_spice_proxy_dst_port source class",
                    "multiTcpWithCag": "ag_ip/ag_port source class",
                    "multiTcpWithoutCag": "vm_ip/vm_proxy_port source class except ice uses host/vm_proxy_port",
                    "notChannelLinkSocketExDest": True,
                },
                "channelLinkDestinationRole": {
                    "destIpPortRole": "ChannelLinkSocketEx.info.dest_ip/dest_port are copied into ProxyChannelManage.link_info after stream creation succeeds",
                    "notAuthBufferDestination": True,
                    "notKcpSocketDestination": True,
                },
                "freshCmd26ProducerSideSynthesis": {
                    "function": "add_link_to_proxy_by_socket",
                    "directProducerForFreshFrame": True,
                    "frameShape": {
                        "allocatedLen": 160,
                        "commandByte": 26,
                        "channelOrIdByte": 0,
                        "u16BodyLen": 156,
                        "bodyCopy": "ZXMemcpy(frame + 4, stack ChannelLinkSocketEx, 0x9c)",
                        "writeCall": "spice_channel_flush_wire(channel, frame, 0xa0)",
                        "statusRead": "spice_channel_read(channel, &status, 1)",
                    },
                    "bodyValueSources": {
                        "dest_ip": {
                            "bodyOffsetRange": "4..7 for IPv4 or 8..23 for IPv6",
                            "sourceSelection": "SpiceSessionPrivate.hostip when nonempty, otherwise SpiceSessionPrivate.host",
                            "sourceOffsets": {
                                "host": 0,
                                "hostip": "0x1448",
                            },
                            "ipv4Transform": "inet_addr(source) followed by ntohl into ChannelLinkSocketEx.info.dest_ip",
                            "ipv6Transform": "inet_pton(AF_INET6, source, ChannelLinkSocketEx.info.ipv6)",
                        },
                        "dest_port": {
                            "bodyOffsetRange": "0..1",
                            "sourceFunction": "get_channel_proxy_link_dest_port(channel)",
                            "staticBranches": [
                                "proxy_type string branch reads session offset 0x8 through ZXStrtoul",
                                "client_type==1 branch reads session offset 0x1240 through ZXStrtoul",
                                "client_type==2 branch reads session offset 0x1238 through ZXStrtoul",
                            ],
                            "exactRuntimeValueStillRequiresSessionState": True,
                        },
                        "link_priority": {
                            "bodyOffset": 2,
                            "sourceFunction": "get_channel_proxy_link_priority(channel)",
                            "staticMapping": "channel private word/dword at 0x974: 1 or 3 -> priority 1; 2 -> priority 3; otherwise priority 2",
                        },
                        "link_type": {
                            "bodyOffset": 3,
                            "source": "add_link_to_proxy_by_socket zero-initializes the stack body and explicitly leaves this byte zero before send",
                        },
                        "flag": {
                            "bodyOffset": 83,
                            "source": "when network_protocol_type is zero and session offset 0x1f54 is positive, low byte of that value is written; otherwise remains zero",
                        },
                        "opentelemetry": {
                            "traceSource": "caller argument + 0x400 copied to body[104:136]",
                            "parentSource": "caller argument + 0x421 copied to body[137:153]",
                            "payloadStoredInReport": False,
                        },
                        "channel_type_id": {
                            "bodyOffsetRange": "154..155",
                            "sourceExpression": "(SpiceChannelPrivate field at 0x974 << 8) | SpiceChannelPrivate field at 0x970",
                            "dwarfBoundary": "related DWARF units identify nearby channel_id/channel_type fields around 0x970/0x974; target-function offsets are the direct evidence",
                            "traceVerifiedValue": False,
                        },
                    },
                    "officialTraceFields": [
                        "loopback client send len=160 cmd26",
                        "accepted-side recv len=156 ChannelLinkSocketEx body",
                        "client-side recv len=1 cmd26 status",
                        "external AUTH_HEAD len=199 follows local proxy/session setup",
                    ],
                    "pythonImplication": "Python can now synthesize the fresh cmd26 frame from session/channel state categories instead of treating body[0:156] as an unknown blob; exact runtime host/port/channel values still must come from safe local state, not local proxy body plaintext replay",
                    "payloadStoredInReport": False,
                },
                "channelTypeIdRole": {
                    "bodyRange": "154..155",
                    "streamManageFields": ["ChannelType=(word>>8)&0x7f", "ChannelId=word&0xff"],
                    "payloadTypeDependency": "QUIC_set_streams_pay_load_type uses ChannelType with sock_link_type to select SPICE_* payload type",
                },
                "channelTypeIdSynthesisRole": {
                    "inputSource": "fresh cmd26 body[154:156]",
                    "derivedFormula": "channel_type_id = (spice_channel_type << 8) | channel_id; send_tunnel_add_link and QUIC_initialize_stream_manage mask the high byte with 0x7f",
                    "streamManageWrites": [
                        "QUIC_initialize_stream_manage writes StreamManage+0x43 = (channel_type_id >> 8) & 0x7f",
                        "QUIC_initialize_stream_manage writes StreamManage+0x34 = channel_type_id & 0xff",
                    ],
                    "payloadTypeMapping": [
                        "sock_link_type=1 uses QUIC_spice_channel_type_to_string(channel_type) and falls back to SPICE_UNKNOWN",
                        "sock_link_type=2 maps to SPICE_OUTBAND independently of the SPICE channel type",
                    ],
                    "channelTypeNameTable": {
                        "source": "QUIC_spice_channel_type_to_string jump table",
                        "validRange": "1..11",
                        "zeroOrOutOfRange": "SPICE_UNKNOWN",
                        "knownNames": {
                            1: "SPICE_MAIN",
                            2: "SPICE_DISPLAY",
                            3: "SPICE_INPUTS",
                            4: "SPICE_CURSOR",
                            5: "SPICE_PLAYBACK",
                            6: "SPICE_RECORD",
                            7: "SPICE_TUNNEL",
                            8: "SPICE_SMARTCARD",
                            9: "SPICE_USBREDIR",
                            10: "SPICE_PORT",
                            11: "SPICE_PROXY",
                        },
                    },
                    "firstChannelCandidateBoundary": {
                        "spiceSessionConnectCreates": [
                            "spice_channel_new(session, 1, 0) creates the MAIN channel unconditionally before proxy-thread handling",
                            "create_channel(cmain, 2, 0) may pre-create DISPLAY only when is_create_main_displaychannel_in_advance() is true",
                        ],
                        "portChannelBoundary": "SPICE_PORT/channel_type=10 is a later port-channel branch in send_tunnel_add_link, not the unconditional first link-unify channel",
                        "virtualLinkIdBoundary": "get_avaliable_virtual_channel_id allocates ProxyChannelManage link ids and does not determine channel_type_id low byte",
                        "candidatePriority": [
                            {"channel_type_id": "0x0100", "meaning": "SPICE_MAIN channel 0", "status": "unconditional_static_candidate_not_trace_verified"},
                            {"channel_type_id": "0x0200", "meaning": "SPICE_DISPLAY channel 0", "status": "conditional_static_candidate"},
                            {"channel_type_id": "0x0a00", "meaning": "SPICE_PORT channel 0", "status": "excluded_as_unconditional_first_candidate"},
                        ],
                        "exactOfficialValueStillUnknown": True,
                    },
                    "zimeCreateDataStreamTraceBoundary": {
                        "officialTraceEvent": "zime_struct/ZIME_CreateDataStream param_before",
                        "observedSafeFields": ["u8Priority=9", "u32MaxBandwidth=4294967295"],
                        "sourceInStaticCode": "StreamParam.u8Priority = stream_manage->priority; StreamParam.u32MaxBandwidth = -1",
                        "cannotInferFromTrace": "the safe ZIME_CreateDataStream struct fields do not expose StreamManage.ChannelType/ChannelId",
                    },
                    "bandwidthImplication": [
                        "channel_type=2 selects bw ctrl type 2 in set_sock_bw_ctrl_type",
                        "channel_type=10 enters the port-channel branch unless port-channel multiplex is enabled",
                        "other SPICE channel types on sock_link_type=1 select bw ctrl type 1",
                    ],
                    "destinationIndependence": "dest_ip/dest_port are copied/logged into ProxyChannelManage but are not used to derive StreamManage ChannelType/ChannelId or the KCP/auth destination",
                    "officialTraceFields": [
                        "loopback client send len=160 cmd26",
                        "accepted-side recv len=156 ChannelLinkSocketEx body",
                        "external AUTH_HEAD len=199 follows local proxy/session setup",
                    ],
                    "exactValueStatus": "structure and side effects are closed; the official first-channel candidate value still must be inferred without reading local proxy body plaintext",
                    "payloadStoredInReport": False,
                },
                "streamCreateGateEvidence": {
                    "function": "handle_quic_protocol_stream_create_processing",
                    "doesNotSynthesizeChannelLinkSocketExFields": True,
                    "hardFailureConditions": [
                        "missing proxy fd session for get_proxy_type_by_link_type(in_sock->data_buf[224])",
                        "QUIC_create_data_stream attempted and returned failure",
                    ],
                    "successWithoutNewQuicStreamConditions": [
                        "port-channel related socket check succeeds",
                        "proxy fd session exists but check_proxy_is_ready equivalent is false",
                        "proxy fd session has no KCP/QUIC channel-manage state ready for stream creation",
                    ],
                    "quicStreamAttemptCondition": "proxy fd session exists, is ready, has KCP state, and the QUIC/channel-ready byte is set",
                    "pythonImplication": "fresh cmd26 success is gated by proxy/session side effects; body field synthesis alone is not enough, but a new QUIC stream is conditional rather than unconditionally required",
                },
                "localSessionBootstrapSideEffects": {
                    "dealCreateProxyFdSessionType6": {
                        "freshRoute": "fd_type_ex=6 keeps link_type=1 and stores the created proxy fd session in the thread/session type6 slot",
                        "networkProtocolByte": "proxy_sock byte 0x2d follows spice_session_get_network_protocol_type()!=0 and selects UDP proxy fd creation when true",
                        "clientTypeByte": "proxy_sock byte 0x68 records spice_session_get_client_type()==1",
                        "linkTypeField": "proxy_sock word 0x18c receives link_type=1 for fresh cmd26 type6 route",
                        "fdTypeField": "proxy_sock dword 0x24 receives fd_type_ex=6",
                    },
                    "initLocalRwSockPairGate": {
                        "proxyLookup": "maps in_sock data_buf[224] through get_proxy_type_by_link_type and requires an existing proxy fd session",
                        "missingProxySessionEffect": "sets an fd-session error flag and stops before UDP/KCP pairing",
                        "udpPairCondition": "enters init_local_rw_sock_pair_udp only when proxy_sock byte 0x2d is true",
                        "tcpPairFallback": "otherwise pairs in_sock directly with the proxy fd session through the local rw sock pointer",
                    },
                    "initLocalRwSockPairUdpSideEffects": {
                        "newSessionType": "creates a TN_UDP_CLD_SOCK fd session on the UDP fd",
                        "copiedFields": [
                            "proxy_sock word 0x18c -> udp_sock word 0x18c",
                            "proxy_sock byte 0x2d -> udp_sock byte 0x2d",
                            "proxy_sock byte 0x60 -> udp_sock byte 0x60",
                        ],
                        "pairing": "sets in_sock->pair and udp_sock->pair before KCP creation",
                        "kcpCreateInputs": "create_udt_session uses get_proxy_kcp_dst_ip/port output, proxy_sock fd_type_ex, UDP fd, and a type6 boolean",
                        "cagAuthTiming": "deal_udt_using_cag runs only after KCP is attached back to the fd-session state",
                    },
                    "officialTraceFields": [
                        "loopback client send len=160 cmd26",
                        "accepted-side recv len=156 ChannelLinkSocketEx body",
                        "client-side recv len=1 cmd26 status",
                        "external AUTH_HEAD len=199 follows local proxy/session setup",
                    ],
                    "payloadStoredInReport": False,
                },
                "freshBodyValueSynthesisBoundaries": {
                    "sendTunnelAddLinkCopies": [
                        "dest_port body[0:2] -> ProxyChannelManage.link_info.dest_port",
                        "link_priority body[2] -> set_clt_fd_session_priority and ProxyChannelManage.link_info.link_priority",
                        "link_type body[3] -> ProxyChannelManage.link_info.link_type",
                        "dest_ip body[4:8] or ipv6 body[8:24] -> ProxyChannelManage.link_info destination branch",
                        "flag body[83] -> ProxyChannelManage.link_info.flag when sock_link_type=1",
                        "channel_type body[84:88] -> low byte rewritten from channel_type_id high byte before storing in ProxyChannelManage.link_info.channel_type",
                        "otlp_trace_id body[104:136] -> ProxyChannelManage OpenTelemetry trace field",
                        "otlp_parent_id body[137:153] -> ProxyChannelManage OpenTelemetry parent/span field",
                        "channel_type_id body[154:156] -> channel type/id, stream metadata, bandwidth and port-channel decisions",
                    ],
                    "notCopiedFromFreshInputBySendTunnelAddLink": [
                        "serial_num body[24:40] is not copied into ProxyChannelManage by send_tunnel_add_link before send_tunnel_link_message",
                        "vm_uuid body[40:77] is not copied into ProxyChannelManage by send_tunnel_add_link before send_tunnel_link_message",
                    ],
                    "downstreamLinkMessageDerivations": {
                        "shape": "send_tunnel_link_message builds the later internal cmd26 buffer with data[0]=26, data[1]=virtual_channel_id, data[2:4]=154 and writeLen=158",
                        "serialNumSource": "for sock_link_type=1, output body[24:40] is generated by spice_processtrack_get_serial_num, not copied from the fresh cmd26 input body",
                        "bandwidthSource": "deal_bw_ctrl_sock_link_message may derive bw_ctrl/tbw_ctrl/link_type from in_sock data_buf[238], session bw_ctrl_cfg and thread bandwidth state",
                        "vmUuidSource": "vm_uuid material is only observed in the emergency branch of send_tunnel_link_message, where it is copied from s->vmid into the later internal message",
                        "notFreshInputProducer": True,
                    },
                    "otelAndAuthRelation": {
                        "cagAuthSource": "deal_udt_using_cag writes serial_uuid from process-track and OpenTelemetry trace/span from g_otlp_trace_id/g_otlp_parent_id into the CAG auth buffer",
                        "freshCmd26InputRole": "fresh cmd26 OTLP body fields are consumed as local proxy bootstrap input and copied to channel manage",
                        "exactValueStatus": "exact official fresh cmd26 OTLP values remain unavailable without local proxy body plaintext, but Python can generate structurally valid non-secret trace/span candidates",
                    },
                    "pythonImplication": "do not use downstream 158-byte send_tunnel_link_message generation rules as the source for fresh 160-byte input body; model only the fields actually consumed before the external AUTH_HEAD gate",
                    "officialTraceFields": [
                        "loopback client send len=160 cmd26",
                        "accepted-side recv len=156 ChannelLinkSocketEx body",
                        "client-side recv len=1 cmd26 status",
                        "external AUTH_HEAD len=199 follows local proxy/session setup",
                    ],
                    "payloadStoredInReport": False,
                },
                "officialTraceFields": [
                    "loopback client send len=160 cmd26",
                    "accepted-side recv len=156 ChannelLinkSocketEx body",
                    "external AUTH_HEAD len=199 follows local proxy/session setup",
                ],
                "payloadStoredInReport": False,
            },
            "pythonImplication": (
                "a Python bootstrap cannot be reduced to sending a 199-byte AUTH_HEAD; it must either reproduce "
                "the local proxy/session side effects or build an equivalent state model before the AUTH gate"
            ),
            "notYetClosed": [
                "materializing safe Python session/channel state for ChannelLinkSocketEx dest_port/dest_ip without replaying local proxy body plaintext",
                "which first-channel channel_type_id candidate is accepted for the fresh cmd26 bootstrap without reading local proxy body plaintext",
                "whether structurally valid generated OpenTelemetry values are enough for fresh cmd26, or whether exact official trace/span correlation is required",
                "whether vm_uuid/serial_num can stay zero or locally generated in the fresh input body because send_tunnel_add_link does not copy them into ProxyChannelManage",
                "whether a Python-only equivalent of the QUIC/channel manage side effects is sufficient for the external ACK-like gate",
                "whether Python must model the type6 proxy fd session slot, proxy_sock byte 0x2d UDP gate, and init_local_rw_sock_pair_udp KCP attachment before AUTH_HEAD",
            ],
            "payloadStoredInReport": False,
        },
        "linkedOutbandTailCandidate": {
            "dispatcher": "local_data_tcp_read",
            "dispatcherBehavior": "uses deal_unlinked_local_data_read before get_proxy_channel_manage_by_fd() succeeds; uses deal_linked_local_data_read after a proxy channel manage exists",
            "linkedLinkType2Path": "deal_linked_local_data_read -> deal_linked_outband_local_data_read",
            "readFunction": "fd_session_async_read_tcp_data",
            "readLimitBehavior": "fd_session_async_read_tcp_non_ssl_data calls recv() with the caller-requested remaining length and does not intentionally over-read beyond that request",
            "linkedPayloadBuffer": "in_sock + 0x9b0 + PROTOCOL_HEADER_SIZE",
            "linkedProtocolHeaderSize": 4,
            "linkedSafetyMargin": 24,
            "linkedMinimumReadSize": 50,
            "linkedMaxReadWithoutBwLimit": 65507,
            "linkedForwardingShapes": [
                {
                    "path": "QUIC port-channel",
                    "header": "cmd=10, channel byte from channel manage, u16 payload length",
                    "writeFunction": "QUIC_stream_port_data_write",
                    "writeLen": "payloadLen + 4",
                },
                {
                    "path": "QUIC data stream",
                    "header": "none",
                    "writeFunction": "QUIC_stream_data_write",
                    "writeLen": "payloadLen",
                },
                {
                    "path": "UDT data stream",
                    "header": "none",
                    "writeFunction": "udt_write_data_stream",
                    "writeLen": "payloadLen",
                },
                {
                    "path": "SPICE port-channel",
                    "header": "cmd=10, channel byte from channel manage, u16 payload length",
                    "writeFunction": "spice_session_write_port_data",
                    "writeLen": "payloadLen + 4",
                },
                {
                    "path": "proxy data",
                    "header": "cmd=10, channel byte from channel manage, u16 payload length",
                    "writeFunction": "proxy_data_write",
                    "writeLen": "payloadLen + 4",
                },
            ],
            "candidateForFreshTail": False,
            "candidateForLaterLinkedFrames": True,
            "confidence": "low-for-fresh-cmd26-tail",
            "conclusion": "linked outband reader remains relevant for later linked frames, but fresh cmd26 tail bytes are already read into in_sock+0x9b0 by deal_local_spice_proxy_head and consumed by send_tunnel_add_link",
            "payloadStoredInReport": False,
        },
        "localRecv4SemanticsEvidence": {
            "officialTraceFields": {
                "loopbackSendLen": 160,
                "loopbackRecvLen": 4,
                "loopbackBodyRecvLen": 156,
                "loopbackCmd26StatusLen": 1,
                "externalAuthHeadLen": 199,
                "externalAckLikeLen": 71,
                "externalAuthDataLen": 241,
            },
            "cmd26DirectResponsePath": "deal_local_spice_proxy_head(cmd=0x1a) -> deal_local_recved_cmd_link -> send_tunnel_add_link",
            "cmd26DirectResponseLen": 1,
            "cmd26DirectResponseWriter": "send_tcp_data_with_cache",
            "cmd26DirectResponseExplainsOfficialRecv4": False,
            "cmd10HeaderWriters": [
                "deal_linked_outband_local_data_read",
                "spice_session_write_port_data",
            ],
            "cmd10HeaderShape": {
                "commandByte": 10,
                "channelByte": "derived from channel manage or port channel",
                "lenAtOffset2": "payload length",
                "headerLen": 4,
            },
            "conclusion": "the official loopback recv len=4 should not be treated as the direct ACK for the cmd26 bootstrap frame; trace direction shows it is the accepted-side read of the local proxy header, followed by accepted-side body recv len=156 and a 1-byte cmd26 status sent back to the client fd",
            "payloadStoredInReport": False,
        },
        "writers": [
            {
                "name": "proxy_data_write",
                "observedRole": "passes data,len onward to QUIC/KCP/TCP writer path",
                "rewrapsCommand26ToFresh160Frame": False,
            },
            {
                "name": "QUIC_proxy_data_write",
                "observedRole": "passes data,len onward to QUIC_deal_quic_data_send",
                "rewrapsCommand26ToFresh160Frame": False,
            },
            {
                "name": "udt_write_data",
                "observedRole": "passes data,len onward to SSL_write or ikcp_send",
                "rewrapsCommand26ToFresh160Frame": False,
            },
            {
                "name": "send_tcp_data_with_cache",
                "observedRole": "passes data,len onward to send()",
                "rewrapsCommand26ToFresh160Frame": False,
            },
            {
                "name": "spice_session_write_port_data",
                "observedRole": "writes a cmd=10 port-channel proxy header",
                "rewrapsCommand26ToFresh160Frame": False,
                "excludedReason": "cmd10_port_channel_path_not_fresh_cmd26_bootstrap_shape",
            },
        ],
        "nextStaticTargets": [
            "field value synthesis rules for ChannelLinkSocketEx fields",
            "deal_create_proxy_fd_session and init_local_rw_sock_pair side effects needed before external AUTH_HEAD",
            "which fresh cmd26 fields must be synthesized by Python without local proxy body plaintext replay",
            "AUTH gate-only live only after minimal bootstrap fields are closed",
        ],
        "payloadStoredInReport": False,
    }


def _redacted_summary_diff(left, right, paths):
    diffs = []
    for path in paths:
        cur_left = left
        cur_right = right
        for part in path:
            cur_left = cur_left.get(part) if isinstance(cur_left, dict) else None
            cur_right = cur_right.get(part) if isinstance(cur_right, dict) else None
        if cur_left != cur_right:
            diffs.append({
                "field": ".".join(path),
                "official": cur_left,
                "python": cur_right,
            })
    return diffs


def _contiguous_offset_groups(offsets):
    groups = []
    for offset in offsets:
        if not groups or offset != groups[-1][-1] + 1:
            groups.append([offset])
        else:
            groups[-1].append(offset)
    return [
        {
            "start": group[0],
            "end": group[-1],
            "len": len(group),
        }
        for group in groups
    ]


def _byte_region_class(data):
    data = _bytes(data)
    if not data:
        return "empty"
    if all(item == 0 for item in data):
        return "all-zero"
    if all((48 <= item <= 57) or (65 <= item <= 70) or (97 <= item <= 102) for item in data):
        return "ascii-hex"
    if all(32 <= item < 127 for item in data):
        return "ascii-printable"
    return "binary-or-mixed"


def _local_proxy_body_offset_evidence(group):
    """Map a redacted local-proxy body diff range to recovered IDA read stages."""
    start = int(group.get("start", 0))
    end = int(group.get("end", start))
    if end <= 63:
        return {
            "bodyOffsetStart": start,
            "bodyOffsetEnd": end,
            "frameOffsetStart": start + 4,
            "frameOffsetEnd": end + 4,
            "idaReadStage": "deal_unlinked_outband_head_data",
            "streamRead": "after 4-byte proxy header, reads 64 bytes to complete a 68-byte USB IPC/outband header",
            "dataBufRange": f"data_buf[{104 + start}..{104 + end}]",
            "candidateSemantics": "inside recovered outband header prefix; IDA logs this header as isRegister/messageId/port/type/linkSource/traceID/spanID, but this summary does not expose field values",
            "evidence": [
                "deal_unlinked_unknown_local_data reads the first 4 bytes into data_buf[216..219]",
                "deal_unlinked_outband_head_data then reads bytes into data_buf[proxy_incoming_header_pos + 100] until position 0x44",
            ],
            "confidence": "medium",
            "payloadStoredInReport": False,
        }
    if end <= 111:
        return {
            "bodyOffsetStart": start,
            "bodyOffsetEnd": end,
            "frameOffsetStart": start + 4,
            "frameOffsetEnd": end + 4,
            "idaReadStage": "deal_unlinked_outband_local_data",
            "streamRead": "continues the same outband stream from 68 to 116 bytes before send_tunnel_add_link()",
            "dataBufRange": f"data_buf[{104 + start}..{104 + end}]",
            "candidateSemantics": "inside recovered ChannelLinkSocketEx/tunnel-add-link input region",
            "evidence": [
                "deal_unlinked_outband_local_data reads bytes into data_buf[proxy_incoming_header_pos + 100] until position 0x74",
                "it then derives dest_port from data_buf[108] and calls send_tunnel_add_link()",
            ],
            "confidence": "medium",
            "payloadStoredInReport": False,
        }
    return {
        "bodyOffsetStart": start,
        "bodyOffsetEnd": end,
        "frameOffsetStart": start + 4,
        "frameOffsetEnd": end + 4,
        "idaReadStage": "beyond_recovered_116_byte_outband_local_header",
        "streamRead": "present in the 156-byte local proxy frame but outside the IDA snippets' confirmed 68/116-byte outband header reads",
        "dataBufRange": None,
        "candidateSemantics": "unmapped tail/second-level local-proxy material; it is outside the recovered unlinked 116-byte outband reader and must not be treated as recovered trace_id/span_id or send_tunnel_link_message material without a fresh xref or trace hook",
        "evidence": [
            "fresh trace frame header declares u16BodyLen=156",
            "deal_unlinked_outband_local_data reads only until proxy_incoming_header_pos 0x74, covering frame offsets 0..115 / body offsets 0..111",
            "init_outband_fd_session_bw_ctrl_link_type passes data_buf[118] and data_buf[151] to OpenTelemetry helpers; those map to earlier body offsets, not body[137:152] or body[155]",
            "the official diff shows this tail changes between bootstrap cycles before the ACK-like gate",
            "send_tunnel_add_link() copies OpenTelemetry trace information before calling send_tunnel_link_message()",
            "send_tunnel_link_message() builds a local command-26 buffer with data[1]=id, data[2:4]=154 and writes 158 bytes; fresh bootstrap frames have channel/id byte 0, lenAtOffset2 156 and wireLen 160, so this function is not the direct shape unless another wrapper transforms it",
        ],
        "confidence": "low",
        "payloadStoredInReport": False,
    }


def _load_jsonl_records(path):
    records = []
    invalid = []
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as err:
            invalid.append({"line": line_number, "error": str(err), "text": line[:160]})
    return records, invalid


def auth_gate_field_diff_from_trace(path, *, python_auth_head_segment=None, python_auth_data_segment=None):
    """Build a redacted field diff for the official AUTH gate trace.

    Full packet hex is parsed only in memory.  The returned structure contains
    lengths, KCP/ZTEC header fields, equality/diff counts, and placement facts;
    it deliberately omits auth payload bytes and local proxy frame bodies.
    """
    records, invalid = _load_jsonl_records(path)
    auth_heads = []
    auth_data = []
    local_sends = []
    local_header_recvs = []
    ack_like = []
    for index, record in enumerate(records, 1):
        if record.get("event") != "transport_buffer":
            continue
        raw = bytes.fromhex(str(record.get("hex") or ""))
        direction = str(record.get("direction") or "")
        kind = classify_payload(raw)
        if direction == "send" and kind.startswith("kcp-auth-head"):
            auth_heads.append((index, record, raw))
        elif direction == "send" and kind.startswith("kcp-auth-data"):
            auth_data.append((index, record, raw))
        elif direction == "send" and record.get("len") == 160 and "127.0.0.1:" in str(record.get("peer") or record.get("remote") or ""):
            local_sends.append((index, record, raw))
        elif direction == "receive" and record.get("len") == 4 and "127.0.0.1:" in str(record.get("peer") or record.get("remote") or ""):
            local_header_recvs.append((index, record, raw))
        elif direction == "receive" and record.get("len") == OFFICIAL_AUTH_HEAD_ACK_LIKE_LEN:
            ack_like.append((index, record, raw))

    local_cycles = []
    for send_index, send_record, send_raw in local_sends:
        send_local = str(send_record.get("local") or "")
        send_peer = str(send_record.get("peer") or send_record.get("remote") or "")
        recv_match = next(
            (
                (recv_index, recv_record, recv_raw)
                for recv_index, recv_record, recv_raw in local_header_recvs
                if str(recv_record.get("local") or "") == send_peer
                and str(recv_record.get("peer") or recv_record.get("remote") or "") == send_local
                and recv_index > send_index
            ),
            None,
        )
        item = {
            "clientSendIndex": send_index,
            "serverReceiveHeaderIndex": recv_match[0] if recv_match else None,
            "clientFd": send_record.get("fd"),
            "serverFd": recv_match[1].get("fd") if recv_match else None,
            "clientSend": _redacted_local_proxy_frame_summary(send_raw),
            "serverReceiveHeader": _redacted_local_proxy_frame_summary(recv_match[2]) if recv_match else None,
            "serverHeaderMatchesClient": bool(recv_match and send_raw[:4] == recv_match[2][:4]),
            "payloadStoredInReport": False,
        }
        local_cycles.append(item)

    local_body_diff = None
    if len(local_sends) >= 2:
        first = local_sends[0][2][4:]
        second = local_sends[1][2][4:]
        differing_offsets = [idx for idx, (left, right) in enumerate(zip(first, second)) if left != right]
        differing_offsets.extend(range(min(len(first), len(second)), max(len(first), len(second))))
        body_groups = _contiguous_offset_groups(differing_offsets)
        frame_groups = [
            {
                "start": item["start"] + 4,
                "end": item["end"] + 4,
                "len": item["len"],
            }
            for item in body_groups
        ]
        group_classes = []
        for item in body_groups:
            left_region = first[item["start"]:item["end"] + 1]
            right_region = second[item["start"]:item["end"] + 1]
            group_classes.append({
                "bodyOffsetStart": item["start"],
                "bodyOffsetEnd": item["end"],
                "len": item["len"],
                "firstRegionClass": _byte_region_class(left_region),
                "secondRegionClass": _byte_region_class(right_region),
                "payloadStoredInReport": False,
            })
        local_body_diff = {
            "firstSendIndex": local_sends[0][0],
            "secondSendIndex": local_sends[1][0],
            "equal": first == second,
            "comparedBytes": min(len(first), len(second)),
            "differingBytes": len(differing_offsets),
            "differingBodyOffsetGroups": body_groups,
            "differingFrameOffsetGroups": frame_groups,
            "differingRegionClasses": group_classes,
            "differingOffsetEvidence": [_local_proxy_body_offset_evidence(item) for item in body_groups],
            "payloadStoredInReport": False,
        }

    official_auth_head_summary = redacted_kcp_auth_wire_summary(auth_heads[0][2]) if auth_heads else None
    official_auth_data_summary = redacted_kcp_auth_wire_summary(auth_data[0][2]) if auth_data else None
    python_auth_head_summary = redacted_kcp_auth_wire_summary(python_auth_head_segment) if python_auth_head_segment else None
    python_auth_data_summary = redacted_kcp_auth_wire_summary(python_auth_data_segment) if python_auth_data_segment else None
    compare_paths = [
        ("wireLen",),
        ("declaredLen",),
        ("declaredPayloadBytes",),
        ("tailBytesAfterDeclaredPayload",),
        ("authBytesPlacement",),
        ("ztecAuthHead", "headerLenField"),
        ("ztecAuthHead", "authHeadLenFromHeader"),
        ("ztecAuthHead", "bufferType"),
        ("ztecAuthHead", "authDataLenField"),
        ("ztecAuthHead", "opentelemetry"),
        ("ztecAuthHead", "linkTypeFromExtendLow16"),
        ("ztecAuthHead", "linkTypeFromExtendHigh7"),
        ("ztecAuthHead", "otelTraceIdRegion", "nonZeroBytes"),
        ("ztecAuthHead", "otelSpanIdRegion", "nonZeroBytes"),
    ]
    return {
        "ok": bool(auth_heads),
        "sourceTrace": str(path),
        "records": len(records),
        "invalidLines": invalid,
        "official": {
            "authHeadSendIndexes": [item[0] for item in auth_heads[:8]],
            "authHeadSendCountBeforeFirstAckLike": len([item for item in auth_heads if not ack_like or item[0] < ack_like[0][0]]),
            "ackLikeIndexes": [item[0] for item in ack_like[:8]],
            "authDataSendIndexes": [item[0] for item in auth_data[:8]],
            "firstAuthHead": official_auth_head_summary,
            "firstAuthData": official_auth_data_summary,
            "localProxyCycles": local_cycles[:8],
            "localProxyFirstTwoBodyDiff": local_body_diff,
            "localProxyWriterChainEvidence": _local_proxy_writer_chain_evidence(),
        },
        "python": {
            "authHead": python_auth_head_summary,
            "authData": python_auth_data_summary,
        },
        "redactedDiff": {
            "authHeadOfficialVsPython": (
                _redacted_summary_diff(official_auth_head_summary, python_auth_head_summary, compare_paths)
                if official_auth_head_summary and python_auth_head_summary
                else []
            ),
            "authDataOfficialVsPython": (
                _redacted_summary_diff(official_auth_data_summary, python_auth_data_summary, [
                    ("wireLen",),
                    ("declaredLen",),
                    ("declaredPayloadBytes",),
                    ("tailBytesAfterDeclaredPayload",),
                    ("authBytesPlacement",),
                ])
                if official_auth_data_summary and python_auth_data_summary
                else []
            ),
        },
        "interpretation": {
            "officialAuthBytesPlacement": official_auth_head_summary.get("authBytesPlacement") if official_auth_head_summary else None,
            "criticalGateField": "KCP declared len is 0 while ZTEC auth bytes are carried as tail/rest after the 21-byte KCP header",
            "notSuccessProof": True,
            "payloadStoredInReport": False,
        },
        "payloadPolicy": "full hex is parsed in memory only; output omits auth payload bytes and local proxy frame bodies",
    }


def _c_string_bytes(value, size, field_name):
    if size <= 0:
        raise ValueError(f"{field_name} size must be positive")
    raw = str(value or "").encode("utf-8")
    if len(raw) >= size:
        raw = raw[: size - 1]
    return raw + (b"\x00" * (size - len(raw)))


def _serial_uuid_bytes(value):
    if value in (None, ""):
        return b"\x00" * 16
    if isinstance(value, str):
        text = value.strip()
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            raw = text.encode("utf-8")
    else:
        raw = _bytes(value)
    if len(raw) != 16:
        raise ValueError("serial_uuid must be exactly 16 bytes")
    return raw


def _random_u32(value):
    if value is None:
        return int.from_bytes(os.urandom(4), "little")
    return int(value) & 0xFFFFFFFF


def _fresh_cmd26_default_priority(channel_type):
    channel_type = int(channel_type)
    if channel_type in {1, 3}:
        return 1
    if channel_type == 2:
        return 3
    return 2


def build_fresh_cmd26_bootstrap_frame(
    *,
    dest_ip,
    dest_port,
    channel_type=1,
    channel_id=0,
    link_priority=None,
    link_type=0,
    serial_num=None,
    vm_uuid="",
    protocol_type=0,
    be_emergency=0,
    bw_ctrl=0,
    tbw_ctrl=0,
    flag=0,
    channel_type_field=0,
    extend=None,
    trace_id="",
    parent_id="",
):
    """Build the fresh cmd26 loopback bootstrap frame from static producer rules.

    This mirrors the recovered ``add_link_to_proxy_by_socket()`` output shape:
    ``cmd=0x1a, channel/id=0, u16BodyLen=0x9c, body=ChannelLinkSocketEx``.
    The returned summary is safe to persist; it deliberately omits destination
    values and the generated frame body.
    """
    port = int(dest_port)
    if not 0 <= port <= 0xFFFF:
        raise ValueError("dest_port must fit in uint16")
    channel_type = int(channel_type)
    channel_id = int(channel_id)
    if not 0 <= channel_type <= 0x7F:
        raise ValueError("channel_type must fit in 7 bits")
    if not 0 <= channel_id <= 0xFF:
        raise ValueError("channel_id must fit in uint8")
    if link_priority is None:
        link_priority = _fresh_cmd26_default_priority(channel_type)
    link_priority = int(link_priority)
    if not 0 <= link_priority <= 0xFF:
        raise ValueError("link_priority must fit in uint8")
    link_type = int(link_type)
    if not 0 <= link_type <= 0xFF:
        raise ValueError("link_type must fit in uint8")

    body = bytearray(FRESH_CMD26_BODY_LEN)
    struct.pack_into("<H", body, FRESH_CMD26_DEST_PORT_OFFSET, port)
    body[FRESH_CMD26_LINK_PRIORITY_OFFSET] = link_priority
    body[FRESH_CMD26_LINK_TYPE_OFFSET] = link_type

    try:
        ip_obj = ipaddress.ip_address(str(dest_ip))
    except ValueError as exc:
        raise ValueError("dest_ip must be a valid IPv4 or IPv6 address") from exc
    if ip_obj.version == 4:
        body[FRESH_CMD26_DEST_IP_OFFSET:FRESH_CMD26_DEST_IP_OFFSET + 4] = ipv4_to_little_endian(str(ip_obj))
        ip_family = "ipv4"
        ip_storage = "host_order_u32_little_endian"
    else:
        body[FRESH_CMD26_IPV6_OFFSET:FRESH_CMD26_IPV6_OFFSET + 16] = ip_obj.packed
        ip_family = "ipv6"
        ip_storage = "inet_pton_ipv6_bytes"

    body[FRESH_CMD26_SERIAL_NUM_OFFSET:FRESH_CMD26_SERIAL_NUM_OFFSET + 16] = _serial_uuid_bytes(serial_num)
    body[FRESH_CMD26_VM_UUID_OFFSET:FRESH_CMD26_VM_UUID_OFFSET + 37] = _c_string_bytes(vm_uuid, 37, "vm_uuid")
    for value, offset, field_name in (
        (protocol_type, FRESH_CMD26_PROTOCOL_TYPE_OFFSET, "protocol_type"),
        (be_emergency, FRESH_CMD26_BE_EMERGENCY_OFFSET, "be_emergency"),
        (flag, FRESH_CMD26_FLAG_OFFSET, "flag"),
    ):
        value = int(value)
        if not 0 <= value <= 0xFF:
            raise ValueError(f"{field_name} must fit in uint8")
        body[offset] = value
    for value, offset, field_name in (
        (bw_ctrl, FRESH_CMD26_BW_CTRL_OFFSET, "bw_ctrl"),
        (tbw_ctrl, FRESH_CMD26_TBW_CTRL_OFFSET, "tbw_ctrl"),
    ):
        value = int(value)
        if not 0 <= value <= 0xFFFF:
            raise ValueError(f"{field_name} must fit in uint16")
        struct.pack_into("<H", body, offset, value)
    channel_type_field = int(channel_type_field)
    if not 0 <= channel_type_field <= 0xFFFFFFFF:
        raise ValueError("channel_type_field must fit in uint32")
    struct.pack_into("<I", body, FRESH_CMD26_CHANNEL_TYPE_OFFSET, channel_type_field)
    body[FRESH_CMD26_EXTEND_OFFSET:FRESH_CMD26_EXTEND_OFFSET + 16] = _fixed_bytes(
        extend or b"\x00" * 16,
        16,
        "extend",
    )
    body[
        FRESH_CMD26_OTLP_TRACE_ID_OFFSET:
        FRESH_CMD26_OTLP_TRACE_ID_OFFSET + FRESH_CMD26_OTLP_TRACE_ID_SIZE
    ] = _c_string_bytes(trace_id, FRESH_CMD26_OTLP_TRACE_ID_SIZE, "trace_id")
    body[
        FRESH_CMD26_OTLP_PARENT_ID_OFFSET:
        FRESH_CMD26_OTLP_PARENT_ID_OFFSET + FRESH_CMD26_OTLP_PARENT_ID_SIZE
    ] = _c_string_bytes(parent_id, FRESH_CMD26_OTLP_PARENT_ID_SIZE, "parent_id")
    channel_type_id = (channel_type << 8) | channel_id
    struct.pack_into("<H", body, FRESH_CMD26_CHANNEL_TYPE_ID_OFFSET, channel_type_id)

    frame = (
        struct.pack("<BBH", FRESH_CMD26_COMMAND, FRESH_CMD26_CHANNEL_PREFIX, FRESH_CMD26_BODY_LEN)
        + bytes(body)
    )
    summary = {
        "sourceType": "fresh-cmd26-bootstrap-builder",
        "producerFunction": "add_link_to_proxy_by_socket",
        "wireLen": len(frame),
        "bodyLen": len(body),
        "commandByte": FRESH_CMD26_COMMAND,
        "channelOrIdByte": FRESH_CMD26_CHANNEL_PREFIX,
        "payloadStoredInReport": False,
        "destination": {
            "ipFamily": ip_family,
            "ipStorage": ip_storage,
            "destIpStoredInSummary": False,
            "destPortStoredInSummary": False,
        },
        "fieldSources": {
            "dest_ip": "SpiceSessionPrivate.hostip if nonempty, otherwise SpiceSessionPrivate.host",
            "dest_port": "get_channel_proxy_link_dest_port(session/channel state)",
            "link_priority": "get_channel_proxy_link_priority(channel_type)",
            "trace_id": "caller argument + 0x400, generated locally for Python builder",
            "parent_id": "caller argument + 0x421, generated locally for Python builder",
            "channel_type_id": "(channel_type << 8) | channel_id",
        },
        "channelType": channel_type,
        "channelId": channel_id,
        "channelTypeIdHex": f"0x{channel_type_id:04x}",
        "linkPriority": link_priority,
        "linkType": link_type,
        "officialTraceFields": [
            "loopback client send len=160 cmd26",
            "accepted-side recv len=156 ChannelLinkSocketEx body",
            "client-side recv len=1 cmd26 status",
            "external AUTH_HEAD len=199 follows local proxy/session setup",
        ],
        "gateBoundary": "builder only; no SYNACK/native bridge/DISPLAY_INIT/verified-run side effects",
    }
    return {"frame": frame, "summary": summary}


def summarize_fresh_cmd26_bootstrap_frame(frame):
    """Return a redacted structural summary for a generated cmd26 frame."""
    packet = _bytes(frame)
    if len(packet) < 4:
        raise ValueError("fresh cmd26 frame is incomplete")
    body_len = _u16le(packet, 2)
    body = packet[4:4 + body_len]
    channel_type_id = _u16le(body, FRESH_CMD26_CHANNEL_TYPE_ID_OFFSET) if len(body) >= FRESH_CMD26_BODY_LEN else None
    return {
        "present": True,
        "wireLen": len(packet),
        "commandByte": packet[0],
        "channelOrIdByte": packet[1],
        "u16BodyLen": body_len,
        "shapeMatchesFreshCmd26": (
            packet[0] == FRESH_CMD26_COMMAND
            and packet[1] == FRESH_CMD26_CHANNEL_PREFIX
            and body_len == FRESH_CMD26_BODY_LEN
            and len(packet) == FRESH_CMD26_WIRE_LEN
        ),
        "payloadStoredInReport": False,
        "fieldSummary": {
            "linkPriority": body[FRESH_CMD26_LINK_PRIORITY_OFFSET] if len(body) >= FRESH_CMD26_BODY_LEN else None,
            "linkType": body[FRESH_CMD26_LINK_TYPE_OFFSET] if len(body) >= FRESH_CMD26_BODY_LEN else None,
            "ipFamilyHint": "ipv6" if len(body) >= FRESH_CMD26_BODY_LEN and any(body[FRESH_CMD26_IPV6_OFFSET:FRESH_CMD26_IPV6_OFFSET + 16]) else "ipv4_or_zero",
            "channelType": ((channel_type_id >> 8) & 0x7F) if channel_type_id is not None else None,
            "channelId": (channel_type_id & 0xFF) if channel_type_id is not None else None,
            "channelTypeIdHex": f"0x{channel_type_id:04x}" if channel_type_id is not None else None,
        },
    }


def build_ztec_cag_type101_auth_buffer(
    *,
    username,
    password,
    vmid,
    dest_ip,
    dest_port,
    serial_uuid=None,
    random_c=None,
    link_type=ZTEC_CAG_TYPE101_LINK_TYPE_PROXY,
    opentelemetry=False,
    trace_id="",
    span_id="",
):
    """Build the official CAG type-101 ZTEC auth buffer shape.

    This mirrors the non-UAC path recovered from ``deal_udt_using_cag()``.
    Sensitive fields are written only into the returned in-memory
    ``authBuffer`` bytes.  The summary deliberately contains only structural
    facts needed by readiness reports and must remain safe to persist.
    """
    port = int(dest_port)
    if not 0 <= port <= 0xFFFF:
        raise ValueError("dest_port must fit in uint16")
    link_type = int(link_type)
    if not 0 <= link_type <= 0xFFFF:
        raise ValueError("link_type must fit in uint16")
    head_len_field = (
        ZTEC_CAG_TYPE101_OTEL_HEAD_LEN
        if opentelemetry
        else ZTEC_CAG_TYPE101_HEAD_LEN
    )
    proxy_offset = (
        ZTEC_CAG_TYPE101_OTEL_PROXY_OFFSET
        if opentelemetry
        else ZTEC_CAG_TYPE101_PROXY_OFFSET
    )
    buffer_len = proxy_offset + ZTEC_CAG_TYPE101_DATA_LEN
    auth_buffer = bytearray(buffer_len)
    auth_buffer[:4] = ZTEC_MAGIC
    struct.pack_into("<H", auth_buffer, 4, head_len_field)
    struct.pack_into("<I", auth_buffer, 6, ZTEC_CAG_TYPE101)
    random_value = _random_u32(random_c)
    struct.pack_into("<I", auth_buffer, 10, random_value)
    struct.pack_into("<I", auth_buffer, 14, ZTEC_CAG_TYPE101_DATA_LEN)
    auth_buffer[18:34] = _serial_uuid_bytes(serial_uuid)
    extend0 = (link_type << 16) | ((link_type << 24) & 0x7F000000)
    if opentelemetry:
        extend0 |= 0x04
        auth_buffer[50:114] = _c_string_bytes(trace_id, 64, "trace_id")
        auth_buffer[114:178] = _c_string_bytes(span_id, 64, "span_id")
    struct.pack_into("<I", auth_buffer, 34, extend0)

    proxy = proxy_offset
    struct.pack_into("<H", auth_buffer, proxy + ZTEC_CAG_TYPE101_PROXY_DEST_PORT_OFFSET, port)
    ip_flags = 0
    try:
        dest_ip_raw = socket.inet_pton(socket.AF_INET, str(dest_ip))
    except OSError:
        try:
            dest_ip_raw = socket.inet_pton(socket.AF_INET6, str(dest_ip))
            ip_flags = 1
        except OSError as exc:
            raise ValueError("dest_ip must be a valid IPv4 or IPv6 address") from exc
    auth_buffer[
        proxy + ZTEC_CAG_TYPE101_PROXY_DEST_IP_OFFSET:
        proxy + ZTEC_CAG_TYPE101_PROXY_DEST_IP_OFFSET + len(dest_ip_raw)
    ] = dest_ip_raw
    auth_buffer[
        proxy + ZTEC_CAG_TYPE101_PROXY_CLIENT_UUID_OFFSET:
        proxy + ZTEC_CAG_TYPE101_PROXY_CLIENT_UUID_OFFSET + 40
    ] = _c_string_bytes(vmid, 40, "vmid")
    auth_buffer[
        proxy + ZTEC_CAG_TYPE101_PROXY_USERNAME_OFFSET:
        proxy + ZTEC_CAG_TYPE101_PROXY_USERNAME_OFFSET + 64
    ] = _c_string_bytes(username, 64, "username")
    auth_buffer[
        proxy + ZTEC_CAG_TYPE101_PROXY_PASSWD_OFFSET:
        proxy + ZTEC_CAG_TYPE101_PROXY_PASSWD_OFFSET + 64
    ] = _c_string_bytes(password, 64, "password")
    struct.pack_into("<H", auth_buffer, proxy + ZTEC_CAG_TYPE101_PROXY_FLAGS_OFFSET, ip_flags)
    return {
        "authBuffer": bytes(auth_buffer),
        "summary": {
            "sourceType": "fresh-cag-type101-builder",
            "magic": "ZTEC",
            "bufferType": ZTEC_CAG_TYPE101,
            "bufferTypeName": "cag-password-auth",
            "headerLenField": head_len_field,
            "authHeadLen": proxy_offset,
            "authDataLen": ZTEC_CAG_TYPE101_DATA_LEN,
            "totalBufferLen": buffer_len,
            "proxyDataOffset": proxy_offset,
            "proxyDataLen": ZTEC_CAG_TYPE101_PROXY_DATA_SIZE,
            "linkType": link_type,
            "opentelemetry": bool(opentelemetry),
            "serialPresent": serial_uuid not in (None, ""),
            "randomPresent": bool(random_value),
            "destIpFamily": "ipv6" if ip_flags else "ipv4",
            "payloadStoredInReport": False,
            "payloadPolicy": "username/password/vmid/dest fields are present only in authBuffer bytes for immediate live use and must not be written to reports",
            "readyForAuthPreflight": True,
        },
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


def _cag_material_destination(connect_info, raw_args, link_type):
    """Select the auth-buffer destination using the official CAG link_type rules."""
    link_type = int(link_type)
    if link_type == ZTEC_CAG_TYPE101_LINK_TYPE_VM_PROXY:
        dest_ip = (
            connect_info.get("vmHost")
            or _first_connect_arg_value(raw_args.get("vmip"))
            or connect_info.get("vmHostV6")
            or _first_connect_arg_value(raw_args.get("vmipv6"))
            or connect_info.get("vm_ip")
            or connect_info.get("host")
            or connect_info.get("h")
        )
        dest_port = (
            connect_info.get("vmPort")
            or raw_args.get("vmport")
            or connect_info.get("vmPortV6")
            or raw_args.get("vmportv6")
            or connect_info.get("vm_proxy_port")
            or connect_info.get("port")
            or connect_info.get("p")
        )
        source = "vm_proxy"
    elif link_type == ZTEC_CAG_TYPE101_LINK_TYPE_ICE:
        dest_ip = connect_info.get("host") or connect_info.get("h")
        dest_port = raw_args.get("p") or connect_info.get("p") or connect_info.get("port")
        source = "ice_host_port"
    else:
        dest_ip = connect_info.get("host") or connect_info.get("h")
        dest_port = (
            connect_info.get("port")
            or raw_args.get("proxy-sport")
            or raw_args.get("proxy_port")
            or raw_args.get("proxy-port")
            or raw_args.get("p")
            or connect_info.get("p")
        )
        source = "proxy_gateway"
    if isinstance(dest_ip, str) and (";" in dest_ip or "," in dest_ip):
        dest_ip = next((part.strip() for part in dest_ip.replace(",", ";").split(";") if part.strip()), "")
    return {
        "destIp": dest_ip,
        "destPort": dest_port,
        "source": source,
        "destFromVmArgs": source == "vm_proxy",
    }


def describe_official_kcp_destination_source(connect_info, *, fd_type_ex="TN_MULTI_TCP_SOCK"):
    """Return redacted evidence for official get_proxy_kcp_dst_ip/port routing.

    IDA evidence shows this helper selects the KCP socket destination, not the
    destination fields embedded in the CAG type101/type102 auth buffer.
    """
    connect_info = connect_info or {}
    raw_args = connect_info.get("rawArgs") or {}
    proxy_type = str(connect_info.get("type") or raw_args.get("type") or "").lower()
    enable_cag = bool(
        connect_info.get("enableCag")
        or connect_info.get("cagexist")
        or connect_info.get("cagExists")
        or raw_args.get("cagexist")
        or raw_args.get("cag-exist")
        or connect_info.get("agIp")
        or connect_info.get("ag_ip")
        or raw_args.get("ag-ip")
        or raw_args.get("ag_ip")
    )
    fd_type = str(fd_type_ex or "")
    if fd_type == "TN_MULTI_TCP_SOCK":
        if enable_cag:
            source = "cag_ag_ip_port"
        elif proxy_type == "ice":
            source = "ice_host_vm_proxy_port"
        else:
            source = "vm_ip_vm_proxy_port"
    elif enable_cag:
        source = "cag_ag_ip_port"
    else:
        source = "host_spice_proxy_port"
    return {
        "sourceType": "ida-get-proxy-kcp-destination-source",
        "fdType": fd_type,
        "proxyType": proxy_type or None,
        "enableCag": enable_cag,
        "destinationSource": source,
        "payloadStoredInReport": False,
        "payloadPolicy": "destination values are intentionally omitted; this helper reports only the source class",
        "evidence": (
            "IDA get_proxy_kcp_dst_ip/get_proxy_kcp_dst_port: CAG returns ag_ip/ag_port; "
            "TN_MULTI_TCP_SOCK without CAG returns vm_ip/vm_proxy_port except ice uses host; "
            "non-multi TCP uses ag_ip/ag_port for CAG or get_spice_proxy_dst_port otherwise"
        ),
        "notAuthBufferDestination": True,
    }


def build_ztec_cag_type101_auth_buffer_from_material(
    auth,
    connect_info,
    *,
    serial_uuid=None,
    random_c=None,
    link_type=ZTEC_CAG_TYPE101_LINK_TYPE_PROXY,
    opentelemetry=False,
    trace_id="",
    span_id="",
):
    """Build type-101 auth bytes from in-memory CAG auth/connect material."""
    auth = auth or {}
    connect_info = connect_info or {}
    raw_args = connect_info.get("rawArgs") or {}
    username = auth.get("vmUserName") or auth.get("username")
    password = auth.get("vmPassword") or auth.get("password")
    vmid = (
        connect_info.get("vmid")
        or connect_info.get("vmId")
        or raw_args.get("vmid")
        or auth.get("vmId")
        or auth.get("vmID")
        or auth.get("uuid")
    )
    destination = _cag_material_destination(connect_info, raw_args, link_type)
    dest_ip = destination["destIp"]
    dest_port = destination["destPort"]
    missing = [
        name
        for name, value in [
            ("vmUserName", username),
            ("vmPassword", password),
            ("vmid", vmid),
            ("destHost", dest_ip),
            ("destPort", dest_port),
        ]
        if value in (None, "")
    ]
    if missing:
        raise ValueError("CAG type101 material is missing: " + ", ".join(missing))
    built = build_ztec_cag_type101_auth_buffer(
        username=username,
        password=password,
        vmid=vmid,
        dest_ip=dest_ip,
        dest_port=dest_port,
        serial_uuid=serial_uuid,
        random_c=random_c,
        link_type=link_type,
        opentelemetry=opentelemetry,
        trace_id=trace_id,
        span_id=span_id,
    )
    built["summary"] = {
        **built["summary"],
        "sourceType": "fresh-cag-material-type101-builder",
        "materialFieldsPresent": {
            "vmUserName": True,
            "vmPassword": True,
            "vmid": True,
            "udpHost": bool(connect_info.get("host")),
            "udpPort": bool(connect_info.get("port")),
            "destHost": True,
            "destPort": True,
            "destFromVmArgs": bool(destination["destFromVmArgs"]),
        },
        "destinationSource": destination["source"],
        "officialKcpDestinationEvidence": describe_official_kcp_destination_source(connect_info),
        "linkTypeSelectionEvidence": "IDA deal_udt_using_cag: link_type 11 uses host/proxy_sport or proxy_port; link_type 139 uses host/port for ice; link_type 140 uses vm_ip/vm_proxy_port when sock link flag is 2",
    }
    return built


def _padded_token_bytes(token, field_name="token"):
    raw = str(token or "").encode("utf-8")
    if not raw:
        raise ValueError(f"{field_name} is required")
    padded_len = len(raw) + 1
    if padded_len & 0x0F:
        padded_len = 16 * ((padded_len >> 4) + 1)
    if padded_len > 0xFFFF:
        raise ValueError(f"{field_name} padded length must fit in uint16")
    return raw + (b"\x00" * (padded_len - len(raw))), padded_len


def build_ztec_cag_type102_auth_buffer(
    *,
    username,
    token,
    vmid,
    dest_ip,
    dest_port,
    serial_uuid=None,
    random_c=None,
    link_type=ZTEC_CAG_TYPE101_LINK_TYPE_PROXY,
    opentelemetry=False,
    trace_id="",
    span_id="",
    auth_type=None,
    token_source="uactoken",
):
    """Build the official CAG type-102 UAC/token ZTEC auth buffer shape.

    DWARF evidence for ``TnProxyUacData_s``:
    ``dest_port@0, flag_@2, dest_ip@4, client_uuid@20, username@60,
    flags@92, reserve@94, extend@96, pwd_len@124, passwd@126`` with a
    fixed base size of 126 bytes.  ``deal_udt_using_cag_uac()`` appends the
    padded token bytes at ``passwd`` and advertises ``data_len = pd_len + 126``.
    """
    port = int(dest_port)
    if not 0 <= port <= 0xFFFF:
        raise ValueError("dest_port must fit in uint16")
    link_type = int(link_type)
    if not 0 <= link_type <= 0xFFFF:
        raise ValueError("link_type must fit in uint16")
    token_bytes, padded_len = _padded_token_bytes(token, "token")
    head_len_field = (
        ZTEC_CAG_TYPE102_OTEL_HEAD_LEN
        if opentelemetry
        else ZTEC_CAG_TYPE102_HEAD_LEN
    )
    proxy_offset = (
        ZTEC_CAG_TYPE102_OTEL_PROXY_OFFSET
        if opentelemetry
        else ZTEC_CAG_TYPE102_PROXY_OFFSET
    )
    auth_data_len = ZTEC_CAG_TYPE102_BASE_DATA_LEN + padded_len
    buffer_len = proxy_offset + auth_data_len
    auth_buffer = bytearray(buffer_len)
    auth_buffer[:4] = ZTEC_MAGIC
    struct.pack_into("<H", auth_buffer, 4, head_len_field)
    struct.pack_into("<I", auth_buffer, 6, ZTEC_CAG_TYPE102)
    random_value = _random_u32(random_c)
    struct.pack_into("<I", auth_buffer, 10, random_value)
    struct.pack_into("<I", auth_buffer, 14, auth_data_len)
    auth_buffer[18:34] = _serial_uuid_bytes(serial_uuid)
    extend0 = (link_type << 16) | ((link_type << 24) & 0x7F000000)
    if opentelemetry:
        extend0 |= 0x04
        auth_buffer[50:114] = _c_string_bytes(trace_id, 64, "trace_id")
        auth_buffer[114:178] = _c_string_bytes(span_id, 64, "span_id")
    struct.pack_into("<I", auth_buffer, 34, extend0)

    proxy = proxy_offset
    struct.pack_into("<H", auth_buffer, proxy + ZTEC_CAG_TYPE102_PROXY_DEST_PORT_OFFSET, port)
    ip_flags = 0
    try:
        dest_ip_raw = socket.inet_pton(socket.AF_INET, str(dest_ip))
    except OSError:
        try:
            dest_ip_raw = socket.inet_pton(socket.AF_INET6, str(dest_ip))
            ip_flags = 1
        except OSError as exc:
            raise ValueError("dest_ip must be a valid IPv4 or IPv6 address") from exc
    auth_buffer[
        proxy + ZTEC_CAG_TYPE102_PROXY_DEST_IP_OFFSET:
        proxy + ZTEC_CAG_TYPE102_PROXY_DEST_IP_OFFSET + len(dest_ip_raw)
    ] = dest_ip_raw
    auth_buffer[
        proxy + ZTEC_CAG_TYPE102_PROXY_CLIENT_UUID_OFFSET:
        proxy + ZTEC_CAG_TYPE102_PROXY_CLIENT_UUID_OFFSET + 40
    ] = _c_string_bytes(vmid, 40, "vmid")
    auth_buffer[
        proxy + ZTEC_CAG_TYPE102_PROXY_USERNAME_OFFSET:
        proxy + ZTEC_CAG_TYPE102_PROXY_USERNAME_OFFSET + 32
    ] = _c_string_bytes(username, 32, "username")
    struct.pack_into("<H", auth_buffer, proxy + ZTEC_CAG_TYPE102_PROXY_FLAGS_OFFSET, ip_flags)
    struct.pack_into("<H", auth_buffer, proxy + ZTEC_CAG_TYPE102_PROXY_PWD_LEN_OFFSET, padded_len)
    auth_buffer[
        proxy + ZTEC_CAG_TYPE102_PROXY_PASSWD_OFFSET:
        proxy + ZTEC_CAG_TYPE102_PROXY_PASSWD_OFFSET + padded_len
    ] = token_bytes
    return {
        "authBuffer": bytes(auth_buffer),
        "summary": {
            "sourceType": "fresh-cag-type102-builder",
            "magic": "ZTEC",
            "bufferType": ZTEC_CAG_TYPE102,
            "bufferTypeName": "cag-uac-token-auth",
            "headerLenField": head_len_field,
            "authHeadLen": proxy_offset,
            "authDataLen": auth_data_len,
            "totalBufferLen": buffer_len,
            "proxyDataOffset": proxy_offset,
            "proxyDataLen": auth_data_len,
            "proxyBaseDataLen": ZTEC_CAG_TYPE102_BASE_DATA_LEN,
            "paddedTokenLen": padded_len,
            "linkType": link_type,
            "authType": str(auth_type) if auth_type not in (None, "") else None,
            "tokenSource": token_source,
            "opentelemetry": bool(opentelemetry),
            "serialPresent": serial_uuid not in (None, ""),
            "randomPresent": bool(random_value),
            "destIpFamily": "ipv6" if ip_flags else "ipv4",
            "layoutEvidence": "DWARF TnProxyUacData_s byte_size=126; passwd offset=126; deal_udt_using_cag_uac data_len=pd_len+126",
            "payloadStoredInReport": False,
            "payloadPolicy": "username/token/vmid/dest fields are present only in authBuffer bytes for immediate live use and must not be written to reports",
            "readyForAuthPreflight": True,
        },
    }


def build_ztec_cag_type102_auth_buffer_from_material(
    auth,
    connect_info,
    *,
    auth_type=None,
    serial_uuid=None,
    random_c=None,
    link_type=ZTEC_CAG_TYPE101_LINK_TYPE_PROXY,
    opentelemetry=False,
    trace_id="",
    span_id="",
):
    """Build type-102 UAC/token auth bytes from in-memory CAG material."""
    auth = auth or {}
    connect_info = connect_info or {}
    raw_args = connect_info.get("rawArgs") or {}
    resolved_auth_type = str(
        auth_type
        or connect_info.get("authType")
        or raw_args.get("auth_type")
        or raw_args.get("auth-type")
        or raw_args.get("token-logon")
        or auth.get("authType")
        or ""
    )
    if resolved_auth_type == "2":
        token_value = (
            connect_info.get("accessToken")
            or raw_args.get("accessToken")
            or auth.get("accessToken")
            or auth.get("tokenInfo", {}).get("accessToken")
        )
        token_source = "access_token"
    else:
        token_value = (
            auth.get("uactoken")
            or auth.get("uacToken")
            or connect_info.get("uactoken")
            or raw_args.get("uactoken")
        )
        token_source = "uactoken"
    username = auth.get("vmUserName") or auth.get("username") or connect_info.get("username")
    vmid = (
        connect_info.get("vmid")
        or connect_info.get("vmId")
        or raw_args.get("vmid")
        or auth.get("vmId")
        or auth.get("vmID")
        or auth.get("uuid")
    )
    destination = _cag_material_destination(connect_info, raw_args, link_type)
    dest_ip = destination["destIp"]
    dest_port = destination["destPort"]
    missing = [
        name
        for name, value in [
            ("username", username),
            (token_source, token_value),
            ("vmid", vmid),
            ("destHost", dest_ip),
            ("destPort", dest_port),
        ]
        if value in (None, "")
    ]
    if missing:
        raise ValueError("CAG type102 material is missing: " + ", ".join(missing))
    built = build_ztec_cag_type102_auth_buffer(
        username=username,
        token=token_value,
        vmid=vmid,
        dest_ip=dest_ip,
        dest_port=dest_port,
        serial_uuid=serial_uuid,
        random_c=random_c,
        link_type=link_type,
        opentelemetry=opentelemetry,
        trace_id=trace_id,
        span_id=span_id,
        auth_type=resolved_auth_type,
        token_source=token_source,
    )
    built["summary"] = {
        **built["summary"],
        "sourceType": "fresh-cag-material-type102-builder",
        "materialFieldsPresent": {
            "username": True,
            "token": True,
            "vmid": True,
            "udpHost": bool(connect_info.get("host")),
            "udpPort": bool(connect_info.get("port")),
            "destHost": True,
            "destPort": True,
            "destFromVmArgs": bool(destination["destFromVmArgs"]),
            "accessToken": token_source == "access_token",
            "uactoken": token_source == "uactoken",
        },
        "destinationSource": destination["source"],
        "officialKcpDestinationEvidence": describe_official_kcp_destination_source(connect_info),
        "linkTypeSelectionEvidence": "IDA deal_udt_using_cag_uac uses the same destination rules as type101: link_type 11 gateway, 139 ice host/port, 140 vm_ip/vm_proxy_port",
    }
    return built


def parse_ztec_auth_buffer(auth_buffer):
    """Parse and split the official ZTEC auth buffer without logging secrets.

    IDA evidence shows ``ikcp_set_auth_data(kcp, pBuffer, head_len, data_len, ...)``
    splits a ZTEC auth buffer into auth-head and auth-data KCP envelopes.  This
    helper accepts only an already-fresh in-memory buffer and returns the byte
    slices plus a redacted summary.  Callers must keep the returned payload
    bytes out of reports.
    """
    packet = _bytes(auth_buffer)
    if len(packet) < ZTEC_AUTH_HEADER_SIZE:
        raise ValueError("ZTEC auth buffer is incomplete")
    if packet[:4] != ZTEC_MAGIC:
        raise ValueError("ZTEC auth buffer magic is missing")
    header_len_field = _u16le(packet, 4)
    auth_head_len = header_len_field + 6
    auth_data_len = _u32le(packet, 14)
    auth_data_offset = auth_head_len
    auth_data_end = auth_data_offset + auth_data_len
    if auth_head_len < ZTEC_AUTH_HEADER_SIZE or auth_head_len > len(packet):
        raise ValueError("ZTEC auth head length is outside the buffer")
    if auth_data_end > len(packet):
        raise ValueError("ZTEC auth data length exceeds the buffer")
    buffer_type = _u32le(packet, 6)
    random_c = _u32le(packet, 10)
    auth_head = packet[:auth_head_len]
    auth_data = packet[auth_data_offset:auth_data_end]
    return {
        "authHead": auth_head,
        "authData": auth_data,
        "summary": {
            "magic": "ZTEC",
            "bufferType": buffer_type,
            "bufferTypeName": {
                101: "cag-password-auth",
                102: "cag-uac-token-auth",
            }.get(buffer_type, "unknown"),
            "randomPresent": bool(random_c),
            "headerLenField": header_len_field,
            "authHeadLen": len(auth_head),
            "authDataLen": len(auth_data),
            "totalBufferLen": len(packet),
            "payloadStoredInReport": False,
            "payloadPolicy": "authHead/authData bytes are returned for immediate live use only and must not be written to reports",
        },
    }


def build_kcp_auth_preflight_from_buffer(
    auth_buffer,
    *,
    conv=0,
    syn_id=0,
    current=0,
):
    """Build AUTH_HEAD and AUTH_DATA KCP envelopes from one fresh auth buffer."""
    split = parse_ztec_auth_buffer(auth_buffer)
    auth_head_segment = build_kcp_auth_segment(
        payload=split["authHead"],
        auth_head=True,
        conv=conv,
        syn_id=syn_id,
        current=current,
        declare_payload_len=False,
    )
    auth_data_segment = build_kcp_auth_segment(
        payload=split["authData"],
        auth_head=False,
        conv=conv,
        syn_id=syn_id,
        current=current,
        declare_payload_len=False,
    )
    return {
        "authHeadSegment": auth_head_segment,
        "authDataSegment": auth_data_segment,
        "summary": {
            **split["summary"],
            "clientAuthHeadConv": KCP_AUTH_HEAD_CONV,
            "clientAuthDataConv": KCP_AUTH_DATA_CONV,
            "authBytesPlacement": "tail_after_zero_declared_len",
            "kcpDeclaredLenField": 0,
            "conv": conv,
            "synIdPresent": bool(syn_id),
            "readyForAuthPreflight": True,
        },
    }


def build_kcp_client_syn_segment(
    *,
    conv=0,
    syn_id=0,
    current=0,
    mtu=1400,
    be_ssl=False,
    detect_mtu=True,
    be_pack_check=True,
    be_fec=True,
    be_multi=False,
    be_algo_mode=1,
    be_using_stream=True,
    be_quic=True,
    be_outband=True,
    reconnect_last_conv=None,
):
    """Build the client SYN recovered from ``ikcp_send_link_sync``.

    IDA evidence: client SYN uses conv ``0x80000001``; cmd advertises SSL,
    MTU detect, pack-check, FEC, support-data-ex (0x40), and multi-link;
    wnd advertises GCC/stream/QUIC/outband capability.  The official client
    sends only the 21-byte header for a fresh SYN, but the header ``len`` field
    is ``kcp->mtu``.  Reconnect appends a 64-byte block after the fixed header,
    with ``last_conv`` at offset 21, while preserving the same declared length.
    """
    cmd = 0x40
    if be_ssl:
        cmd |= 0x01
    if detect_mtu:
        cmd |= 0x02
    if be_pack_check:
        cmd |= 0x04
    if be_fec:
        cmd |= 0x10
    if be_multi:
        cmd |= 0x80
    if int(be_algo_mode) == 2:
        wnd = 0x0001
    else:
        wnd = 0
    if be_using_stream:
        wnd |= 0x0002
    if be_quic:
        wnd |= 0x0020
    if be_outband:
        wnd |= 0x0010
    payload = b""
    if reconnect_last_conv is not None:
        payload = struct.pack("<I", int(reconnect_last_conv) & 0xFFFFFFFF) + (b"\x00" * 60)
    return encode_kcp_segment(
        conv=KCP_CLIENT_SYN_CONV,
        cmd=cmd,
        wnd=wnd,
        ts=current,
        sn=syn_id,
        una=conv,
        payload=payload,
        declared_len=mtu,
    )


def looks_like_kcp_segment(data):
    packet = _bytes(data)
    if len(packet) < KCP_SEG_HEADER_SIZE:
        return False
    cmd = packet[4]
    wnd = _u16le(packet, 5)
    if _u32le(packet, 0) not in {KCP_CLIENT_SYN_CONV, KCP_SYNC_ACK_CONV, *KCP_AUTH_CONVS} and cmd not in KCP_AUTH_ACK_CMDS:
        return False
    if cmd & ~sum(KCP_CMD_FLAGS):
        return False
    if wnd & 0xFFC0:
        return False
    length = _u16le(packet, 19)
    if length > len(packet) - KCP_SEG_HEADER_SIZE:
        return _u32le(packet, 0) == KCP_CLIENT_SYN_CONV and len(packet) in {
            KCP_SEG_HEADER_SIZE,
            KCP_SEG_HEADER_SIZE + 64,
        }
    return True


def decode_rap_frame(data):
    """Decode the common RAP UDP tunnel frame envelope from trace samples.

    The first four bytes are a per-session tunnel identifier, not a fixed magic.
    Data-like frames observed in the Linux trace carry an unaligned little-endian
    payload length at offset 19, followed by encrypted or TLS/SPICE payload at
    offset 24.  The surrounding header fields are still candidate fields, so the
    decoder preserves both endian views instead of assigning protocol names too
    early.
    """
    packet = _bytes(data)
    if len(packet) < RAP_MIN_HEADER_SIZE:
        raise ValueError("RAP frame is incomplete")
    frame = {
        "tunnelIdHex": packet[:4].hex(),
        "frameType": packet[4],
        "flags": packet[5],
        "field06Be": int.from_bytes(packet[6:8], "big"),
        "field06Le": _u16le(packet, 6),
        "word08": _u32le(packet, 8),
        "word08Be": int.from_bytes(packet[8:12], "big"),
        "word12": _u32le(packet, 12),
        "word12Be": int.from_bytes(packet[12:16], "big"),
        "word16": _u32le(packet, 16),
        "word16Be": int.from_bytes(packet[16:20], "big") if len(packet) >= 20 else None,
        "headerSize": RAP_MIN_HEADER_SIZE,
        "payloadLength": None,
        "payloadLengthSource": None,
        "payload": b"",
        "rest": b"",
        "payloadLengthMatches": False,
    }
    if frame["frameType"] in RAP_DATA_FRAME_TYPES:
        if len(packet) < RAP_DATA_HEADER_SIZE:
            raise ValueError("RAP data frame is incomplete")
        payload_length = _u16le(packet, RAP_PAYLOAD_LENGTH_OFFSET)
        payload_end = RAP_DATA_HEADER_SIZE + payload_length
        frame.update({
            "headerSize": RAP_DATA_HEADER_SIZE,
            "header16Prefix": packet[16:19],
            "postLengthBytes": packet[21:RAP_DATA_HEADER_SIZE],
            "payloadLength": payload_length,
            "payloadLengthSource": "offset19_le16",
            "payload": packet[RAP_DATA_HEADER_SIZE:min(len(packet), payload_end)],
            "rest": packet[payload_end:] if payload_end <= len(packet) else b"",
            "payloadLengthMatches": payload_end <= len(packet),
        })
    else:
        frame["headerSize"] = RAP_MIN_HEADER_SIZE
        frame["controlBytes"] = packet[6:RAP_MIN_HEADER_SIZE]
        frame["rest"] = packet[RAP_MIN_HEADER_SIZE:]
    return frame


def decode_zime_payload_envelope(frame_or_payload, post_length_bytes=None):
    """Decode the small ZIME payload envelope inside RAP data frames.

    Observed family Linux RAP data frames do not carry raw SPICE directly.  The
    RAP payload often starts with a little-endian inner length, while the third
    byte of the RAP post-length field mirrors the local SPICE channel prefix
    seen on loopback frames such as ``0a 02 26 00 ...``.  The bytes after the
    length are still protected/encoded by ZIME, so this helper deliberately
    reports only envelope facts and does not treat captured ciphertext as
    replayable protocol data.
    """
    if isinstance(frame_or_payload, dict):
        payload = _bytes(frame_or_payload.get("payload") or b"")
        post = _bytes(frame_or_payload.get("postLengthBytes") or b"")
    else:
        payload = _bytes(frame_or_payload)
        post = _bytes(post_length_bytes or b"")
    if len(payload) < 2:
        raise ValueError("ZIME payload envelope is incomplete")
    declared = _u16le(payload, 0)
    protected = payload[2:]
    if declared > len(protected):
        raise ValueError("ZIME payload length exceeds protected payload")
    channel_prefix = post[2] if len(post) >= 3 else None
    return {
        "innerPayloadLength": declared,
        "protectedPayloadLength": len(protected),
        "overheadBytes": len(protected) - declared,
        "channelPrefix": channel_prefix,
        "postLengthBytesHex": post.hex(),
        "protectedPayloadHexPrefix": protected[:32].hex(),
        "traceOnly": True,
    }


def try_decode_zime_payload_envelope(frame_or_payload, post_length_bytes=None):
    try:
        return decode_zime_payload_envelope(frame_or_payload, post_length_bytes=post_length_bytes)
    except ValueError:
        return None


def decode_rap_frames(data, max_frames=128):
    """Decode one UDP datagram that may contain multiple RAP frames.

    The Linux trace shows small 0x82 control frames concatenated before 0x81
    data frames in the same datagram.  Keeping this as a datagram splitter
    avoids assigning unknown control fields too early while still preserving the
    true payload boundary for runner work.
    """
    remaining = _bytes(data)
    frames = []
    tunnel_id = None
    while remaining:
        if len(frames) >= max_frames:
            raise ValueError("too many RAP frames in one datagram")
        if len(remaining) < RAP_MIN_HEADER_SIZE:
            raise ValueError("trailing RAP data is shorter than a frame header")
        frame = decode_rap_frame(remaining)
        if tunnel_id is None:
            tunnel_id = frame["tunnelIdHex"]
        frames.append(frame)
        rest = frame.get("rest") or b""
        if not rest:
            break
        if not looks_like_rap_frame(rest) or rest[:4].hex() != tunnel_id:
            break
        if len(rest) == len(remaining):
            raise ValueError("RAP frame decoder made no progress")
        remaining = rest
    return frames


def _fixed_bytes(value, size, field_name):
    if isinstance(value, int):
        if value < 0 or value >= (1 << (size * 8)):
            raise ValueError(f"{field_name} does not fit in {size} bytes")
        return value.to_bytes(size, "little")
    raw = _bytes(value)
    if len(raw) != size:
        raise ValueError(f"{field_name} must be exactly {size} bytes")
    return raw


def encode_rap_data_frame(
    tunnel_id,
    frame_type,
    flags,
    field06,
    word08,
    word12,
    header16_prefix=b"\x00\x00\x00",
    payload=b"",
    post_length=b"\x00\x00\x00",
):
    payload = _bytes(payload)
    tunnel = _bytes(tunnel_id)
    if len(tunnel) != 4:
        raise ValueError("tunnel_id must be exactly 4 bytes")
    if len(payload) > 0xFFFF:
        raise ValueError("RAP payload is too large")
    return (
        tunnel
        + struct.pack(
            "<BBHII",
            int(frame_type),
            int(flags),
            int(field06),
            int(word08),
            int(word12),
        )
        + _fixed_bytes(header16_prefix, 3, "header16_prefix")
        + struct.pack("<H", len(payload))
        + _fixed_bytes(post_length, 3, "post_length")
        + payload
    )


def encode_rap_control_frame(
    tunnel_id,
    frame_type,
    flags,
    field06,
    word08,
    word12,
    word16=0,
    tail=b"\x00\x00",
):
    tunnel = _bytes(tunnel_id)
    if len(tunnel) != 4:
        raise ValueError("tunnel_id must be exactly 4 bytes")
    return (
        tunnel
        + struct.pack(
            "<BBHIII",
            int(frame_type),
            int(flags),
            int(field06),
            int(word08),
            int(word12),
            int(word16),
        )
        + _fixed_bytes(tail, 2, "tail")
    )


def decode_local_spice_client_frame(data):
    """Decode the 0x0a-prefixed local SPICE frame used on loopback sockets."""
    packet = _bytes(data)
    if len(packet) < LOCAL_SPICE_CLIENT_HEADER_SIZE:
        raise ValueError("local SPICE client frame is incomplete")
    marker = packet[0]
    if marker != 0x0A:
        raise ValueError(f"local SPICE client marker 0x0a expected, got 0x{marker:02x}")
    payload_length = _u16le(packet, 2)
    end = LOCAL_SPICE_CLIENT_HEADER_SIZE + payload_length
    if len(packet) < end:
        raise ValueError("local SPICE client frame payload is incomplete")
    return {
        "marker": marker,
        "channelPrefix": packet[1],
        "payloadLength": payload_length,
        "payload": packet[LOCAL_SPICE_CLIENT_HEADER_SIZE:end],
        "rest": packet[end:],
    }


def encode_local_spice_client_frame(channel_prefix, payload=b""):
    payload = _bytes(payload)
    if len(payload) > 0xFFFF:
        raise ValueError("local SPICE client payload is too large")
    return struct.pack("<BBH", 0x0A, int(channel_prefix), len(payload)) + payload


def parse_udp_target(target, default_port=None):
    """Parse ``host:port`` or ``udp://host:port`` into a UDP socket target."""
    if isinstance(target, tuple) and len(target) >= 2:
        return str(target[0]), int(target[1])
    text = str(target or "").strip()
    if not text:
        raise ValueError("RAP/ZIME UDP target is required")
    if text.startswith("udp://"):
        text = text[6:]
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            raise ValueError(f"invalid UDP target: {target}")
        host = text[1:end]
        rest = text[end + 1:]
        if rest.startswith(":"):
            return host, int(rest[1:])
        if default_port is not None:
            return host, int(default_port)
        raise ValueError(f"UDP target port is required: {target}")
    host, sep, port = text.rpartition(":")
    if sep:
        if not host or not port:
            raise ValueError(f"invalid UDP target: {target}")
        return host, int(port)
    if default_port is not None:
        return text, int(default_port)
    raise ValueError(f"UDP target port is required: {target}")


def format_udp_target(target):
    host, port = parse_udp_target(target)
    return f"{host}:{port}"


def _hex_to_fixed_bytes(value, size, field_name):
    if isinstance(value, str):
        raw = bytes.fromhex(value)
    else:
        raw = _bytes(value)
    if len(raw) != size:
        raise ValueError(f"{field_name} must be exactly {size} bytes")
    return raw


def _fixed_hex_or_zero(value, size, field_name):
    if value in (None, ""):
        return b"\x00" * size
    return _hex_to_fixed_bytes(value, size, field_name)


def _template_int(template, name, default=0):
    value = (template or {}).get(name, default)
    if value in (None, ""):
        return int(default)
    return int(value, 0) if isinstance(value, str) else int(value)


def _normalize_rap_payload_envelope(value):
    mode = str(value or RAP_PAYLOAD_ENVELOPE_RAW).strip().lower()
    if mode not in RAP_PAYLOAD_ENVELOPES:
        raise ValueError(f"unsupported RAP payload envelope: {value}")
    return mode


def _normalize_rap_template_mode(value):
    mode = str(value or RAP_TEMPLATE_MODE_STATIC).strip().lower()
    if mode not in RAP_TEMPLATE_MODES:
        raise ValueError(f"unsupported RAP template mode: {value}")
    return mode


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
            "header16Prefix": _fixed_hex_or_zero(item.get("header16PrefixHex"), 3, "RAP template header16 prefix"),
            "postLength": _fixed_hex_or_zero(item.get("postLengthHex"), 3, "RAP template post-length bytes"),
            "header16PrefixHex": _fixed_hex_or_zero(item.get("header16PrefixHex"), 3, "RAP template header16 prefix").hex(),
            "postLengthHex": _fixed_hex_or_zero(item.get("postLengthHex"), 3, "RAP template post-length bytes").hex(),
            "payloadKind": item.get("payloadKind"),
            "payloadLength": item.get("payloadLength"),
            "zimePayloadEnvelopeObserved": bool(item.get("zimePayloadEnvelopeObserved")),
            "traceOnly": True,
        })
    return normalized


def _payload_kind_template_candidates(kind):
    values = []
    if kind:
        values.append(kind)
    prefix = "zime-udp-reserved4:"
    if isinstance(kind, str) and kind.startswith(prefix):
        values.append(kind[len(prefix):])
    return values


def _len16_prefixed(payload):
    payload = bytes(payload or b"")
    if len(payload) > 0xFFFF:
        raise ValueError("RAP payload envelope exceeds 65535 bytes")
    return len(payload).to_bytes(2, "little") + payload


def rap_payload_from_native(payload, envelope=RAP_PAYLOAD_ENVELOPE_RAW):
    """Apply the observed RAP data-frame payload envelope to a native packet.

    This transforms only Python-generated native packet-out bytes. It never
    makes captured RAP ciphertext replayable and remains a short-test helper.
    """
    payload = bytes(payload or b"")
    mode = _normalize_rap_payload_envelope(envelope)
    summary = {
        "mode": mode,
        "inputLen": len(payload),
        "reserve4Stripped": False,
    }
    if mode == RAP_PAYLOAD_ENVELOPE_RAW:
        summary["wirePayloadLen"] = len(payload)
        return payload, summary
    if mode == RAP_PAYLOAD_ENVELOPE_LEN16:
        wire_payload = _len16_prefixed(payload)
        summary.update({
            "declaredLen": len(payload),
            "wirePayloadLen": len(wire_payload),
        })
        return wire_payload, summary
    if mode == RAP_PAYLOAD_ENVELOPE_STRIP_RESERVE4_LEN16:
        if len(payload) < 4:
            raise ValueError("strip-reserve4-len16 requires a native payload of at least 4 bytes")
        stripped = payload[4:]
        wire_payload = _len16_prefixed(stripped)
        summary.update({
            "reserve4Stripped": True,
            "declaredLen": len(stripped),
            "wirePayloadLen": len(wire_payload),
        })
        return wire_payload, summary
    raise ValueError(f"unsupported RAP payload envelope: {envelope}")


def _clean_decoded_ztec(decoded):
    return {key: value for key, value in decoded.items() if key != "rest"}


def _frame_summary(frame):
    payload = frame.get("payload") or b""
    rest = frame.get("rest") or b""
    summary = {
        "tunnelIdHex": frame.get("tunnelIdHex"),
        "frameType": frame.get("frameType"),
        "flags": frame.get("flags"),
        "field06Be": frame.get("field06Be"),
        "field06Le": frame.get("field06Le"),
        "word08": frame.get("word08"),
        "word12": frame.get("word12"),
        "word16": frame.get("word16"),
        "headerSize": frame.get("headerSize"),
        "payloadLength": frame.get("payloadLength"),
        "payloadLengthSource": frame.get("payloadLengthSource"),
        "payloadLengthMatches": frame.get("payloadLengthMatches"),
        "payloadKind": classify_payload(payload),
        "payloadHexPrefix": payload[:80].hex(),
        "restLength": len(rest),
    }
    envelope = try_decode_zime_payload_envelope(frame)
    if envelope:
        summary["zimePayloadEnvelope"] = envelope
    return summary


def load_runner_input(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data.get("runnerInput") or data


def runner_config_from_input(runner_input=None, *, target=None, tunnel_id=None, ztec_host=None, ztec_port=None):
    """Build a conservative UDP runner config from an analysis report."""
    source = runner_input or {}
    if "runnerInput" in source:
        source = source["runnerInput"]
    targets = list(source.get("candidateUdpTargets") or [])
    selected_target = target or (targets[0] if targets else None)
    host, port = parse_udp_target(selected_target)
    ztec_targets = list(source.get("candidateZtecTargets") or [])
    selected_ztec_target = ztec_targets[0] if ztec_targets else None
    if selected_ztec_target:
        default_ztec_host, default_ztec_port = parse_udp_target(selected_ztec_target)
    else:
        default_ztec_host, default_ztec_port = host, port
    selected_tunnel = tunnel_id or source.get("primaryTunnelId")
    if not selected_tunnel:
        raise ValueError("RAP tunnel id is required; rerun analyze-rap-zime or pass --tunnel-id")
    tunnel = _hex_to_fixed_bytes(selected_tunnel, 4, "tunnel_id")
    return {
        "target": (host, port),
        "targetText": f"{host}:{port}",
        "tunnelId": tunnel,
        "tunnelIdHex": tunnel.hex(),
        "ztecHost": ztec_host or default_ztec_host,
        "ztecPort": int(ztec_port or default_ztec_port),
        "rapDataFrameTemplate": source.get("rapDataFrameTemplate"),
        "rapDataFrameSendTemplates": _normalize_rap_send_templates(source.get("rapDataFrameSendTemplates")),
        "sourceNeedsTraceWithSocketRemote": bool(source.get("needsTraceWithSocketRemote")),
    }


def runner_input_readiness(
    runner_input=None,
    *,
    source_path=None,
    require_templates=False,
    require_ztec=True,
    require_kcp_auth_ready=False,
    max_age_seconds=None,
):
    """Return a redacted readiness summary for RAP/ZIME live-short-test input."""
    source = runner_input or {}
    if "runnerInput" in source:
        source = source["runnerInput"]
    targets = list(source.get("candidateUdpTargets") or [])
    ztec_targets = list(source.get("candidateZtecTargets") or [])
    templates = list(source.get("rapDataFrameSendTemplates") or [])
    template = source.get("rapDataFrameTemplate")
    kcp_auth_material = source.get("kcpAuthMaterial") if isinstance(source.get("kcpAuthMaterial"), dict) else {}
    kcp_auth_material_declared = bool(
        source.get("kcpAuthMaterialAvailable")
        or (
            kcp_auth_material
            and kcp_auth_material.get("fresh")
            and (kcp_auth_material.get("source") or kcp_auth_material.get("sourceType"))
        )
    )
    kcp_auth_material_source = None
    if kcp_auth_material_declared:
        kcp_auth_material_source = str(
            kcp_auth_material.get("sourceType")
            or kcp_auth_material.get("source")
            or "declared"
        )[:80]
    kcp_auth_disabled_proven = bool(
        source.get("kcpAuthDisabled")
        or source.get("kcpAuthDisabledProven")
        or (isinstance(source.get("kcpAuth"), dict) and source["kcpAuth"].get("disabledProven"))
    )
    kcp_auth_ready = bool(kcp_auth_disabled_proven or kcp_auth_material_declared)
    checks = {
        "transportIsRapZimeUdp": source.get("transport") == "rap-zime-udp",
        "hasPrimaryTunnelId": bool(source.get("primaryTunnelId")),
        "hasCandidateUdpTarget": bool(targets),
        "hasCandidateZtecTarget": bool(ztec_targets),
        "hasRapDataFrameTemplate": bool(template),
        "hasRapDataFrameSendTemplates": bool(templates),
        "needsTraceWithSocketRemote": bool(source.get("needsTraceWithSocketRemote")),
        "kcpAuthReadyForLiveSynack": kcp_auth_ready,
    }
    required = [
        ("transportIsRapZimeUdp", "runner input transport is not rap-zime-udp"),
        ("hasPrimaryTunnelId", "RAP primary tunnel id is missing"),
        ("hasCandidateUdpTarget", "RAP UDP target is missing"),
        ("hasRapDataFrameTemplate", "RAP data-frame template is missing"),
    ]
    if require_ztec:
        required.append(("hasCandidateZtecTarget", "ZTEC target is missing"))
    if require_templates:
        required.append(("hasRapDataFrameSendTemplates", "send-side RAP templates are missing"))
    if require_kcp_auth_ready:
        required.append(("kcpAuthReadyForLiveSynack", "KCP auth is not ready: provide fresh auth material source or prove auth disabled"))
    missing = [message for key, message in required if not checks[key]]
    warnings = []
    if checks["needsTraceWithSocketRemote"]:
        missing.append("trace lacks socket remote details required to drive the UDP runner")
    if not require_templates and not checks["hasRapDataFrameSendTemplates"]:
        warnings.append("send-side RAP templates are absent; dynamic template mode cannot be used")
    age_seconds = None
    if source_path:
        try:
            age_seconds = max(0.0, time.time() - Path(source_path).stat().st_mtime)
        except OSError:
            warnings.append("could not stat runner input file for freshness")
    stale = False
    if max_age_seconds is not None and age_seconds is not None:
        stale = age_seconds > float(max_age_seconds)
        if stale:
            missing.append("runner input file is older than the configured max age")
    if age_seconds is None:
        warnings.append("freshness is not proven from runner input structure alone")
    else:
        warnings.append("file mtime is only a freshness hint; live login/connection material can still expire")
    ready = not missing
    return {
        "ok": ready,
        "readyForLiveShortTest": ready,
        "desktopKeepaliveProven": False,
        "proof": "runner_input_structure_only",
        "sessionOwningIfUsedLive": True,
        "counts": {
            "candidateUdpTargets": len(targets),
            "candidateZtecTargets": len(ztec_targets),
            "rapDataFrameSendTemplates": len(templates),
        },
        "checks": checks,
        "missing": missing,
        "warnings": warnings,
        "kcpAuth": {
            "requiredForLiveSynack": bool(require_kcp_auth_ready),
            "preflightObservedInTrace": bool(source.get("kcpAuthPreflightObserved")),
            "disabledProven": kcp_auth_disabled_proven,
            "freshMaterialDeclared": kcp_auth_material_declared,
            "materialSourceType": kcp_auth_material_source,
            "payloadStoredInReport": False,
            "payloadPolicy": "auth payload bytes must come from a fresh authorized session and must not be written to reports",
            "ready": kcp_auth_ready,
        },
        "freshness": {
            "sourcePath": str(source_path) if source_path else None,
            "ageSeconds": round(age_seconds, 3) if age_seconds is not None else None,
            "maxAgeSeconds": max_age_seconds,
            "stale": stale,
            "freshnessProven": False,
        },
        "source": {
            "sourceTrace": source.get("sourceTrace"),
            "implementationUse": source.get("implementationUse"),
        },
        "nextStep": (
            "Use this runner input only for a short session-owning live test after confirming freshness."
            if ready
            else (
                "Recover fresh KCP auth material or prove auth disabled before SYN/SYNACK live probing."
                if require_kcp_auth_ready and not kcp_auth_ready
                else "Regenerate runner input from a fresh official trace with UDP target, tunnel id, ZTEC target, socket remote, and RAP send templates."
            )
        ),
    }


def check_runner_input_file(path, *, require_templates=False, require_ztec=True, require_kcp_auth_ready=False, max_age_seconds=None):
    data = load_runner_input(path)
    return runner_input_readiness(
        data,
        source_path=path,
        require_templates=require_templates,
        require_ztec=require_ztec,
        require_kcp_auth_ready=require_kcp_auth_ready,
        max_age_seconds=max_age_seconds,
    )


class RapZimeUdpSession:
    """Small UDP transport for the observed RAP/ZIME outer envelope."""

    def __init__(
        self,
        sock,
        target,
        tunnel_id,
        *,
        ztec_host=None,
        ztec_port=None,
        ztec_marker=0x04A0,
        flags=0,
        field06=0,
        word08=0,
        word12=0,
        header16_prefix=b"\x00\x00\x00",
        post_length=b"\x00\x00\x00",
        frame_type=0x81,
        rap_payload_envelope=RAP_PAYLOAD_ENVELOPE_RAW,
        rap_send_templates=None,
        rap_template_mode=RAP_TEMPLATE_MODE_STATIC,
    ):
        self.sock = sock
        self.target = parse_udp_target(target)
        self.tunnel_id = _hex_to_fixed_bytes(tunnel_id, 4, "tunnel_id")
        self.ztec_host = ztec_host or self.target[0]
        self.ztec_port = int(ztec_port or self.target[1])
        self.ztec_marker = int(ztec_marker)
        self.flags = int(flags)
        self.field06 = int(field06)
        self.word08 = int(word08)
        self.word12 = int(word12)
        self.header16_prefix = _fixed_bytes(header16_prefix, 3, "header16_prefix")
        self.post_length = _fixed_bytes(post_length, 3, "post_length")
        self.frame_type = int(frame_type)
        self.rap_payload_envelope = _normalize_rap_payload_envelope(rap_payload_envelope)
        self.rap_send_templates = _normalize_rap_send_templates(rap_send_templates)
        self.rap_template_mode = _normalize_rap_template_mode(rap_template_mode)
        self._rap_template_cursor = 0
        self._rap_template_kind_cursors = {}
        self.sent_packets = 0
        self.received_packets = 0

    def _recvfrom(self, timeout=None):
        old_timeout = self.sock.gettimeout()
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            data, remote = self.sock.recvfrom(65535)
        finally:
            if timeout is not None:
                self.sock.settimeout(old_timeout)
        self.received_packets += 1
        return data, remote

    def send_ztec_keepalive(self, *, sequence=0, nonce=None, tail=None, reserved=0, wait_ack=True, timeout=5):
        if nonce is None:
            nonce = time.time_ns() & 0xFFFF
        if tail is None:
            tail = (time.time_ns() >> 16) & 0xFFFFFFFF
        request = encode_ztec_keepalive_request(
            self.ztec_host,
            self.ztec_port,
            sequence,
            nonce,
            marker=self.ztec_marker,
            tail=tail,
            reserved=reserved,
        )
        sent = self.sock.sendto(request, self.target)
        self.sent_packets += 1
        report = {
            "target": format_udp_target(self.target),
            "bytesSent": sent,
            "request": _clean_decoded_ztec(decode_ztec_keepalive(request)),
            "ackReceived": False,
        }
        if not wait_ack:
            return report
        try:
            response, remote = self._recvfrom(timeout=timeout)
        except socket.timeout:
            report["error"] = "timeout waiting for ZTEC ack"
            return report
        report.update({
            "responseRemote": format_udp_target(remote[:2]),
            "responseBytes": len(response),
            "responseKind": classify_payload(response),
            "responseHexPrefix": response[:80].hex(),
        })
        if looks_like_ztec_ack(response):
            report["ackReceived"] = True
            report["ack"] = _clean_decoded_ztec(decode_ztec_keepalive(response))
        return report

    def _select_rap_template(self, payload):
        if not self.rap_send_templates:
            return None, {
                "mode": self.rap_template_mode,
                "source": "static",
                "payloadKind": classify_payload(payload),
            }
        requested_mode = self.rap_template_mode
        mode = RAP_TEMPLATE_MODE_PAYLOAD_KIND if requested_mode == RAP_TEMPLATE_MODE_AUTO else requested_mode
        payload_kind = classify_payload(payload)
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

    def build_rap_data_frame(self, payload=b"", *, flags=None, field06=None, word08=None, word12=None, frame_type=None, header16_prefix=None, post_length=None):
        return encode_rap_data_frame(
            self.tunnel_id,
            self.frame_type if frame_type is None else int(frame_type),
            self.flags if flags is None else int(flags),
            self.field06 if field06 is None else int(field06),
            self.word08 if word08 is None else int(word08),
            self.word12 if word12 is None else int(word12),
            self.header16_prefix if header16_prefix is None else _fixed_bytes(header16_prefix, 3, "header16_prefix"),
            payload,
            post_length=self.post_length if post_length is None else _fixed_bytes(post_length, 3, "post_length"),
        )

    def receive_rap_datagram(self, *, timeout=5):
        data, remote = self._recvfrom(timeout=timeout)
        frames = decode_rap_frames(data)
        return {
            "remote": format_udp_target(remote[:2]),
            "bytesReceived": len(data),
            "frameCount": len(frames),
            "frames": frames,
            "frameSummaries": [_frame_summary(frame) for frame in frames],
        }

    def send_rap_payload(self, payload=b"", *, flags=None, field06=None, word08=None, word12=None, wait_response=False, timeout=5):
        payload = _bytes(payload)
        wire_payload, payload_envelope = rap_payload_from_native(payload, self.rap_payload_envelope)
        template, template_selection = self._select_rap_template(payload)
        frame_kwargs = {
            "flags": flags,
            "field06": field06,
            "word08": word08,
            "word12": word12,
        }
        if template:
            frame_kwargs.update({
                "frame_type": template["frameType"],
                "flags": template["flags"],
                "field06": template["field06"],
                "word08": template["word08"],
                "word12": template["word12"],
                "header16_prefix": template["header16Prefix"],
                "post_length": template["postLength"],
            })
        packet = self.build_rap_data_frame(wire_payload, **frame_kwargs)
        sent = self.sock.sendto(packet, self.target)
        self.sent_packets += 1
        report = {
            "target": format_udp_target(self.target),
            "bytesSent": sent,
            "payloadKind": classify_payload(payload),
            "wirePayloadKind": classify_payload(wire_payload),
            "payloadEnvelope": payload_envelope,
            "rapTemplateSelection": template_selection,
            "frame": _frame_summary(decode_rap_frame(packet)),
            "response": None,
        }
        if wait_response:
            try:
                response = self.receive_rap_datagram(timeout=timeout)
            except socket.timeout:
                response = {"error": "timeout waiting for RAP response"}
            report["response"] = response
        return report


def run_udp_probe(
    *,
    runner_input_file=None,
    runner_input=None,
    target=None,
    tunnel_id=None,
    payloads=None,
    ztec=True,
    ztec_host=None,
    ztec_port=None,
    timeout=5,
    wait_response=False,
    rap_payload_envelope=RAP_PAYLOAD_ENVELOPE_RAW,
    rap_template_mode=RAP_TEMPLATE_MODE_STATIC,
):
    """Run a short RAP/ZIME UDP transport probe.

    This is a transport-layer probe, not a desktop keepalive proof.  It is meant
    to validate target/tunnel parameters and local runner mechanics before the
    SPICE link/auth/display state machine is wired into this transport.
    """
    source = load_runner_input(runner_input_file) if runner_input_file else (runner_input or {})
    config = runner_config_from_input(
        source,
        target=target,
        tunnel_id=tunnel_id,
        ztec_host=ztec_host,
        ztec_port=ztec_port,
    )
    template = config.get("rapDataFrameTemplate") or {}
    payloads = list(payloads or [])
    started = time.time()
    report = {
        "ok": True,
        "transport": "rap-zime-udp",
        "target": config["targetText"],
        "tunnelIdHex": config["tunnelIdHex"],
        "sourceNeedsTraceWithSocketRemote": config["sourceNeedsTraceWithSocketRemote"],
        "rapPayloadEnvelope": _normalize_rap_payload_envelope(rap_payload_envelope),
        "rapTemplateMode": _normalize_rap_template_mode(rap_template_mode),
        "rapSendTemplateCount": len(config["rapDataFrameSendTemplates"]),
        "ztec": None,
        "rap": [],
        "desktopKeepaliveProven": False,
        "proof": "transport_probe_only",
    }
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        session = RapZimeUdpSession(
            sock,
            config["target"],
            config["tunnelId"],
            ztec_host=config["ztecHost"],
            ztec_port=config["ztecPort"],
            frame_type=_template_int(template, "frameType", 0x81),
            flags=_template_int(template, "flags", 0),
            field06=_template_int(template, "field06", 0),
            word08=_template_int(template, "word08", 0),
            word12=_template_int(template, "word12", 0),
            header16_prefix=_fixed_hex_or_zero(template.get("header16PrefixHex"), 3, "RAP data-frame header16 prefix"),
            post_length=_fixed_hex_or_zero(template.get("postLengthHex"), 3, "RAP data-frame post-length bytes"),
            rap_payload_envelope=rap_payload_envelope,
            rap_send_templates=config["rapDataFrameSendTemplates"],
            rap_template_mode=rap_template_mode,
        )
        if ztec:
            report["ztec"] = session.send_ztec_keepalive(timeout=timeout)
        for payload in payloads:
            report["rap"].append(session.send_rap_payload(payload, wait_response=wait_response, timeout=timeout))
        report["sentPackets"] = session.sent_packets
        report["receivedPackets"] = session.received_packets
    report["startedAt"] = started
    report["endedAt"] = time.time()
    report["elapsedSeconds"] = round(report["endedAt"] - started, 3)
    return report


def _target_from_runner_input_for_raw_udp(runner_input=None, *, target=None):
    source = runner_input or {}
    if "runnerInput" in source:
        source = source["runnerInput"]
    targets = list(source.get("candidateUdpTargets") or [])
    selected_target = target or (targets[0] if targets else None)
    if not selected_target:
        raise ValueError("UDP target is required; pass --target or provide candidateUdpTargets")
    host, port = parse_udp_target(selected_target)
    return (host, port), f"{host}:{port}", source


def _recv_kcp_until(sock, *, timeout, receive_limit, predicate):
    responses = []
    matched = None
    old_timeout = sock.gettimeout()
    sock.settimeout(float(timeout))
    try:
        for _ in range(max(0, int(receive_limit))):
            try:
                data, remote = sock.recvfrom(65535)
            except socket.timeout:
                break
            decoded = decode_kcp_segment(data) if looks_like_kcp_segment(data) else None
            item = {
                "remote": format_udp_target(remote[:2]),
                "bytesReceived": len(data),
                "payloadKind": classify_payload(data),
                "kcp": _kcp_segment_summary(decoded) if decoded else None,
            }
            responses.append(item)
            if decoded and predicate(decoded):
                matched = decoded
                break
    finally:
        sock.settimeout(old_timeout)
    return responses, matched


def _recv_auth_head_gate_ack(sock, *, timeout, receive_limit, expected_remote=None):
    """Wait for cmd=7 or the official same-fd 71-byte ACK-like gate.

    Fresh official auth-focus trace proved that the first external AUTH gate is
    accepted when the same UDP fd receives a 71-byte response before AUTH_DATA.
    The payload itself is intentionally not stored.
    """
    responses = []
    matched = None
    ack_like = None
    old_timeout = sock.gettimeout()
    sock.settimeout(float(timeout))
    try:
        for _ in range(max(0, int(receive_limit))):
            try:
                data, remote = sock.recvfrom(65535)
            except socket.timeout:
                break
            remote_tuple = remote[:2]
            decoded = decode_kcp_segment(data) if looks_like_kcp_segment(data) else None
            same_remote = expected_remote is None or remote_tuple == expected_remote
            item = {
                "remote": format_udp_target(remote_tuple),
                "bytesReceived": len(data),
                "payloadKind": classify_payload(data),
                "kcp": _kcp_segment_summary(decoded) if decoded else None,
                "sameExternalFdAsAuthHead": True,
                "sameRemoteAsAuthTarget": same_remote if expected_remote is not None else None,
                "officialAuthHeadAckLike": bool(same_remote and len(data) == OFFICIAL_AUTH_HEAD_ACK_LIKE_LEN),
                "payloadStoredInReport": False,
            }
            responses.append(item)
            if decoded and decoded.get("authHeadAckCmd"):
                matched = decoded
                break
            if item["officialAuthHeadAckLike"]:
                ack_like = item
                break
    finally:
        sock.settimeout(old_timeout)
    return responses, matched, ack_like


def _send_ztec_prime_on_socket(sock, udp_target, *, ztec_host=None, ztec_port=None, timeout=1.0):
    host = ztec_host or udp_target[0]
    port = int(ztec_port or udp_target[1])
    sequence = 0
    nonce = time.time_ns() & 0xFFFF
    tail = (time.time_ns() >> 16) & 0xFFFFFFFF
    request = encode_ztec_keepalive_request(host, port, sequence, nonce, tail=tail)
    sent = sock.sendto(request, udp_target)
    report = {
        "enabled": True,
        "target": format_udp_target(udp_target),
        "bytesSent": sent,
        "request": _clean_decoded_ztec(decode_ztec_keepalive(request)),
        "ackReceived": False,
    }
    old_timeout = sock.gettimeout()
    sock.settimeout(float(timeout))
    try:
        try:
            response, remote = sock.recvfrom(65535)
        except socket.timeout:
            report["error"] = "timeout waiting for ZTEC ack"
            return report
    finally:
        sock.settimeout(old_timeout)
    report.update({
        "responseRemote": format_udp_target(remote[:2]),
        "responseBytes": len(response),
        "responseKind": classify_payload(response),
    })
    if looks_like_ztec_ack(response):
        report["ackReceived"] = True
        report["ack"] = _clean_decoded_ztec(decode_ztec_keepalive(response))
    return report


def _kcp_auth_probe_parity_assessment(
    local_socket_lifecycle,
    *,
    pre_auth_session_state=None,
    auth_head_ack,
    auth_head_ack_like=None,
    auth_ack,
    synack,
    auth_gate_only=False,
):
    """Summarize how the Python probe differs from the official UDP lifecycle."""
    auth_head_gate_accepted = bool(auth_head_ack or auth_head_ack_like)
    if not auth_head_gate_accepted:
        blocked_at = "auth_head"
    elif auth_gate_only:
        blocked_at = None
    elif auth_ack is None:
        blocked_at = "auth_data"
    elif synack is None:
        blocked_at = "client_syn"
    else:
        blocked_at = None

    explicit_bind = bool(local_socket_lifecycle.get("explicitBindBeforeSend"))
    requested_bind = local_socket_lifecycle.get("requestedLocalBind") or ""
    source_port_ruled_out = bool(blocked_at == "auth_head" and explicit_bind and requested_bind.endswith(":0"))
    ruled_out = []
    if source_port_ruled_out:
        ruled_out.append("lack_of_explicit_ephemeral_udp_bind")
    pre_auth_loop = bool(local_socket_lifecycle.get("preAuthReceiveLoopStarted"))
    pre_auth_implicit_bind = bool(local_socket_lifecycle.get("implicitBindForPreAuthReceive"))
    fresh_cmd26_bootstrap = bool(local_socket_lifecycle.get("freshCmd26LocalBootstrapModeled"))
    fresh_cmd26_status = bool(local_socket_lifecycle.get("freshCmd26LocalBootstrapStatusReceived"))
    pre_auth_state_contract = bool(local_socket_lifecycle.get("preAuthSessionStateContractClosed"))
    tcp_readiness_modeled = bool(local_socket_lifecycle.get("officialTcpListenReadinessModeled"))
    auth_head_send_count = int(local_socket_lifecycle.get("authHeadSendCount") or 0)
    auth_head_configured_attempts = int(local_socket_lifecycle.get("authHeadConfiguredAttempts") or 1)
    if blocked_at == "auth_head" and pre_auth_loop:
        ruled_out.append("pre_auth_receive_window_alone")
        if pre_auth_implicit_bind:
            ruled_out.append("pre_auth_implicit_udp_bind_alone")

    modeled_native = set()
    native_model = ((pre_auth_session_state or {}).get("nativeEquivalentStateModel") or {})
    for key, value in (native_model.get("sideEffectModel") or {}).items():
        if isinstance(value, dict) and value.get("modeled") is True:
            modeled_native.add(key)
    missing_official_lifecycle = [
        "local_tcp_listen_readiness_fd",
        "udp_get_tcp_link_info_gate",
        "listen_udp_data_thread_ice_deal_sock_loop",
        "local_proxy_protocol_header_link_type_detection",
        "deal_create_proxy_fd_session_link_type_assignment",
        "proxy_sock_link_type_copied_to_udp_sock",
        "create_fd_session_TN_UDP_CLD_SOCK",
        "thread_kcp_list_attachment_before_deal_udt_using_cag",
    ]
    if pre_auth_state_contract:
        missing_official_lifecycle = [
            item for item in missing_official_lifecycle
            if item not in modeled_native and item != "proxy_sock_link_type_copied_to_udp_sock"
        ]
    if tcp_readiness_modeled:
        missing_official_lifecycle = [
            item for item in missing_official_lifecycle
            if item not in {"local_tcp_listen_readiness_fd", "udp_get_tcp_link_info_gate"}
        ]
    modeled_by_python = [
        "one UDP fd is reused for AUTH_HEAD/AUTH_DATA send and receive",
        "same-fd 71-byte ACK-like response is accepted as the official AUTH_HEAD gate before AUTH_DATA",
        *(
            ["official three-send AUTH_HEAD pump is modeled before declaring the gate missing"]
            if auth_head_configured_attempts >= 3
            else []
        ),
        "getsockname() records the local UDP endpoint before and after first send",
        "optional explicit local UDP bind is available for source-port experiments",
    ]
    if pre_auth_loop:
        modeled_by_python.append("optional pre-AUTH receive window can bind the UDP socket and enter recvfrom() before AUTH_HEAD")
    if fresh_cmd26_bootstrap:
        modeled_by_python.append("pre-AUTH fresh cmd26 local bootstrap frame shape is modeled before AUTH_HEAD")
        if fresh_cmd26_status:
            modeled_by_python.append("fresh cmd26 local bootstrap received the 1-byte status before AUTH_HEAD")
    if pre_auth_state_contract:
        modeled_by_python.append("pre-AUTH local proxy/session state contract is closed for local gate-only testing")
    if modeled_native:
        modeled_by_python.append("pre-AUTH native-equivalent in_sock/proxy_sock/udp_sock/thread.kcp_list side effects are modeled locally")
    if tcp_readiness_modeled:
        modeled_by_python.append("pre-AUTH local TCP listen readiness fd and udp_get_tcp_link_info gate are modeled locally")
    return {
        "stageBlocked": blocked_at,
        "officialPath": "spice_init_udp_thread -> listen_udp_data_thread -> init_local_rw_sock_pair_udp -> deal_udt_using_cag -> ikcp_set_auth_data",
        "pythonProbePath": (
            "single_udp_socket -> optional_local_bind -> AUTH_HEAD_pump -> wait_cmd7_or_71_byte_ACK_like -> AUTH_DATA -> stop"
            if auth_gate_only
            else "single_udp_socket -> optional_local_bind -> AUTH_HEAD_pump -> wait_cmd7_or_71_byte_ACK_like -> AUTH_DATA -> wait_ACK -> SYN"
        ),
        "officialAuthHeadPump": {
            "officialSendCountBeforeAckLike": 3,
            "officialGapsMsApprox": [77, 82],
            "pythonConfiguredAttempts": auth_head_configured_attempts,
            "pythonActualSendCount": auth_head_send_count,
            "modeled": auth_head_configured_attempts >= 3,
            "source": "fresh official auth-focus trace indexes 768/787/804 -> 819",
        },
        "readinessPortInterpretation": "g_tcp_listen_port is a local 127.0.0.1 TCP listen readiness port, not the outbound UDP source port",
        "modeledByPython": modeled_by_python,
        "notModeledYet": missing_official_lifecycle,
        "nativeSideEffectBoundary": (
            "fresh cmd26 frame and pre-AUTH state contract are modeled locally; this still requires a gate-only live run to prove cloud ACK-like acceptance"
            if pre_auth_state_contract
            else "fresh cmd26 frame emission is modeled, but native proxy fd/session, UDP gate, KCP attachment and QUIC/channel manage side effects are still tracked separately"
            if fresh_cmd26_bootstrap
            else "fresh cmd26 local bootstrap frame emission is not modeled in this run"
        ),
        "ruledOutByThisRun": ruled_out,
        "sourcePortHypothesisStatus": (
            "explicit_ephemeral_bind_not_sufficient"
            if source_port_ruled_out
            else ("explicit_bind_tested" if explicit_bind else "not_tested_in_this_run")
        ),
        "actionableNextEvidence": [
            "recover or trace the local proxy protocol header path that sets data_buf[224] to 1 or 2 before init_local_rw_sock_pair_udp()",
            "recover or trace whether deal_udt_using_cag emits any packet or CAG-side binding before AUTH_HEAD",
            "fresh official UDP trace should capture sendto payload class, local UDP source endpoint, remote endpoint, and whether any packet precedes AUTH_HEAD",
            "if static analysis continues, prioritize get_thread_kcp, deal_kcp_auth_cmd, and CAG auth result handling over repeating auth-buffer builders",
        ],
        "doNotRepeatWithoutNewEvidence": [
            "type102_accessToken_with_local_bind_0",
            "ztec_prime_target_variants",
            *(
                ["pre_auth_receive_window_without_proxy_header_or_official_trace"]
                if pre_auth_loop and blocked_at == "auth_head"
                else []
            ),
        ],
    }


def pre_auth_native_side_effect_contract(runner_model=None):
    """Return the official native side-effect contract before AUTH_HEAD.

    This is deliberately separate from the Python pre-auth configuration audit:
    the static/native side effects are recovered here, while ``runner_model``
    records whether the runner has built a redacted native-equivalent state
    model for the current gate-only attempt.
    """
    runner_model = runner_model or {}
    side_effect_model = runner_model.get("sideEffectModel") or {}
    modeled_keys = {
        key for key, value in side_effect_model.items()
        if isinstance(value, dict) and value.get("modeled") is True
    }
    all_runner_equivalent = bool(runner_model.get("allRequiredModeled")) and modeled_keys == {
        "local_proxy_protocol_header_link_type_detection",
        "deal_create_proxy_fd_session_link_type_assignment",
        "create_fd_session_TN_UDP_CLD_SOCK",
        "thread_kcp_list_attachment_before_deal_udt_using_cag",
    }
    official_fields = [
        "loopback accepted-side recv len=4 local proxy header",
        "loopback accepted-side recv len=156 ChannelLinkSocketEx body",
        "loopback client-side recv len=1 cmd26 status/control",
        "same external fd later sends AUTH_HEAD len=199",
        "same external fd/remote must receive len=71 ACK-like before AUTH_DATA",
    ]
    return {
        "status": (
            "static_contract_recovered_runner_equivalent_modeled_for_gate_only"
            if all_runner_equivalent
            else "static_contract_recovered_runner_equivalent_not_implemented"
        ),
        "payloadStoredInReport": False,
        "officialTraceFields": official_fields,
        "gateBoundary": "required before treating AUTH_HEAD199 as official-equivalent; does not permit AUTH_ACK/SYNACK/native bridge/DISPLAY_INIT",
        "runnerEquivalentModeled": all_runner_equivalent,
        "runnerModelSource": runner_model.get("sourceType") if runner_model else None,
        "sideEffects": [
            {
                "key": "local_proxy_protocol_header_link_type_detection",
                "functions": [
                    "deal_unlinked_unknown_local_data",
                    "check_spice_proxy_protocol_header",
                    "deal_local_link_proxy_create",
                ],
                "nativeWrite": "in_sock->data_buf[224] is first set to 1; rejected 4-byte local proxy header switches it to 2/outband",
                "freshCmd26Effect": "fresh cmd26 accepted header keeps link_type=1 and dispatches to deal_local_link_proxy_create",
                "downstreamConsumer": "get_proxy_type_by_link_type(session, in_sock->data_buf[224])",
                "officialTraceField": "accepted-side recv len=4 local proxy header before accepted-side recv len=156 body",
                "runnerEquivalentImplemented": "local_proxy_protocol_header_link_type_detection" in modeled_keys,
                "currentPythonGap": "runner sends one cmd26 body to zqoe but does not own the accepted-side IceSocket whose data_buf[224] is consumed by init_local_rw_sock_pair_udp",
            },
            {
                "key": "deal_create_proxy_fd_session_link_type_assignment",
                "functions": [
                    "deal_local_link_proxy_create",
                    "deal_create_proxy_fd_session",
                    "get_thread_proxy_fd_session",
                ],
                "nativeWrite": "type6 route creates or reuses proxy fd session, writes proxy_sock->data_buf[224]=1 and proxy_sock->cag_client_key=6",
                "additionalWrites": [
                    "proxy_sock byte 0x2d/BYTE5(ssl) records UDT/network-protocol gate",
                    "proxy_sock byte 0x68/LOBYTE(pair) records SSL/client-type gate",
                    "proxy_sock byte 0x60/LOBYTE(kcp_session) records enable_cag",
                    "proxy_sock dword 0x24/cag_client_key records fd_type_ex",
                ],
                "downstreamConsumer": "init_local_rw_sock_pair() requires this proxy fd session before UDP/KCP pairing",
                "officialTraceField": "cmd26 status/control precedes first external AUTH_HEAD len=199",
                "runnerEquivalentImplemented": "deal_create_proxy_fd_session_link_type_assignment" in modeled_keys,
                "currentPythonGap": "pre-auth-state CLI flag documents the expected session slot but does not materialize a native-equivalent proxy fd session",
            },
            {
                "key": "create_fd_session_TN_UDP_CLD_SOCK",
                "functions": [
                    "init_local_rw_sock_pair_udp",
                    "create_fd_session",
                ],
                "nativeWrite": "create_fd_session(thread, proxy_udp_fd, TN_SVR_SOCK, TN_UDP_CLD_SOCK) wraps the UDP fd as udp_sock",
                "copiedFields": [
                    "proxy_sock->data_buf[224] -> udp_sock->data_buf[224]",
                    "proxy_sock byte 0x2d/BYTE5(ssl) -> udp_sock byte 0x2d/BYTE5(ssl)",
                    "proxy_sock byte 0x60/LOBYTE(kcp_session) -> udp_sock byte 0x60/LOBYTE(kcp_session)",
                ],
                "pairing": "udp_sock and in_sock are linked through data_buf[28] before KCP creation",
                "officialTraceField": "external AUTH_HEAD len=199 follows local proxy/session setup on the same official sequence",
                "runnerEquivalentImplemented": "create_fd_session_TN_UDP_CLD_SOCK" in modeled_keys,
                "currentPythonGap": "runner opens a raw UDP socket and records getsockname(), but has no IceSocket wrapper, pair pointer, or fd-session flags",
            },
            {
                "key": "thread_kcp_list_attachment_before_deal_udt_using_cag",
                "functions": [
                    "init_local_rw_sock_pair_udp",
                    "create_udt_session",
                    "deal_udt_using_cag",
                    "get_thread_kcp",
                ],
                "nativeWrite": "create_udt_session creates KCP, init_local_rw_sock_pair_udp inserts it into thread kcp_list, sets kcp->user_data=udp_sock and kcp->be_using_cag from udp_sock",
                "ordering": "deal_udt_using_cag(kcp, kcp->be_ssl) runs only after the KCP is attached to the thread list and user_data points at udp_sock",
                "responseBinding": "get_thread_kcp accepts cmd 1/2/7/9 only when incoming source port matches kcp->dest_port and syn_id matches kcp->syn_id",
                "officialTraceField": "same external fd pumps AUTH_HEAD len=199 and later must receive same-remote len=71 ACK-like",
                "runnerEquivalentImplemented": "thread_kcp_list_attachment_before_deal_udt_using_cag" in modeled_keys,
                "currentPythonGap": "runner builds KCP bytes directly and has no thread kcp_list object for response binding or native auth state transitions",
            },
        ],
        "runnerConsequence": (
            "AUTH_HEAD199 length parity plus the modeled native-equivalent state is still insufficient without same-fd 71-byte ACK-like live acceptance"
            if all_runner_equivalent
            else "AUTH_HEAD199 length parity is insufficient until these side effects are implemented or proven unnecessary by a same-fd 71-byte ACK-like live acceptance"
        ),
    }


def _recv_pre_auth_window(sock, *, timeout, receive_limit):
    """Observe datagrams before AUTH_HEAD without storing payload bytes."""
    packets = []
    old_timeout = sock.gettimeout()
    sock.settimeout(float(timeout))
    try:
        for _ in range(max(0, int(receive_limit))):
            try:
                data, remote = sock.recvfrom(65535)
            except socket.timeout:
                break
            decoded = decode_kcp_segment(data) if looks_like_kcp_segment(data) else None
            packets.append({
                "remote": format_udp_target(remote[:2]),
                "bytesReceived": len(data),
                "payloadKind": classify_payload(data),
                "kcp": _kcp_segment_summary(decoded) if decoded else None,
            })
    finally:
        sock.settimeout(old_timeout)
    return packets


def _start_pre_auth_tcp_listen_readiness(enabled):
    """Open a local TCP listen fd to model native udp_get_tcp_link_info readiness."""
    report = {
        "enabled": bool(enabled),
        "mode": "local-tcp-listen-readiness",
        "payloadStoredInReport": False,
    }
    if not enabled:
        return None, report
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(5)
        listener.setblocking(False)
        host, port = listener.getsockname()[:2]
        report.update({
            "listenReady": True,
            "endpointFamily": "loopback-ipv4",
            "portPresent": bool(port),
            "portStoredInReport": False,
            "modeledNativeWrites": [
                "g_sock_listen_fd=open TCP listen fd",
                "g_tcp_listen_port=getsockname(g_sock_listen_fd).port",
                "udp_get_tcp_link_info(nullptr) returns ip_info_51305 when g_tcp_listen_port is nonzero",
            ],
            "officialTraceFields": [
                "listen_udp_data() creates g_sock_listen_fd via ice_create_fd(0, 0)",
                "listen_udp_data() calls udp_get_local_port(g_sock_listen_fd)",
                "spice_init_udp_thread() waits until udp_get_tcp_link_info(nullptr) returns non-null",
            ],
        })
        return listener, report
    except OSError as exc:
        listener.close()
        report.update({
            "listenReady": False,
            "error": exc.__class__.__name__,
        })
        return None, report


def _run_pre_auth_fresh_cmd26_bootstrap(config, *, timeout):
    """Send a redacted fresh cmd26 loopback bootstrap frame before AUTH_HEAD."""
    if not config:
        return {
            "enabled": False,
            "payloadStoredInReport": False,
        }
    if config is True:
        raise ValueError("pre_auth_fresh_cmd26_bootstrap requires a configuration dict")
    cfg = dict(config)
    local_host = cfg.pop("local_host", None)
    if local_host is None:
        local_host = cfg.pop("host", "127.0.0.1")
    if "local_port" in cfg:
        local_port = int(cfg.pop("local_port"))
    else:
        local_port = int(cfg.pop("port"))
    build_args = {
        "dest_ip": cfg.pop("dest_ip"),
        "dest_port": cfg.pop("dest_port"),
    }
    for key in (
        "channel_type",
        "channel_id",
        "link_priority",
        "link_type",
        "serial_num",
        "vm_uuid",
        "protocol_type",
        "be_emergency",
        "bw_ctrl",
        "tbw_ctrl",
        "flag",
        "channel_type_field",
        "extend",
        "trace_id",
        "parent_id",
    ):
        if key in cfg:
            build_args[key] = cfg.pop(key)
    if cfg:
        raise ValueError(f"unknown pre_auth_fresh_cmd26_bootstrap keys: {', '.join(sorted(cfg))}")

    built = build_fresh_cmd26_bootstrap_frame(**build_args)
    frame = built["frame"]
    report = {
        "enabled": True,
        "mode": "fresh-cmd26-loopback-bootstrap",
        "producerFunction": "add_link_to_proxy_by_socket",
        "frameSummary": summarize_fresh_cmd26_bootstrap_frame(frame),
        "builderSummary": built["summary"],
        "localProxyEndpointIsLoopback": str(local_host) in {"127.0.0.1", "::1", "localhost"},
        "statusReceived": False,
        "statusBytesReceived": 0,
        "statusReadMode": "drain_available_without_payload_storage",
        "statusReadLimit": FRESH_CMD26_STATUS_READ_LIMIT,
        "payloadStoredInReport": False,
        "officialTraceFields": [
            "loopback client send len=160 cmd26",
            "accepted-side recv len=156 ChannelLinkSocketEx body",
            "client-side recv local proxy status/control response",
            "external AUTH_HEAD len=199 follows local proxy/session setup",
        ],
    }
    try:
        with socket.create_connection((local_host, local_port), timeout=float(timeout)) as conn:
            conn.settimeout(float(timeout))
            conn.sendall(frame)
            report["bytesSent"] = len(frame)
            chunks = []
            status = conn.recv(1)
            if status:
                chunks.append(status)
                conn.settimeout(min(FRESH_CMD26_STATUS_DRAIN_TIMEOUT, float(timeout)))
                while sum(len(chunk) for chunk in chunks) < FRESH_CMD26_STATUS_READ_LIMIT:
                    try:
                        chunk = conn.recv(FRESH_CMD26_STATUS_READ_LIMIT - sum(len(part) for part in chunks))
                    except socket.timeout:
                        break
                    except OSError as exc:
                        report["statusDrainError"] = exc.__class__.__name__
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
            report["statusBytesReceived"] = sum(len(chunk) for chunk in chunks)
            report["statusReceived"] = report["statusBytesReceived"] > 0
    except OSError as exc:
        report["error"] = exc.__class__.__name__
    return report


def build_pre_auth_native_equivalent_state_model(config, *, pre_auth_local_bootstrap=None):
    """Build a redacted Python model for native side effects before AUTH_HEAD."""
    config = dict(config or {})
    bootstrap_status = bool((pre_auth_local_bootstrap or {}).get("statusReceived"))
    type6_slot = bool(config.get("type6_proxy_fd_session_slot"))
    udp_gate = bool(config.get("proxy_sock_udp_gate"))
    udp_kcp_attachment = bool(config.get("init_local_rw_sock_pair_udp_kcp_attachment"))
    quic_ready_or_bypassed = bool(config.get("quic_channel_manage_ready_or_bypassed"))
    channel_type_id = config.get("channel_type_id_candidate", "0x0100")
    link_type = int(config.get("link_type_after_header", 1))
    fd_type_ex = int(config.get("fd_type_ex", 6))

    side_effects = {
        "local_proxy_protocol_header_link_type_detection": {
            "modeled": bootstrap_status,
            "nativeObject": "in_sock",
            "modeledWrites": [
                f"in_sock.data_buf_224={link_type}",
                "local proxy header accepted for cmd26",
            ],
            "consumer": "deal_local_link_proxy_create -> get_proxy_type_by_link_type",
            "officialTraceField": "accepted-side recv len=4 local proxy header",
        },
        "deal_create_proxy_fd_session_link_type_assignment": {
            "modeled": bootstrap_status and type6_slot,
            "nativeObject": "proxy_sock",
            "modeledWrites": [
                f"proxy_sock.data_buf_224={link_type}",
                f"proxy_sock.fd_type_ex={fd_type_ex}",
                f"proxy_sock.cag_client_key={fd_type_ex}",
            ],
            "consumer": "init_local_rw_sock_pair requires the proxy fd session slot",
            "officialTraceField": "cmd26 status/control precedes first external AUTH_HEAD len=199",
        },
        "create_fd_session_TN_UDP_CLD_SOCK": {
            "modeled": bootstrap_status and type6_slot and udp_gate,
            "nativeObject": "udp_sock",
            "modeledWrites": [
                "udp_sock.sock_type=TN_UDP_CLD_SOCK",
                f"udp_sock.data_buf_224=proxy_sock.data_buf_224({link_type})",
                "in_sock.pair=udp_sock",
                "udp_sock.pair=in_sock",
            ],
            "consumer": "create_udt_session uses the UDP fd-session wrapper",
            "officialTraceField": "external AUTH_HEAD len=199 follows local proxy/session setup",
        },
        "thread_kcp_list_attachment_before_deal_udt_using_cag": {
            "modeled": bootstrap_status and type6_slot and udp_gate and udp_kcp_attachment,
            "nativeObject": "thread.kcp_list",
            "modeledWrites": [
                "kcp.user_data=udp_sock",
                "thread.kcp_list contains kcp before deal_udt_using_cag",
                "kcp.be_using_cag=udp_sock.enable_cag",
            ],
            "consumer": "deal_udt_using_cag and get_thread_kcp response binding",
            "officialTraceField": "same external fd pumps AUTH_HEAD len=199 before ACK-like",
        },
    }
    missing = [key for key, value in side_effects.items() if not value["modeled"]]
    return {
        "enabled": bool(config),
        "sourceType": "pre-auth-native-equivalent-state-model",
        "allRequiredModeled": bool(config) and not missing,
        "sideEffectModel": side_effects,
        "missingSideEffects": missing,
        "channelTypeIdCandidate": channel_type_id,
        "quicChannelManageReadyOrBypassed": quic_ready_or_bypassed,
        "payloadStoredInReport": False,
        "boundary": "redacted local state model only; same-fd 71-byte ACK-like is still required before AUTH_DATA is accepted as official-equivalent",
    }


def _summarize_pre_auth_session_state_model(config, *, pre_auth_local_bootstrap=None):
    """Summarize the minimal Python-side state contract before AUTH_HEAD."""
    native_equivalent = build_pre_auth_native_equivalent_state_model(
        config,
        pre_auth_local_bootstrap=pre_auth_local_bootstrap,
    )
    required = [
        {
            "key": "fresh_cmd26_status",
            "nativeEvidence": "add_link_to_proxy_by_socket reads the local proxy status/control response before external AUTH_HEAD",
            "officialTraceField": "client-side recv local proxy status/control response",
            "modeled": bool((pre_auth_local_bootstrap or {}).get("statusReceived")),
        },
        {
            "key": "type6_proxy_fd_session_slot",
            "nativeEvidence": "deal_create_proxy_fd_session(fd_type_ex=6) stores the proxy fd session in the type6 slot",
            "officialTraceField": "loopback client send len=160 cmd26 -> accepted-side recv len=156 ChannelLinkSocketEx body",
            "modeled": bool((config or {}).get("type6_proxy_fd_session_slot")),
        },
        {
            "key": "proxy_sock_udp_gate",
            "nativeEvidence": "proxy_sock byte 0x2d gates init_local_rw_sock_pair_udp()",
            "officialTraceField": "external AUTH_HEAD len=199 follows local proxy/session setup",
            "modeled": bool((config or {}).get("proxy_sock_udp_gate")),
        },
        {
            "key": "init_local_rw_sock_pair_udp_kcp_attachment",
            "nativeEvidence": "init_local_rw_sock_pair_udp() creates TN_UDP_CLD_SOCK and attaches KCP before deal_udt_using_cag()",
            "officialTraceField": "same external fd pumps AUTH_HEAD len=199 before ACK-like",
            "modeled": bool((config or {}).get("init_local_rw_sock_pair_udp_kcp_attachment")),
        },
        {
            "key": "quic_channel_manage_ready_or_bypassed",
            "nativeEvidence": "handle_quic_protocol_stream_create_processing() is conditional on proxy/session/QUIC/channel state",
            "officialTraceField": "AUTH_HEAD len=199 follows cmd26 status; stream creation evidence is not an AUTH gate success signal",
            "modeled": bool((config or {}).get("quic_channel_manage_ready_or_bypassed")),
        },
    ]
    optional = {
        "channel_type_id_candidate": (config or {}).get("channel_type_id_candidate", "0x0100"),
        "dest_ip_source": (config or {}).get("dest_ip_source", "hostip_or_host"),
        "dest_port_source": (config or {}).get("dest_port_source", "get_channel_proxy_link_dest_port"),
        "opentelemetry_source": (config or {}).get("opentelemetry_source", "locally_generated_structural_candidate"),
    }
    missing = [item["key"] for item in required if not item["modeled"]]
    return {
        "enabled": bool(config),
        "sourceType": "pre-auth-session-state-contract",
        "allRequiredModeled": bool(config) and not missing,
        "nativeEquivalentStateModel": native_equivalent,
        "requiredChecks": required,
        "missingChecks": missing,
        "optionalFieldSources": optional,
        "readyForGateOnlyLive": bool(config) and not missing,
        "payloadStoredInReport": False,
        "boundary": "local readiness contract only; it is not a cloud ACK-like proof and does not permit SYNACK/native bridge/DISPLAY_INIT",
    }


def build_auth_gate_live_preflight_audit_from_cag_material(
    *,
    auth,
    connect_info,
    syn_id=None,
    conv=0,
    current=None,
    pre_auth_fresh_cmd26_bootstrap=None,
    pre_auth_session_state_model=None,
    auth_buffer_type="type101",
    auth_type=None,
    link_type=ZTEC_CAG_TYPE101_LINK_TYPE_PROXY,
    opentelemetry=True,
    auth_head_attempts=3,
    auth_head_retry_interval=0.08,
    trace_id="",
    span_id="",
    pre_auth_tcp_listen_readiness=False,
):
    """Build a redacted, no-network audit for the AUTH gate-only live attempt."""
    normalized_auth_buffer_type = str(auth_buffer_type or "type101").strip().lower()
    if normalized_auth_buffer_type in {"101", "type101", "password"}:
        material = build_ztec_cag_type101_auth_buffer_from_material(
            auth,
            connect_info,
            link_type=link_type,
            opentelemetry=opentelemetry,
            trace_id=trace_id,
            span_id=span_id,
        )
        transport_name = "fresh-cag-type101-material"
    elif normalized_auth_buffer_type in {"102", "type102", "uac", "token"}:
        material = build_ztec_cag_type102_auth_buffer_from_material(
            auth,
            connect_info,
            auth_type=auth_type,
            link_type=link_type,
            opentelemetry=opentelemetry,
            trace_id=trace_id,
            span_id=span_id,
        )
        transport_name = "fresh-cag-type102-material"
    else:
        raise ValueError(f"unsupported CAG auth buffer type: {auth_buffer_type}")
    if syn_id is None:
        syn_id = time.time_ns() & 0xFFFFFFFF
    if current is None:
        current = int(time.monotonic() * 1000) & 0xFFFFFFFF
    auth_material = build_kcp_auth_preflight_from_buffer(
        material["authBuffer"],
        conv=conv,
        syn_id=syn_id,
        current=current,
    )
    auth_head_wire = redacted_kcp_auth_wire_summary(auth_material["authHeadSegment"])
    auth_data_wire = redacted_kcp_auth_wire_summary(auth_material["authDataSegment"])

    bootstrap_plan = {
        "enabled": False,
        "payloadStoredInReport": False,
    }
    if pre_auth_fresh_cmd26_bootstrap:
        cfg = dict(pre_auth_fresh_cmd26_bootstrap)
        local_proxy_configured = bool(cfg.get("local_host") or cfg.get("host")) and bool(cfg.get("local_port") or cfg.get("port"))
        cfg.pop("local_host", None)
        cfg.pop("host", None)
        cfg.pop("local_port", None)
        cfg.pop("port", None)
        built = build_fresh_cmd26_bootstrap_frame(**cfg)
        bootstrap_plan = {
            "enabled": True,
            "localProxyEndpointConfigured": local_proxy_configured,
            "frameSummary": summarize_fresh_cmd26_bootstrap_frame(built["frame"]),
            "builderSummary": built["summary"],
            "runtimeStatusRequired": "client-side recv len=1 cmd26 status",
            "payloadStoredInReport": False,
            "officialTraceFields": [
                "loopback client send len=160 cmd26",
                "accepted-side recv len=156 ChannelLinkSocketEx body",
                "client-side recv len=1 cmd26 status",
                "external AUTH_HEAD len=199 follows local proxy/session setup",
            ],
        }

    state_config = dict(pre_auth_session_state_model or {})
    state_model = _summarize_pre_auth_session_state_model(
        state_config,
        pre_auth_local_bootstrap={"statusReceived": False},
    )
    state_config_checks = [
        "type6_proxy_fd_session_slot",
        "proxy_sock_udp_gate",
        "init_local_rw_sock_pair_udp_kcp_attachment",
        "quic_channel_manage_ready_or_bypassed",
    ]
    missing_state_config = [key for key in state_config_checks if not state_config.get(key)]
    auth_checks = {
        "authHeadWireLen199": auth_head_wire.get("wireLen") == OFFICIAL_AUTH_HEAD_WIRE_LEN,
        "authDataWireLen241": auth_data_wire.get("wireLen") == OFFICIAL_AUTH_DATA_WIRE_LEN,
        "authHeadConv": bool(auth_head_wire.get("authHeadConv")),
        "authDataConv": bool(auth_data_wire.get("authDataConv")),
        "authHeadPumpModeled": int(auth_head_attempts or 0) >= 3,
        "authGateOnlyBoundary": True,
    }
    missing_config = []
    if not bootstrap_plan.get("enabled"):
        missing_config.append("pre_auth_cmd26_local_proxy")
    if missing_state_config:
        missing_config.extend(missing_state_config)
    for key, ok in auth_checks.items():
        if not ok:
            missing_config.append(key)
    ready_for_attempt = not missing_config
    tcp_readiness_plan = {
        "enabled": bool(pre_auth_tcp_listen_readiness),
        "mode": "local-tcp-listen-readiness",
        "runtimeStatusRequired": "listen fd must bind 127.0.0.1:0 and keep g_tcp_listen_port nonzero during live AUTH_HEAD",
        "payloadStoredInReport": False,
        "officialTraceFields": [
            "listen_udp_data() creates g_sock_listen_fd via ice_create_fd(0, 0)",
            "listen_udp_data() calls udp_get_local_port(g_sock_listen_fd)",
            "spice_init_udp_thread() waits until udp_get_tcp_link_info(nullptr) returns non-null",
        ],
    }
    return {
        "ok": False,
        "mode": "auth-gate-live-preflight-audit",
        "transport": transport_name,
        "networkSent": False,
        "localProxyConnected": False,
        "sessionOwningIfRunLive": True,
        "desktopKeepaliveProven": False,
        "displayPathObserved": False,
        "verifiedRunPassed": False,
        "authGateOnly": True,
        "readyForGateOnlyLiveAttempt": ready_for_attempt,
        "missingConfiguration": missing_config,
        "runtimeGatesStillRequired": [
            "fresh cmd26 local proxy must return 1-byte status during live gate-only run",
            "same external UDP fd must receive 71-byte ACK-like before AUTH_DATA",
        ],
        "authPreflight": {
            **auth_material["summary"],
            "authHeadWire": auth_head_wire,
            "authDataWire": auth_data_wire,
            "authHeadConfiguredAttempts": int(auth_head_attempts or 0),
            "authHeadRetryIntervalSeconds": float(auth_head_retry_interval or 0.0),
            "payloadStoredInReport": False,
        },
        "preAuthLocalBootstrapPlan": bootstrap_plan,
        "preAuthTcpListenReadinessPlan": tcp_readiness_plan,
        "preAuthSessionState": state_model,
        "preAuthNativeSideEffectContract": pre_auth_native_side_effect_contract(
            state_model.get("nativeEquivalentStateModel")
        ),
        "configurationChecks": {
            **auth_checks,
            "stateContractConfigComplete": not missing_state_config,
            "preAuthCmd26Configured": bool(bootstrap_plan.get("enabled")),
        },
        "connectInfo": {
            "type": connect_info.get("type"),
            "hostPresent": bool(connect_info.get("host")),
            "portPresent": bool(connect_info.get("port")),
            "udpSsl": bool(connect_info.get("udpSsl")),
            "accessTokenPresent": bool(connect_info.get("accessToken")),
            "cpsidPresent": bool(connect_info.get("cpsid")),
            "payloadStoredInReport": False,
        },
        "authMaterialSource": material["summary"],
        "payloadStoredInReport": False,
        "nextStep": (
            "Run AUTH gate-only live in a session-owning window and stop after AUTH_DATA if same-fd 71-byte ACK-like is received."
            if ready_for_attempt
            else "Complete missing pre-AUTH gate-only configuration before any live run."
        ),
    }


def run_kcp_auth_sync_probe(
    *,
    auth_buffer,
    runner_input_file=None,
    runner_input=None,
    target=None,
    timeout=1.0,
    receive_limit=4,
    syn_id=None,
    conv=0,
    current=None,
    mtu=1400,
    be_ssl=False,
    detect_mtu=True,
    be_pack_check=True,
    be_fec=True,
    be_multi=False,
    be_algo_mode=1,
    be_using_stream=True,
    be_quic=True,
    be_outband=True,
    ztec_prime=False,
    ztec_host=None,
    ztec_port=None,
    ztec_timeout=None,
    local_bind_host=None,
    local_bind_port=None,
    pre_auth_receive_timeout=0.0,
    pre_auth_receive_limit=0,
    pre_auth_bind_host="0.0.0.0",
    pre_auth_fresh_cmd26_bootstrap=None,
    pre_auth_session_state_model=None,
    pre_auth_tcp_listen_readiness=False,
    auth_gate_only=False,
    auth_head_attempts=1,
    auth_head_retry_interval=0.08,
    report_file=None,
):
    """Run AUTH_HEAD/AUTH_DATA then client SYN against a live UDP endpoint.

    The auth buffer must be fresh and supplied in memory by a trusted caller.
    Reports intentionally include only redacted length/type summaries and KCP
    header summaries; auth payload bytes are never written to report files.
    """
    source = load_runner_input(runner_input_file) if runner_input_file else (runner_input or {})
    udp_target, target_text, source = _target_from_runner_input_for_raw_udp(source, target=target)
    if syn_id is None:
        syn_id = time.time_ns() & 0xFFFFFFFF
    if current is None:
        current = int(time.monotonic() * 1000) & 0xFFFFFFFF
    auth_material = build_kcp_auth_preflight_from_buffer(
        auth_buffer,
        conv=conv,
        syn_id=syn_id,
        current=current,
    )
    client_syn = build_kcp_client_syn_segment(
        conv=conv,
        syn_id=syn_id,
        current=current,
        mtu=mtu,
        be_ssl=be_ssl,
        detect_mtu=detect_mtu,
        be_pack_check=be_pack_check,
        be_fec=be_fec,
        be_multi=be_multi,
        be_algo_mode=be_algo_mode,
        be_using_stream=be_using_stream,
        be_quic=be_quic,
        be_outband=be_outband,
    )
    started_at = time.time()
    auth_head_attempts = max(1, int(auth_head_attempts or 1))
    auth_head_retry_interval = max(0.0, float(auth_head_retry_interval or 0.0))
    auth_head_ack = None
    auth_head_ack_like = None
    auth_ack = None
    synack = None
    auth_data_sent = False
    stages = []
    ztec_prime_report = {
        "enabled": False,
        "ackReceived": False,
    }
    local_socket_lifecycle = {
        "socketFamily": "AF_INET",
        "socketType": "SOCK_DGRAM",
        "explicitBindBeforeSend": False,
        "officialListenThreadStarted": False,
        "officialTcpLinkInfoWait": False,
        "officialCreateFdSessionModeled": False,
        "officialReadLoopStartedBeforeAuthHead": False,
        "officialUdpFdAttachedToIceSocket": False,
        "officialKcpAttachedToThreadList": False,
        "officialTcpListenReadinessModeled": False,
        "freshCmd26LocalBootstrapModeled": False,
        "freshCmd26LocalBootstrapStatusReceived": False,
        "preAuthSessionStateContractClosed": False,
        "preAuthReceiveLoopStarted": False,
        "implicitBindForPreAuthReceive": False,
        "requestedLocalBind": None,
        "getsocknameCapturedAfterFirstSend": True,
    }
    pre_auth_receive = {
        "enabled": bool(float(pre_auth_receive_timeout or 0) > 0 and int(pre_auth_receive_limit or 0) > 0),
        "timeoutSeconds": float(pre_auth_receive_timeout or 0),
        "receiveLimit": int(pre_auth_receive_limit or 0),
        "packets": [],
        "payloadStoredInReport": False,
    }
    pre_auth_local_bootstrap = {
        "enabled": False,
        "payloadStoredInReport": False,
    }
    pre_auth_tcp_readiness = {
        "enabled": False,
        "payloadStoredInReport": False,
    }
    pre_auth_session_state = {
        "enabled": False,
        "payloadStoredInReport": False,
    }
    tcp_readiness_listener, pre_auth_tcp_readiness = _start_pre_auth_tcp_listen_readiness(
        pre_auth_tcp_listen_readiness
    )
    try:
      with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(float(timeout))
        if local_bind_host is not None or local_bind_port is not None:
            bind_host = local_bind_host or "0.0.0.0"
            bind_port = int(local_bind_port or 0)
            local_socket_lifecycle["requestedLocalBind"] = f"{bind_host}:{bind_port}"
            sock.bind((bind_host, bind_port))
            local_socket_lifecycle["explicitBindBeforeSend"] = True
            local_socket_lifecycle["localEndpointAfterBind"] = format_udp_target(sock.getsockname()[:2])
        if pre_auth_receive["enabled"]:
            local_socket_lifecycle["preAuthReceiveLoopStarted"] = True
            if not local_socket_lifecycle["explicitBindBeforeSend"]:
                bind_host = pre_auth_bind_host or "0.0.0.0"
                sock.bind((bind_host, 0))
                local_socket_lifecycle["implicitBindForPreAuthReceive"] = True
                local_socket_lifecycle["localEndpointAfterPreAuthBind"] = format_udp_target(sock.getsockname()[:2])
            pre_auth_receive["localEndpointBeforeWindow"] = format_udp_target(sock.getsockname()[:2])
            pre_auth_receive["packets"] = _recv_pre_auth_window(
                sock,
                timeout=pre_auth_receive["timeoutSeconds"],
                receive_limit=pre_auth_receive["receiveLimit"],
            )
            pre_auth_receive["localEndpointAfterWindow"] = format_udp_target(sock.getsockname()[:2])
        local_socket_lifecycle["localEndpointBeforeFirstSend"] = format_udp_target(sock.getsockname()[:2])
        if pre_auth_fresh_cmd26_bootstrap:
            pre_auth_local_bootstrap = _run_pre_auth_fresh_cmd26_bootstrap(
                pre_auth_fresh_cmd26_bootstrap,
                timeout=timeout,
            )
            local_socket_lifecycle["freshCmd26LocalBootstrapModeled"] = bool(pre_auth_local_bootstrap.get("enabled"))
            local_socket_lifecycle["freshCmd26LocalBootstrapStatusReceived"] = bool(
                pre_auth_local_bootstrap.get("statusReceived")
            )
        pre_auth_session_state = _summarize_pre_auth_session_state_model(
            pre_auth_session_state_model,
            pre_auth_local_bootstrap=pre_auth_local_bootstrap,
        )
        local_socket_lifecycle["preAuthSessionStateContractClosed"] = bool(
            pre_auth_session_state.get("allRequiredModeled")
        )
        if pre_auth_tcp_readiness.get("enabled"):
            local_socket_lifecycle["officialListenThreadStarted"] = True
            local_socket_lifecycle["officialTcpLinkInfoWait"] = True
            local_socket_lifecycle["officialTcpListenReadinessModeled"] = bool(
                pre_auth_tcp_readiness.get("listenReady")
            )
        if ztec_prime:
            ztec_prime_report = _send_ztec_prime_on_socket(
                sock,
                udp_target,
                ztec_host=ztec_host,
                ztec_port=ztec_port,
                timeout=timeout if ztec_timeout is None else ztec_timeout,
            )

        local_endpoint = local_socket_lifecycle["localEndpointBeforeFirstSend"]
        auth_head_stage = {
            "stage": "auth_head",
            "bytesSent": 0,
            "sendCount": 0,
            "totalBytesSent": 0,
            "attempts": [],
            "officialAuthHeadPump": {
                "enabled": auth_head_attempts > 1,
                "configuredAttempts": auth_head_attempts,
                "retryIntervalSeconds": auth_head_retry_interval,
                "source": "fresh official trace: AUTH_HEAD sent three times at ~77 ms and ~82 ms gaps before 71-byte ACK-like",
            },
            "segment": _kcp_segment_summary(decode_kcp_segment(auth_material["authHeadSegment"])),
        }
        stages.append(auth_head_stage)
        responses = []
        for attempt_index in range(auth_head_attempts):
            sent = sock.sendto(auth_material["authHeadSegment"], udp_target)
            if attempt_index == 0:
                local_endpoint = format_udp_target(sock.getsockname()[:2])
                local_socket_lifecycle["localEndpointAfterFirstSend"] = local_endpoint
                auth_head_stage["bytesSent"] = sent
            auth_head_stage["sendCount"] += 1
            auth_head_stage["totalBytesSent"] += sent
            auth_head_stage["attempts"].append({
                "attempt": attempt_index + 1,
                "bytesSent": sent,
            })
            per_attempt_timeout = float(timeout)
            if attempt_index < auth_head_attempts - 1:
                per_attempt_timeout = min(float(timeout), auth_head_retry_interval) if auth_head_retry_interval else 0.0
            attempt_responses, auth_head_ack, auth_head_ack_like = _recv_auth_head_gate_ack(
                sock,
                timeout=per_attempt_timeout,
                receive_limit=receive_limit,
                expected_remote=udp_target,
            )
            for response in attempt_responses:
                response["afterAuthHeadAttempt"] = attempt_index + 1
            responses.extend(attempt_responses)
            if auth_head_ack or auth_head_ack_like:
                break
        if "localEndpointAfterFirstSend" not in local_socket_lifecycle:
            local_socket_lifecycle["localEndpointAfterFirstSend"] = format_udp_target(sock.getsockname()[:2])
            local_endpoint = local_socket_lifecycle["localEndpointAfterFirstSend"]
        local_socket_lifecycle["authHeadSendCount"] = auth_head_stage["sendCount"]
        local_socket_lifecycle["authHeadConfiguredAttempts"] = auth_head_attempts
        local_socket_lifecycle["authHeadRetryIntervalSeconds"] = auth_head_retry_interval
        auth_head_stage["responses"] = responses
        auth_head_stage["ackReceived"] = auth_head_ack is not None
        auth_head_stage["ackLikeReceived"] = auth_head_ack_like is not None
        auth_head_stage["authGateAccepted"] = bool(auth_head_ack or auth_head_ack_like)
        if auth_head_ack or auth_head_ack_like:
            sent = sock.sendto(auth_material["authDataSegment"], udp_target)
            auth_data_sent = True
            stages.append({
                "stage": "auth_data",
                "bytesSent": sent,
                "segment": _kcp_segment_summary(decode_kcp_segment(auth_material["authDataSegment"])),
            })
            if auth_gate_only:
                stages[-1]["responses"] = []
                stages[-1]["ackReceived"] = False
                stages[-1]["stoppedAtAuthGate"] = True
            else:
                responses, auth_ack = _recv_kcp_until(
                    sock,
                    timeout=timeout,
                    receive_limit=receive_limit,
                    predicate=lambda decoded: decoded.get("authAckCmd"),
                )
                stages[-1]["responses"] = responses
                stages[-1]["ackReceived"] = auth_ack is not None
        if auth_ack and not auth_gate_only:
            sent = sock.sendto(client_syn, udp_target)
            stages.append({
                "stage": "client_syn",
                "bytesSent": sent,
                "segment": _kcp_segment_summary(decode_kcp_segment(client_syn)),
            })
            responses, synack = _recv_kcp_until(
                sock,
                timeout=timeout,
                receive_limit=receive_limit,
                predicate=lambda decoded: decoded.get("syncAckConv"),
            )
            stages[-1]["responses"] = responses
            stages[-1]["synackReceived"] = synack is not None
    finally:
        if tcp_readiness_listener is not None:
            tcp_readiness_listener.close()
    report = {
        "ok": synack is not None,
        "transport": "kcp-auth-sync-udp",
        "target": target_text,
        "sessionOwningIfUsedLive": True,
        "desktopKeepaliveProven": False,
        "displayPathObserved": False,
        "verifiedRunPassed": False,
        "proof": "kcp_auth_sync_probe_only",
        "source": {
            "transport": source.get("transport"),
            "sourceTrace": source.get("sourceTrace"),
        },
        "authPreflight": {
            **auth_material["summary"],
            "authHeadWire": redacted_kcp_auth_wire_summary(auth_material["authHeadSegment"]),
            "authDataWire": redacted_kcp_auth_wire_summary(auth_material["authDataSegment"]),
            "authHeadSendCount": local_socket_lifecycle.get("authHeadSendCount"),
            "authHeadConfiguredAttempts": auth_head_attempts,
            "authHeadRetryIntervalSeconds": auth_head_retry_interval,
            "authHeadAckReceived": auth_head_ack is not None,
            "authHeadAckLikeReceived": auth_head_ack_like is not None,
            "authHeadGateAccepted": bool(auth_head_ack or auth_head_ack_like),
            "officialAckLikeLength": OFFICIAL_AUTH_HEAD_ACK_LIKE_LEN,
            "authDataSentAfterAuthHeadGate": auth_data_sent,
            "authAckReceived": auth_ack is not None,
            "payloadStoredInReport": False,
        },
        "authGateOnly": bool(auth_gate_only),
        "authGateConfirmed": bool((auth_head_ack or auth_head_ack_like) and auth_data_sent),
        "idaHandshakeEvidence": kcp_sync_ida_evidence(),
        "idaUdpSessionEvidence": kcp_udp_session_lifecycle_ida_evidence(),
        "localSocketLifecycle": local_socket_lifecycle,
        "preAuthReceive": pre_auth_receive,
        "preAuthLocalBootstrap": pre_auth_local_bootstrap,
        "preAuthTcpListenReadiness": pre_auth_tcp_readiness,
        "preAuthSessionState": pre_auth_session_state,
        "preAuthNativeSideEffectContract": pre_auth_native_side_effect_contract(
            pre_auth_session_state.get("nativeEquivalentStateModel")
        ),
        "officialParityAssessment": _kcp_auth_probe_parity_assessment(
            local_socket_lifecycle,
            pre_auth_session_state=pre_auth_session_state,
            auth_head_ack=auth_head_ack,
            auth_head_ack_like=auth_head_ack_like,
            auth_ack=auth_ack,
            synack=synack,
            auth_gate_only=auth_gate_only,
        ),
        "localEndpoint": local_endpoint,
        "ztecPrime": ztec_prime_report,
        "stages": stages,
        "synackReceived": synack is not None,
        "synack": _kcp_segment_summary(synack) if synack else None,
        "synackNegotiation": kcp_synack_negotiation_summary(synack) if synack else None,
        "nextStep": (
            "Use SYNACK fields to initialize KCP/ZIME channel context before native ZIME channel creation."
            if synack
            else (
                "AUTH gate reproduced through AUTH_DATA; stop here until the AUTH gate evidence is reviewed before SYNACK/native bridge/DISPLAY_INIT."
                if auth_gate_only and auth_data_sent
                else "AUTH gate did not complete; reproduce official local proxy/session bootstrap and first 199-byte AUTH_HEAD before any SYNACK/native bridge work."
            )
        ),
        "startedAt": started_at,
        "endedAt": time.time(),
    }
    report["elapsedSeconds"] = round(report["endedAt"] - report["startedAt"], 3)
    core.write_private_json_report(report, report_file)
    return report


def _redact_cag_kcp_auth_sync_report(report):
    pre_auth = report.get("preAuthReceive")
    if isinstance(pre_auth, dict):
        for packet in pre_auth.get("packets") or []:
            if packet.get("remote"):
                packet["remote"] = "<redacted:cag-udp-peer>"
    for stage in report.get("stages") or []:
        for response in stage.get("responses") or []:
            if response.get("remote"):
                response["remote"] = "<redacted:cag-udp-peer>"
    ztec = report.get("ztecPrime")
    if isinstance(ztec, dict) and ztec.get("enabled"):
        report["ztecPrime"] = {
            "enabled": True,
            "target": "<redacted:cag-udp-target>",
            "bytesSent": ztec.get("bytesSent"),
            "request": {
                "hostPresent": bool((ztec.get("request") or {}).get("host")),
                "portPresent": bool((ztec.get("request") or {}).get("port")),
                "sequencePresent": "sequence" in (ztec.get("request") or {}),
                "payloadStoredInReport": False,
            },
            "ackReceived": bool(ztec.get("ackReceived")),
            "responseBytes": ztec.get("responseBytes"),
            "responseKind": ztec.get("responseKind"),
            "error": ztec.get("error"),
            "responseRemote": "<redacted:cag-udp-peer>" if ztec.get("responseRemote") else None,
            "payloadStoredInReport": False,
        }
    return report


def run_kcp_auth_sync_probe_from_cag_material(
    *,
    auth,
    connect_info,
    timeout=1.0,
    receive_limit=4,
    syn_id=None,
    conv=0,
    current=None,
    mtu=1400,
    be_ssl=False,
    detect_mtu=True,
    be_pack_check=True,
    be_fec=True,
    be_multi=False,
    be_algo_mode=1,
    be_using_stream=True,
    be_quic=True,
    be_outband=True,
    ztec_prime=False,
    ztec_host=None,
    ztec_port=None,
    ztec_timeout=None,
    local_bind_host=None,
    local_bind_port=None,
    pre_auth_receive_timeout=0.0,
    pre_auth_receive_limit=0,
    pre_auth_bind_host="0.0.0.0",
    pre_auth_fresh_cmd26_bootstrap=None,
    pre_auth_session_state_model=None,
    pre_auth_tcp_listen_readiness=False,
    serial_uuid=None,
    random_c=None,
    auth_buffer_type="type101",
    auth_type=None,
    link_type=ZTEC_CAG_TYPE101_LINK_TYPE_PROXY,
    opentelemetry=True,
    auth_gate_only=True,
    auth_head_attempts=3,
    auth_head_retry_interval=0.08,
    trace_id="",
    span_id="",
    report_file=None,
):
    """Build a fresh CAG auth buffer from CAG material and probe AUTH/SYNACK.

    ``auth`` and ``connect_info`` are live in-memory inputs.  The output report
    is redacted and does not persist the auth buffer or CAG target address.
    """
    normalized_auth_buffer_type = str(auth_buffer_type or "type101").strip().lower()
    if normalized_auth_buffer_type in {"101", "type101", "password"}:
        material = build_ztec_cag_type101_auth_buffer_from_material(
            auth,
            connect_info,
            serial_uuid=serial_uuid,
            random_c=random_c,
            link_type=link_type,
            opentelemetry=opentelemetry,
            trace_id=trace_id,
            span_id=span_id,
        )
        transport_name = "fresh-cag-type101-material"
        proof_name = "fresh_cag_type101_kcp_auth_sync_probe_only"
    elif normalized_auth_buffer_type in {"102", "type102", "uac", "token"}:
        material = build_ztec_cag_type102_auth_buffer_from_material(
            auth,
            connect_info,
            auth_type=auth_type,
            serial_uuid=serial_uuid,
            random_c=random_c,
            link_type=link_type,
            opentelemetry=opentelemetry,
            trace_id=trace_id,
            span_id=span_id,
        )
        transport_name = "fresh-cag-type102-material"
        proof_name = "fresh_cag_type102_kcp_auth_sync_probe_only"
    else:
        raise ValueError(f"unsupported CAG auth buffer type: {auth_buffer_type}")
    target = f"{connect_info.get('host')}:{connect_info.get('port')}"
    raw_args = connect_info.get("rawArgs") or {}
    default_ztec_host = (
        ztec_host
        or connect_info.get("vmHost")
        or _first_connect_arg_value(raw_args.get("vmip"))
    )
    default_ztec_port = (
        ztec_port
        or connect_info.get("vmPort")
        or raw_args.get("vmport")
    )
    report = run_kcp_auth_sync_probe(
        auth_buffer=material["authBuffer"],
        runner_input={
            "transport": transport_name,
            "candidateUdpTargets": [target],
        },
        timeout=timeout,
        receive_limit=receive_limit,
        syn_id=syn_id,
        conv=conv,
        current=current,
        mtu=mtu,
        be_ssl=be_ssl or bool(connect_info.get("udpSsl")),
        detect_mtu=detect_mtu,
        be_pack_check=be_pack_check,
        be_fec=be_fec,
        be_multi=be_multi,
        be_algo_mode=be_algo_mode,
        be_using_stream=be_using_stream,
        be_quic=be_quic,
        be_outband=be_outband,
        ztec_prime=ztec_prime,
        ztec_host=default_ztec_host,
        ztec_port=default_ztec_port,
        ztec_timeout=ztec_timeout,
        local_bind_host=local_bind_host,
        local_bind_port=local_bind_port,
        pre_auth_receive_timeout=pre_auth_receive_timeout,
        pre_auth_receive_limit=pre_auth_receive_limit,
        pre_auth_bind_host=pre_auth_bind_host,
        pre_auth_fresh_cmd26_bootstrap=pre_auth_fresh_cmd26_bootstrap,
        pre_auth_session_state_model=pre_auth_session_state_model,
        pre_auth_tcp_listen_readiness=pre_auth_tcp_listen_readiness,
        auth_gate_only=auth_gate_only,
        auth_head_attempts=auth_head_attempts,
        auth_head_retry_interval=auth_head_retry_interval,
        report_file=None,
    )
    _redact_cag_kcp_auth_sync_report(report)
    report["target"] = "<redacted:cag-udp-target>"
    report["proof"] = proof_name
    report["authMaterialSource"] = material["summary"]
    report["connectInfo"] = {
        "type": connect_info.get("type"),
        "hostPresent": bool(connect_info.get("host")),
        "portPresent": bool(connect_info.get("port")),
        "gatewayPortPresent": bool(connect_info.get("gatewayPort")),
        "udpPortSource": connect_info.get("udpPortSource"),
        "udpSsl": bool(connect_info.get("udpSsl")),
        "accessTokenPresent": bool(connect_info.get("accessToken")),
        "cpsidPresent": bool(connect_info.get("cpsid")),
        "ztecPrimeHostSource": (
            "explicit" if ztec_host else ("vmHost" if connect_info.get("vmHost") else ("rawArgs.vmip" if raw_args.get("vmip") else "udpTarget"))
        ),
        "ztecPrimePortSource": (
            "explicit" if ztec_port else ("vmPort" if connect_info.get("vmPort") else ("rawArgs.vmport" if raw_args.get("vmport") else "udpTarget"))
        ),
        "payloadStoredInReport": False,
    }
    report["nextStep"] = (
        "Use SYNACK fields to initialize KCP/ZIME channel context before native ZIME channel creation."
        if report.get("synackReceived")
        else (
            "AUTH gate reproduced through AUTH_DATA; stop here before AUTH_ACK/SYNACK/native bridge/DISPLAY_INIT."
            if report.get("authGateConfirmed")
            else "Fresh CAG AUTH gate did not complete; reproduce official local proxy/session bootstrap and first 199-byte AUTH_HEAD before any SYNACK/native bridge work."
        )
    )
    core.write_private_json_report(report, report_file)
    return report


def assess_auth_gate_only_report(report):
    """Assess whether a redacted report proves the current AUTH gate-only success.

    This deliberately does not treat SYNACK, native bridge, DISPLAY_INIT, ACK/PONG,
    or MARK activity as success.  The only accepted proof is the current gate:
    local cmd26/status, AUTH_HEAD199, same-remote 71-byte ACK-like, AUTH_DATA241,
    then stop.
    """
    if not isinstance(report, dict):
        raise ValueError("auth gate report must be a JSON object")

    stages = report.get("stages") or []
    stage_names = [stage.get("stage") for stage in stages if isinstance(stage, dict)]
    auth_head_stage = next(
        (stage for stage in stages if isinstance(stage, dict) and stage.get("stage") == "auth_head"),
        {},
    )
    auth_data_stage = next(
        (stage for stage in stages if isinstance(stage, dict) and stage.get("stage") == "auth_data"),
        {},
    )
    ack_like_responses = [
        response
        for response in auth_head_stage.get("responses") or []
        if isinstance(response, dict)
        and response.get("officialAuthHeadAckLike")
        and response.get("bytesReceived") == OFFICIAL_AUTH_HEAD_ACK_LIKE_LEN
        and response.get("sameExternalFdAsAuthHead") is True
        and response.get("sameRemoteAsAuthTarget") is True
    ]
    preflight = report.get("authPreflight") or {}
    bootstrap = report.get("preAuthLocalBootstrap") or {}
    session_state = report.get("preAuthSessionState") or {}
    auth_material_source = report.get("authMaterialSource") or {}

    sensitive_report_key_names = {
        "accessToken",
        "authBuffer",
        "authPayload",
        "authPayloadHex",
        "bodyHex",
        "connectStr",
        "cpsid",
        "frameBodyHex",
        "jwt",
        "localProxyFrameBody",
        "password",
        "payload",
        "payloadHex",
        "token",
        "vmPassword",
    }
    normalized_sensitive_report_keys = {
        "".join(ch for ch in key.lower() if ch.isalnum()) for key in sensitive_report_key_names
    }

    def contains_sensitive_report_key(value):
        if isinstance(value, dict):
            for key, child in value.items():
                normalized_key = "".join(ch for ch in str(key).lower() if ch.isalnum())
                if normalized_key in normalized_sensitive_report_keys and child is not None and not isinstance(child, bool):
                    return True
                if contains_sensitive_report_key(child):
                    return True
        elif isinstance(value, list):
            return any(contains_sensitive_report_key(item) for item in value)
        return False

    auth_head_responses = [
        response for response in auth_head_stage.get("responses") or [] if isinstance(response, dict)
    ]

    checks = []

    def add(key, ok, official_trace_field, detail=""):
        checks.append({
            "key": key,
            "ok": bool(ok),
            "officialTraceField": official_trace_field,
            "detail": detail,
        })

    add("auth_gate_only_mode", report.get("authGateOnly") is True, "gate-only Python run stops at AUTH_DATA")
    add("no_desktop_keepalive_claim", report.get("desktopKeepaliveProven") is False, "40-minute verified-run remains out of scope")
    add("no_display_path_claim", report.get("displayPathObserved") is False, "DISPLAY_INIT/native display path remains frozen")
    add("no_verified_run_claim", report.get("verifiedRunPassed") is False, "40-minute verified-run remains frozen")
    add("pre_auth_cmd26_send160", bootstrap.get("bytesSent") == FRESH_CMD26_WIRE_LEN, "loopback client send len=160 cmd26")
    add("pre_auth_cmd26_status1", bootstrap.get("statusReceived") is True and (bootstrap.get("statusBytesReceived") or 0) >= 1, "client-side recv local proxy status/control response")
    add("pre_auth_state_contract", session_state.get("readyForGateOnlyLive") is True, "external AUTH_HEAD len=199 follows local proxy/session setup")
    add("auth_head_wire_len_199", (preflight.get("authHeadWire") or {}).get("wireLen") == OFFICIAL_AUTH_HEAD_WIRE_LEN, "external AUTH_HEAD len=199")
    add("auth_data_wire_len_241", (preflight.get("authDataWire") or {}).get("wireLen") == OFFICIAL_AUTH_DATA_WIRE_LEN, "external AUTH_DATA len=241")
    add("same_remote_ack_like_71", bool(ack_like_responses) and preflight.get("authHeadAckLikeReceived") is True, "same external fd/remote recv len=71 ACK-like")
    add("auth_data_after_ack_like", preflight.get("authDataSentAfterAuthHeadGate") is True and report.get("authGateConfirmed") is True, "AUTH_DATA sent only after 71-byte ACK-like")
    add("stopped_at_auth_gate", stage_names == ["auth_head", "auth_data"] and auth_data_stage.get("stoppedAtAuthGate") is True, "stop immediately after AUTH_DATA in gate-only mode")
    add("no_auth_ack_claim", preflight.get("authAckReceived") is False, "AUTH_ACK remains frozen before gate review")
    add("no_synack_claim", report.get("synackReceived") is False and report.get("synack") is None, "SYNACK/native bridge remains frozen")
    add(
        "no_auth_payload_stored",
        preflight.get("payloadStoredInReport") is False
        and (preflight.get("authHeadWire") or {}).get("payloadStoredInReport") is False
        and (preflight.get("authDataWire") or {}).get("payloadStoredInReport") is False,
        "auth payload bytes are not stored in accepted reports",
    )
    add(
        "no_local_proxy_payload_stored",
        bootstrap.get("payloadStoredInReport") is False,
        "local proxy frame body is not stored in accepted reports",
    )
    add(
        "no_ack_like_payload_stored",
        bool(auth_head_responses) and all(response.get("payloadStoredInReport") is False for response in auth_head_responses),
        "ACK-like/local response payload bytes are not stored in accepted reports",
    )
    add(
        "no_auth_material_payload_stored",
        auth_material_source.get("payloadStoredInReport") is False,
        "CAG auth material is summarized without payload bytes",
    )
    add(
        "no_sensitive_payload_fields",
        not contains_sensitive_report_key(report),
        "accepted report contains no sensitive payload field names",
    )

    missing = [item["key"] for item in checks if not item["ok"]]
    accepted = not missing

    failure_stage_by_check = {
        "auth_gate_only_mode": "execution_boundary",
        "no_desktop_keepalive_claim": "frozen_scope_violation",
        "no_display_path_claim": "frozen_scope_violation",
        "no_verified_run_claim": "frozen_scope_violation",
        "pre_auth_cmd26_send160": "local_proxy_bootstrap",
        "pre_auth_cmd26_status1": "local_proxy_bootstrap",
        "pre_auth_state_contract": "session_state_contract",
        "auth_head_wire_len_199": "auth_head_wire",
        "auth_data_wire_len_241": "auth_data_wire",
        "same_remote_ack_like_71": "auth_head_ack_like",
        "auth_data_after_ack_like": "auth_data_gate",
        "stopped_at_auth_gate": "gate_only_stop",
        "no_auth_ack_claim": "frozen_scope_violation",
        "no_synack_claim": "frozen_scope_violation",
        "no_auth_payload_stored": "report_redaction",
        "no_local_proxy_payload_stored": "report_redaction",
        "no_ack_like_payload_stored": "report_redaction",
        "no_auth_material_payload_stored": "report_redaction",
        "no_sensitive_payload_fields": "report_redaction",
    }
    first_missing_check = next((item for item in checks if not item["ok"]), None)
    first_blocking_stage = (
        failure_stage_by_check.get(first_missing_check["key"], "unknown")
        if first_missing_check
        else None
    )
    return {
        "ok": accepted,
        "mode": "auth-gate-only-report-acceptance",
        "authGateOnlyAccepted": accepted,
        "desktopKeepaliveProven": False,
        "displayPathObserved": False,
        "verifiedRunPassed": False,
        "checks": checks,
        "missingEvidence": missing,
        "failureStage": first_blocking_stage,
        "failureCheck": first_missing_check["key"] if first_missing_check else None,
        "failureOfficialTraceField": first_missing_check["officialTraceField"] if first_missing_check else None,
        "acceptedProof": (
            "local cmd26/status -> AUTH_HEAD199 -> same-remote 71-byte ACK-like -> AUTH_DATA241 -> stop"
            if accepted
            else ""
        ),
        "officialTraceFields": [
            "loopback client send len=160 cmd26",
            "client-side recv len=1 cmd26 status",
            "external AUTH_HEAD len=199",
            "same external fd recv len=71 ACK-like",
            "external AUTH_DATA len=241",
        ],
        "payloadStoredInReport": False,
        "nextStep": (
            "AUTH gate-only evidence is present; review it before any AUTH_ACK/SYNACK/native bridge/DISPLAY_INIT work."
            if accepted
            else "AUTH gate-only evidence is incomplete; do not advance to AUTH_ACK/SYNACK/native bridge/DISPLAY_INIT."
        ),
    }


def run_kcp_sync_probe(
    *,
    runner_input_file=None,
    runner_input=None,
    target=None,
    timeout=1.0,
    receive_limit=4,
    syn_id=None,
    conv=0,
    current=None,
    mtu=1400,
    be_ssl=False,
    detect_mtu=True,
    be_pack_check=True,
    be_fec=True,
    be_multi=False,
    be_algo_mode=1,
    be_using_stream=True,
    be_quic=True,
    be_outband=True,
    report_file=None,
):
    """Send the recovered KCP client SYN and wait for a SYNACK-like datagram.

    This is a transport handshake probe only.  It does not prove desktop
    keepalive and does not call native ZIME.
    """
    source = load_runner_input(runner_input_file) if runner_input_file else (runner_input or {})
    udp_target, target_text, source = _target_from_runner_input_for_raw_udp(source, target=target)
    if syn_id is None:
        syn_id = time.time_ns() & 0xFFFFFFFF
    if current is None:
        current = int(time.monotonic() * 1000) & 0xFFFFFFFF
    packet = build_kcp_client_syn_segment(
        conv=conv,
        syn_id=syn_id,
        current=current,
        mtu=mtu,
        be_ssl=be_ssl,
        detect_mtu=detect_mtu,
        be_pack_check=be_pack_check,
        be_fec=be_fec,
        be_multi=be_multi,
        be_algo_mode=be_algo_mode,
        be_using_stream=be_using_stream,
        be_quic=be_quic,
        be_outband=be_outband,
    )
    sent_at = time.time()
    responses = []
    synack = None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(float(timeout))
        sent = sock.sendto(packet, udp_target)
        local_endpoint = format_udp_target(sock.getsockname()[:2])
        for _ in range(max(0, int(receive_limit))):
            try:
                data, remote = sock.recvfrom(65535)
            except socket.timeout:
                break
            decoded = None
            if looks_like_kcp_segment(data):
                decoded = decode_kcp_segment(data)
            item = {
                "remote": format_udp_target(remote[:2]),
                "bytesReceived": len(data),
                "payloadKind": classify_payload(data),
                "kcp": _kcp_segment_summary(decoded) if decoded else None,
            }
            responses.append(item)
            if decoded and decoded.get("syncAckConv"):
                synack = decoded
                break
    report = {
        "ok": synack is not None,
        "transport": "kcp-sync-udp",
        "target": target_text,
        "sessionOwningIfUsedLive": True,
        "desktopKeepaliveProven": False,
        "displayPathObserved": False,
        "verifiedRunPassed": False,
        "proof": "kcp_sync_probe_only",
        "source": {
            "transport": source.get("transport"),
            "sourceTrace": source.get("sourceTrace"),
        },
        "idaHandshakeEvidence": kcp_sync_ida_evidence(),
        "authPreflight": kcp_auth_preflight_summary(),
        "localEndpoint": local_endpoint,
        "clientSyn": _kcp_segment_summary(decode_kcp_segment(packet)),
        "bytesSent": sent,
        "responses": responses,
        "synackReceived": synack is not None,
        "synack": _kcp_segment_summary(synack) if synack else None,
        "synackNegotiation": kcp_synack_negotiation_summary(synack) if synack else None,
        "nextStep": (
            "Use SYNACK fields to initialize KCP/ZIME channel context before native ZIME channel creation."
            if synack
            else "No SYNACK received; do not repeat raw ZIME packet-out until target/session context is refreshed or SYN parameters are corrected."
        ),
        "startedAt": sent_at,
        "endedAt": time.time(),
    }
    report["elapsedSeconds"] = round(report["endedAt"] - report["startedAt"], 3)
    core.write_private_json_report(report, report_file)
    return report


def kcp_sync_ida_evidence():
    """Return non-sensitive IDA evidence needed to interpret SYN/SYNACK probes."""
    return {
        "authPreflight": {
            "function": "ikcp_set_auth_data / deal_kcp_auth_cmd / ikcp_set_auth_data_res",
            "sequence": [
                "send IKCP_CONV_AUTH_HEAD with auth head bytes when auth head is pending",
                "wait for IKCP_CONV_AUTH_HEAD_ACK (cmd 7)",
                "send IKCP_CONV_AUTH_DATA with auth data bytes",
                "wait for IKCP_CONV_AUTH_ACK (cmd 9)",
                "ikcp_set_auth_data_res calls ikcp_send_link_sync only after deal_auth_res returns 200",
            ],
            "clientAuthHeadConv": KCP_AUTH_HEAD_CONV,
            "clientAuthDataConv": KCP_AUTH_DATA_CONV,
            "safeRunnerConstraint": "Do not synthesize auth payload from stale or sensitive state; recover it from fresh official trace or confirmed connect material first.",
        },
        "clientSyn": {
            "function": "ikcp_send_link_sync",
            "wireSize": "21 bytes for fresh SYN; 85 bytes when reconnect_last_conv is present",
            "conv": KCP_CLIENT_SYN_CONV,
            "declaredLen": "kcp->mtu, not payload length",
            "sn": "kcp->syn_id",
            "una": "kcp->conv",
            "defaultCapabilities": [
                "detect-mtu",
                "client-pack-check",
                "client-fec",
                "support-data-ex",
                "stream",
                "outband",
                "quic",
            ],
        },
        "clientSynackMatch": {
            "function": "get_thread_kcp",
            "appliesWhenCmd": [1, 2, 7, 9],
            "rule": "incoming source port must match kcp->dest_port and segment sn must match kcp->syn_id",
            "whyItMatters": (
                "A probe with a correct 21-byte SYN can still receive no usable SYNACK "
                "when target/session context is stale or when the peer does not bind the "
                "packet to the current KCP session."
            ),
        },
        "serverSynackHandling": {
            "function": "ikcp_deal_svr_sync_ack",
            "convUpdate": "kcp->conv = synack.una",
            "packCheck": "client pack-check remains enabled only when synack.cmd has server-pack-check",
            "fec": "client FEC remains enabled only when synack.cmd has server-fec",
            "useQuic": "kcp->use_quic is true only when client requested QUIC and synack.wnd has quic",
            "usingStream": "kcp->be_using_stream follows synack.wnd stream bit",
            "headLen": "21 + 2 when FEC is negotiated, plus 1 when stream is negotiated",
            "nextPacket": "client sends IKCP_CONV_SYNACK ack back after processing SYNACK",
        },
        "zimeGate": {
            "function": "deal_kcp_sync_ack_cmd",
            "rule": "QUIC/ZIME channel creation happens only after SYNACK and use_quic negotiation",
        },
    }


def kcp_udp_session_lifecycle_ida_evidence():
    """Return non-sensitive IDA evidence for official UDP/KCP session setup."""
    return {
        "sourceReports": [
            "reports/ida-libspice-zime-auth-source-20260704.json",
            "reports/ida-libspice-zime-udp-fd-source-20260704.json",
            "reports/ida-snippet-spice_init_udp_thread.txt",
            "reports/ida-snippet-listen_udp_data.txt",
            "reports/ida-snippet-init_local_rw_sock_pair_udp.txt",
            "reports/ida-snippet-create_udt_session.txt",
            "reports/ida-snippet-ice_create_fd-20260704.txt",
            "reports/ida-snippet-udp_get_local_port-20260704.txt",
            "reports/ida-snippet-send_udt_data-20260704.txt",
            "reports/ida-snippet-create_fd_session-20260704.txt",
            "reports/ida-libspice-zime-link-flag-source-directed-20260704.json",
            "reports/ida-libspice-zime-link-flag-source-directed-20260704-snippets.txt",
        ],
        "officialSequence": [
            "spice_init_udp_thread() stores destination via udp_set_dest_addr_info()",
            "spice_init_udp_thread() starts listen_udp_data_thread when g_udt_thread_run is false",
            "listen_udp_data() creates g_sock_listen_fd via ice_create_fd(0, 0): TCP listen on 127.0.0.1:0",
            "listen_udp_data() creates g_sock_udt_fd via ice_create_fd(0, 1): UDP socket without TCP bind/listen",
            "listen_udp_data() configures UDP socket buffers and PMTU/DF related options",
            "listen_udp_data() calls udp_get_local_port(g_sock_listen_fd), which stores the TCP listen port in g_tcp_listen_port",
            "spice_init_udp_thread() waits until udp_get_tcp_link_info(nullptr) returns non-null",
            "deal_unlinked_unknown_local_data() reads the local proxy protocol header and sets data_buf[224] to 1 or 2",
            "deal_local_link_proxy_create() maps data_buf[224] through get_proxy_type_by_link_type() and creates a proxy fd session if missing",
            "deal_create_proxy_fd_session() stores link_type into proxy_sock->data_buf[224]",
            "init_local_rw_sock_pair_udp() creates a TN_UDP_CLD_SOCK fd session on the UDP fd",
            "init_local_rw_sock_pair_udp() copies proxy_sock->data_buf[224] into udp_sock->data_buf[224]",
            "init_local_rw_sock_pair_udp() creates a KCP session with create_udt_session(dest_ip, dest_port, udp_fd, ...)",
            "init_local_rw_sock_pair_udp() links the KCP into the thread kcp_list and sets user_data=udp_sock",
            "deal_udt_using_cag() runs only after the KCP/session object is attached when be_using_cag is true",
        ],
        "functionEvidence": {
            "deal_unlinked_unknown_local_data": {
                "behavior": "after collecting the 4-byte proxy protocol header, sets data_buf[224]=1, then switches it to 2 when check_spice_proxy_protocol_header() indicates the outband header path",
                "implication": "the official link flag is negotiated before CAG AUTH and is not a value derived from auth-buffer material alone",
            },
            "deal_local_link_proxy_create": {
                "behavior": "maps the local socket link flag through get_proxy_type_by_link_type() and calls deal_create_proxy_fd_session() when the needed proxy fd session does not exist",
                "implication": "proxy fd/session setup is a precondition for the UDP/KCP pair path used by init_local_rw_sock_pair_udp()",
            },
            "deal_create_proxy_fd_session": {
                "behavior": "defaults link_type=1, switches to link_type=2 for TN_MULTI_TCP_SOCK, then writes proxy_sock->data_buf[224]=link_type",
                "implication": "the proxy socket is the upstream source of the UDP socket link flag observed by deal_udt_using_cag()",
            },
            "ice_create_fd": {
                "behavior": "with be_udp=0 creates TCP socket, sets SO_REUSEADDR, binds 127.0.0.1:port, fcntl nonblocking, then listen(5); with be_udp=1 creates UDP socket and returns it after nonblocking setup without TCP bind/listen",
                "implication": "the official readiness port is a local TCP listen port; it should not be confused with the outbound UDP source port",
            },
            "udp_get_local_port": {
                "behavior": "calls getsockname(fd) and stores ntohs(sockaddr_in.sin_port) into g_tcp_listen_port",
                "implication": "udp_get_tcp_link_info() gates on a local TCP listen endpoint being ready",
            },
            "spice_init_udp_thread": {
                "behavior": "starts listen_udp_data_thread and waits for udp_get_tcp_link_info(nullptr)",
                "implication": "official setup has an asynchronous listener/bootstrap phase before KCP CAG auth",
            },
            "listen_udp_data": {
                "behavior": "creates separate listen and UDP fds, applies socket options, calls udp_get_local_port(), then enters ice_deal_sock()",
                "implication": "official traffic is tied to a long-lived event loop, not a one-shot UDP send path",
            },
            "init_local_rw_sock_pair_udp": {
                "behavior": "creates TN_UDP_CLD_SOCK session, copies proxy_sock->data_buf[224] to udp_sock->data_buf[224], pairs it with the inbound socket, creates KCP, attaches it to thread kcp_list, then calls deal_udt_using_cag()",
                "implication": "KCP AUTH is emitted after fd-session, link-flag propagation and thread-list state exist",
            },
            "create_fd_session": {
                "behavior": "allocates/reuses an IceSocket, stores fd in gap14[4], records sock_type, links the socket into the thread socket ring, and initializes queues/mutexes",
                "implication": "the official UDP fd is wrapped in IceSocket/thread state before KCP output uses it",
            },
            "create_udt_session": {
                "behavior": "calls ikcp_create(), ikcp_set_dest(), sets stream/output callbacks, generates syn_id with ZXRand(), and enables detect-MTU",
                "implication": "syn_id and destination are properties of an attached KCP object",
            },
            "udt_output": {
                "behavior": "builds sockaddr from kcp->dest_ip/dest_port and calls send_udt_data(buf, len, sa, sa_len, user, &saved_errno)",
                "implication": "wire output uses the fd/session object passed as KCP user data, not only a destination tuple",
            },
            "send_udt_data": {
                "behavior": "calls sendto((int)user, buf, len, 0, addr, addrlen) and reports EMSGSIZE-class errors through handle_socket_emsgsize_error()",
                "implication": "the outbound UDP source endpoint comes from the UDP fd represented by KCP user data",
            },
            "get_thread_kcp": {
                "behavior": "for cmd 1/2/7/9 matches incoming packets by source port == kcp->dest_port and syn_id == kcp->syn_id",
                "implication": "responses are accepted only when they bind to the existing KCP session context",
            },
        },
        "pythonRunnerDelta": {
            "currentProbe": "run_kcp_auth_sync_probe opens one UDP socket, does not explicitly bind before send, sends AUTH_HEAD directly, and records getsockname() after first send.",
            "notModeledYet": [
                "local 127.0.0.1 TCP listen fd lifecycle from ice_create_fd(0, 0)",
                "udp_get_local_port(g_sock_listen_fd) / udp_get_tcp_link_info() readiness gate",
                "listen_udp_data_thread / ice_deal_sock event loop",
                "local proxy protocol header parsing that sets data_buf[224] to 1/2",
                "deal_create_proxy_fd_session() proxy_sock link_type assignment",
                "proxy_sock->data_buf[224] propagation into udp_sock->data_buf[224]",
                "create_fd_session(TN_UDP_CLD_SOCK) and socket pair state",
                "thread kcp_list attachment before deal_udt_using_cag()",
            ],
            "nextImplementationChoices": [
                "do not repeat explicit local-bind/source-port probes without new official trace evidence",
                "add a probe mode that starts a receive loop before AUTH_HEAD and records pre-send local endpoint",
                "prefer a fresh official UDP trace focused on packets before AUTH_HEAD and CAG-side session binding",
            ],
        },
    }


def kcp_auth_preflight_summary():
    return {
        "requiredBeforeClientSynWhenAuthEnabled": True,
        "implementedCodec": True,
        "liveProbeSendsAuth": False,
        "clientAuthHeadConv": KCP_AUTH_HEAD_CONV,
        "clientAuthDataConv": KCP_AUTH_DATA_CONV,
        "ackCommands": {
            "IKCP_CONV_AUTH_HEAD_ACK": 7,
            "IKCP_CONV_AUTH_ACK": 9,
        },
        "idaEvidence": [
            "ikcp_set_auth_data sends auth head/data KCP envelopes before link sync",
            "deal_kcp_auth_cmd handles AUTH_HEAD_ACK/AUTH_ACK",
            "ikcp_set_auth_data_res calls ikcp_send_link_sync only after deal_auth_res returns 200",
        ],
        "nextStep": "Recover fresh auth head/data bytes or prove auth is disabled before expecting SYNACK from a live target.",
    }


def kcp_synack_negotiation_summary(segment):
    if not segment:
        return None
    cmd_flags = set(segment.get("cmdFlags") or [])
    wnd_flags = set(segment.get("wndFlags") or [])
    fec = "server-fec" in cmd_flags
    stream = "stream" in wnd_flags
    head_len = KCP_SEG_HEADER_SIZE + (2 if fec else 0) + (1 if stream else 0)
    return {
        "newConvFromUna": segment["una"],
        "packCheckNegotiated": "server-pack-check" in cmd_flags,
        "fecNegotiated": fec,
        "useQuicNegotiated": "quic" in wnd_flags,
        "streamNegotiated": stream,
        "headLen": head_len,
        "nativeBridgePrerequisite": "Use these negotiated fields before ZIME_CreateDataChannel.",
    }


def _kcp_segment_summary(segment):
    if not segment:
        return None
    return {
        "conv": segment["conv"],
        "cmd": segment["cmd"],
        "wnd": segment["wnd"],
        "ts": segment["ts"],
        "sn": segment["sn"],
        "una": segment["una"],
        "len": segment["len"],
        "headerSize": segment["headerSize"],
        "payloadLengthMatches": segment.get("payloadLengthMatches"),
        "cmdFlags": segment.get("cmdFlags") or [],
        "wndFlags": segment.get("wndFlags") or [],
        "clientSynConv": bool(segment.get("clientSynConv")),
        "syncAckConv": bool(segment.get("syncAckConv")),
        "authHeadConv": bool(segment.get("authHeadConv")),
        "authDataConv": bool(segment.get("authDataConv")),
        "authConv": bool(segment.get("authConv")),
        "authHeadAckCmd": bool(segment.get("authHeadAckCmd")),
        "authAckCmd": bool(segment.get("authAckCmd")),
        "authAckCmdAny": bool(segment.get("authAckCmdAny")),
    }


def _load_jsonl(path):
    records = []
    invalid = []
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as err:
            invalid.append({"line": line_number, "error": str(err), "text": line[:200]})
    return records, invalid


def _decode_record_hex(record):
    value = record.get("hex") or ""
    if not isinstance(value, str) or not value:
        return b""
    try:
        return bytes.fromhex(value)
    except ValueError:
        return b""


def _record_target(record):
    peer = record.get("peer")
    if peer and peer != "-":
        return peer
    remote = record.get("remote")
    if remote and remote != "-":
        return remote
    return peer or remote or "-"


def _fd_key(record):
    fd = record.get("fd")
    if fd is None:
        return None
    return (record.get("pid"), fd)


def _record_target_with_source(record, fd_lifecycle):
    target = _record_target(record)
    if _is_external_target(target):
        return target, "record"
    if target and target != "-":
        return target, "record"
    info = fd_lifecycle.get(_fd_key(record)) if fd_lifecycle else None
    if info:
        inferred = info.get("lastExternalTarget")
        if _is_external_target(inferred):
            return inferred, info.get("lastExternalTargetSource") or "fdLifecycle"
    return target, "record"


def _is_external_target(target):
    text = str(target or "")
    return bool(
        text
        and text != "-"
        and not text.startswith("127.")
        and not text.startswith("localhost")
        and not text.startswith("::1")
        and not text.startswith("family:")
        and not text.startswith("unix:")
        and not text.startswith("/")
    )


def _is_family_ip(host):
    try:
        ip = ipaddress.ip_address(str(host or ""))
    except ValueError:
        return False
    benchmark = ipaddress.ip_network("198.18.0.0/15")
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip in benchmark)


def _is_family_target(target):
    return str(target or "").startswith("family:")


def _is_protocol_kind(kind):
    text = str(kind or "")
    return text.startswith("spice-") or text.startswith("chuanyun-frame")


def _is_tls_kind(kind):
    return str(kind or "").startswith("tls-")


def _socket_lifecycle_is_datagram(info):
    if not info:
        return False
    try:
        return (int(info.get("type")) & 0x0F) == 2
    except (TypeError, ValueError):
        return False


def _record_can_carry_rap(record, target=None, fd_info=None):
    function = str(record.get("function") or "")
    peer = record.get("peer")
    remote = record.get("remote")
    address_functions = {"sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg"}
    if function in address_functions and _is_external_target(target):
        return True
    if function in {"send", "recv"} and _is_external_target(target) and _socket_lifecycle_is_datagram(fd_info):
        return True
    if remote and remote != "-":
        return function in address_functions
    return function in {"sendto", "recvfrom", "recvmsg", "recvmmsg"} and (not peer or peer == "-")


def _update_socket_lifecycle(fd_lifecycle, record):
    key = _fd_key(record)
    if key is None:
        return None
    event = record.get("event")
    info = fd_lifecycle.setdefault(key, {
        "pid": key[0],
        "fd": key[1],
        "events": Counter(),
    })
    if event:
        info["events"][str(event)] += 1
    if event == "transport_socket":
        for field in ("domain", "type", "protocol", "ret", "errno"):
            if field in record:
                info[field] = record.get(field)
    elif event == "transport_bind":
        for field in ("requestedLocal", "local", "ret", "errno"):
            if field in record:
                info[field] = record.get(field)
    elif event == "transport_connect":
        for field in ("remote", "local", "peerAfter", "ret", "errno"):
            if field in record:
                info[field] = record.get(field)
        for field in ("peerAfter", "remote"):
            value = record.get(field)
            if _is_external_target(value):
                info["lastExternalTarget"] = value
                info["lastExternalTargetSource"] = f"fdLifecycle:{field}"
                break
    elif event == "transport_buffer":
        for field in ("peer", "remote"):
            value = record.get(field)
            if _is_external_target(value):
                info["lastExternalTarget"] = value
                info["lastExternalTargetSource"] = "record"
                break
        local = record.get("local")
        if local and local != "-":
            info["local"] = local
    return info


def looks_like_ztec_ack(data):
    packet = _bytes(data)
    return len(packet) >= ZTEC_KEEPALIVE_ACK_SIZE and packet[:4] != ZTEC_MAGIC and _u16le(packet, 4) == 0x04A0


def looks_like_rap_frame(data):
    packet = _bytes(data)
    return len(packet) >= RAP_MIN_HEADER_SIZE and packet[4] in RAP_FRAME_TYPES and packet[:4] not in {ZTEC_MAGIC, b"REDQ"}


def classify_tls_record(data):
    packet = _bytes(data)
    if len(packet) < 5:
        return None
    content_type = packet[0]
    if content_type not in TLS_CONTENT_TYPES:
        return None
    if packet[1] != 0x03 or packet[2] > 0x04:
        return None
    length = int.from_bytes(packet[3:5], "big")
    if length <= max(0, len(packet) - 5):
        return TLS_CONTENT_TYPES[content_type]
    return f"{TLS_CONTENT_TYPES[content_type]}-fragment"


def classify_quic_candidate(data):
    packet = _bytes(data)
    if len(packet) >= 6 and packet[0] & 0x80:
        return "quic-long-header-candidate"
    if len(packet) >= 10 and packet[4] & 0x80:
        return "zime-udp-reserved4:quic-long-header-candidate"
    return None


def classify_payload(data):
    """Classify a payload using only local codec rules and observed SPICE tags."""
    packet = _bytes(data)
    if not packet:
        return "empty"
    if len(packet) >= 4 and packet[:4] == ZTEC_MAGIC:
        return "ztec-keepalive-request"
    if looks_like_ztec_ack(packet):
        return "ztec-keepalive-ack"
    if len(packet) >= 4 and packet[:4] == b"REDQ":
        return "spice-link"
    if looks_like_kcp_segment(packet):
        try:
            segment = decode_kcp_segment(packet)
        except ValueError:
            segment = {}
        if segment.get("clientSynConv"):
            prefix = "kcp-client-syn"
        elif segment.get("syncAckConv"):
            prefix = "kcp-sync-segment"
        elif segment.get("authHeadAckCmd"):
            prefix = "kcp-auth-head-ack"
        elif segment.get("authAckCmd"):
            prefix = "kcp-auth-ack"
        elif segment.get("authHeadConv"):
            prefix = "kcp-auth-head"
        elif segment.get("authDataConv"):
            prefix = "kcp-auth-data"
        else:
            prefix = "kcp-segment"
        flags = list(segment.get("wndFlags") or []) + list(segment.get("cmdFlags") or [])
        if flags:
            return f"{prefix}:{','.join(flags)}"
        return prefix
    tls_kind = classify_tls_record(packet)
    if tls_kind:
        return tls_kind
    quic_kind = classify_quic_candidate(packet)
    if quic_kind:
        return quic_kind
    if len(packet) >= LOCAL_SPICE_CLIENT_HEADER_SIZE and packet[0] == 0x0A:
        try:
            local = decode_local_spice_client_frame(packet)
            inner = classify_payload(local["payload"])
            return f"local-spice-client:{inner}"
        except ValueError:
            pass
    if len(packet) >= 6:
        message_type = _u16le(packet, 0)
        size = _u32le(packet, 2)
        if message_type in SPICE_KIND_NAMES and message_type >= 0x0065 and size <= len(packet) - 6:
            return SPICE_KIND_NAMES[message_type]
    if len(packet) >= 18:
        message_type = _u16le(packet, 8)
        size = _u32le(packet, 10)
        if size <= len(packet) - 18:
            return SPICE_KIND_NAMES.get(message_type, f"spice-data-unknown:0x{message_type:04x}")
    if len(packet) >= 6:
        message_type = _u16le(packet, 0)
        size = _u32le(packet, 2)
        if size <= len(packet) - 6:
            return SPICE_KIND_NAMES.get(message_type, f"spice-mini-unknown:0x{message_type:04x}")
    return "unknown"


def _apply_progress(kind, progress):
    if "spice-link" in kind:
        progress["spiceLinkSeen"] = True
    if "spice-display-init" in kind:
        progress["displayInitSeen"] = True
    if "spice-set-ack" in kind:
        progress["setAckSeen"] = True
    if "spice-ack-sync" in kind:
        progress["ackSyncSeen"] = True
    if "spice-ping" in kind:
        progress["pingSeen"] = True
    if "spice-pong" in kind:
        progress["pongSeen"] = True
    if "spice-surface-create" in kind:
        progress["surfaceCreateSeen"] = True
    if "spice-draw-copy" in kind:
        progress["drawCopySeen"] = True
    if "spice-mark" in kind:
        progress["markSeen"] = True


def _progress_template():
    return {
        "spiceLinkSeen": False,
        "displayInitSeen": False,
        "setAckSeen": False,
        "ackSyncSeen": False,
        "pingSeen": False,
        "pongSeen": False,
        "surfaceCreateSeen": False,
        "drawCopySeen": False,
        "markSeen": False,
    }


def _display_path_observed(progress):
    display_activity = (
        (progress["surfaceCreateSeen"] and progress["markSeen"])
        or (progress["surfaceCreateSeen"] and progress["drawCopySeen"])
        or (progress["drawCopySeen"] and progress["markSeen"])
    )
    return bool(progress["displayInitSeen"] and display_activity)


def _ack_pong_observed(progress):
    return bool((progress["setAckSeen"] or progress["ackSyncSeen"]) and (progress["pingSeen"] or progress["pongSeen"]))


def _sample_record(index, record, kind, extra=None):
    redacted_hex = str(record.get("hex") or "")[:160]
    if "kcp-auth" in str(kind):
        redacted_hex = "<redacted:kcp-auth>"
    item = {
        "index": index,
        "event": record.get("event"),
        "function": record.get("function"),
        "direction": record.get("direction"),
        "fd": record.get("fd"),
        "peer": record.get("peer"),
        "remote": record.get("remote"),
        "target": _record_target(record),
        "len": record.get("len"),
        "ret": record.get("ret"),
        "payloadKind": kind,
        "hexPrefix": redacted_hex,
    }
    if extra:
        item.update(extra)
    return item


def _auth_preflight_record(index, record, segment, *, target=None, target_source=None, frame_index=None):
    return {
        "index": index,
        "event": record.get("event"),
        "function": record.get("function"),
        "direction": record.get("direction"),
        "fd": record.get("fd"),
        "target": target or _record_target(record),
        "targetSource": target_source,
        "frameIndex": frame_index,
        "kind": "auth-head" if segment.get("authHeadConv") else "auth-data",
        "conv": segment.get("conv"),
        "sn": segment.get("sn"),
        "una": segment.get("una"),
        "declaredLen": segment.get("len"),
        "payloadLengthMatches": segment.get("payloadLengthMatches"),
        "payloadRedacted": True,
    }


def _record_kcp_auth_segment(counter, samples, index, record, payload, *, target=None, target_source=None, frame_index=None, sample_limit=40):
    try:
        if not looks_like_kcp_segment(payload):
            return
        segment = decode_kcp_segment(payload)
    except ValueError:
        return
    if not segment.get("authConv"):
        return
    key = "auth-head" if segment.get("authHeadConv") else "auth-data"
    counter[key] += 1
    direction = str(record.get("direction") or "unknown")
    counter[f"{key}:{direction}"] += 1
    if len(samples) < sample_limit:
        samples.append(
            _auth_preflight_record(
                index,
                record,
                segment,
                target=target,
                target_source=target_source,
                frame_index=frame_index,
            )
        )


def analyze_trace(path, report_file=None, sample_limit=40):
    """Summarize official-client RAP/ZIME/SPICE trace into runner input.

    The output is intentionally conservative: it identifies observed tunnel IDs,
    UDP targets, local SPICE prefixes, and display-path evidence without claiming
    the full ZIME/RAP state machine is known.
    """
    records, invalid = _load_jsonl(path)
    sample_limit = max(1, int(sample_limit))
    kind_counts = Counter()
    tunnel_counts = Counter()
    target_counts = Counter()
    frame_type_counts = Counter()
    rap_data_template_counts = Counter()
    zime_channel_prefix_counts = Counter()
    zime_envelope_counts = Counter()
    local_prefix_counts = Counter()
    ztec_counts = Counter()
    ztec_target_counts = Counter()
    family_kind_counts = Counter()
    family_flow_counts = {}
    family_flow_progress = {}
    external_tls_counts = Counter()
    kcp_auth_counts = Counter()
    kcp_auth_samples = []
    fd_lifecycle = {}
    target_source_counts = {}
    rap_samples = []
    rap_data_send_templates = []
    local_samples = []
    ztec_samples = []
    family_samples = []
    external_tls_samples = []
    socket_lifecycle_samples = []
    progress = _progress_template()

    for index, record in enumerate(records):
        event = record.get("event")
        if event in {"transport_socket", "transport_bind", "transport_connect", "transport_buffer"}:
            info = _update_socket_lifecycle(fd_lifecycle, record)
            if event != "transport_buffer" and info and len(socket_lifecycle_samples) < sample_limit:
                socket_lifecycle_samples.append({
                    "index": index,
                    "event": event,
                    "function": record.get("function"),
                    "pid": record.get("pid"),
                    "fd": record.get("fd"),
                    "domain": record.get("domain"),
                    "type": record.get("type"),
                    "protocol": record.get("protocol"),
                    "requestedLocal": record.get("requestedLocal"),
                    "local": record.get("local"),
                    "remote": record.get("remote"),
                    "peerAfter": record.get("peerAfter"),
                    "ret": record.get("ret"),
                    "errno": record.get("errno"),
                })
        if record.get("event") not in {"transport_buffer", "zime_buffer", "ssl_buffer"}:
            continue
        raw = _decode_record_hex(record)
        if not raw:
            continue
        computed_kind = classify_payload(raw)
        recorded_kind = str(record.get("payloadKind") or "")
        kind = computed_kind if computed_kind != "unknown" else (recorded_kind or computed_kind)
        kind_counts[kind] += 1
        _apply_progress(kind, progress)
        target, target_source = _record_target_with_source(record, fd_lifecycle)
        _record_kcp_auth_segment(
            kcp_auth_counts,
            kcp_auth_samples,
            index,
            record,
            raw,
            target=target,
            target_source=target_source,
            sample_limit=sample_limit,
        )

        if _is_family_target(target) and _is_protocol_kind(kind):
            family_kind_counts[kind] += 1
            flow_key = (record.get("fd"), target)
            family_flow_counts.setdefault(flow_key, Counter())[kind] += 1
            family_flow_progress.setdefault(flow_key, _progress_template())
            _apply_progress(kind, family_flow_progress[flow_key])
            if len(family_samples) < sample_limit:
                family_samples.append(_sample_record(index, record, kind))

        if _is_external_target(target) and _is_tls_kind(kind):
            external_tls_counts[kind] += 1
            if len(external_tls_samples) < sample_limit:
                external_tls_samples.append(_sample_record(index, record, kind))

        if raw[:4] == ZTEC_MAGIC or looks_like_ztec_ack(raw):
            decoded = decode_ztec_keepalive(raw)
            ztec_counts[decoded["kind"]] += 1
            if decoded["kind"] == "ztec_keepalive_request":
                ztec_target_counts[f"{decoded['host']}:{decoded['port']}"] += 1
            if len(ztec_samples) < sample_limit:
                ztec_samples.append(_sample_record(index, record, decoded["kind"], {
                    "decoded": {k: v for k, v in decoded.items() if k != "rest"},
                }))

        fd_info = fd_lifecycle.get(_fd_key(record))
        if _record_can_carry_rap(record, target, fd_info) and looks_like_rap_frame(raw):
            try:
                decoded_frames = decode_rap_frames(raw)
            except ValueError:
                decoded_frames = [decode_rap_frame(raw)]
            for frame_index, decoded in enumerate(decoded_frames):
                payload_kind = classify_payload(decoded.get("payload") or b"")
                _record_kcp_auth_segment(
                    kcp_auth_counts,
                    kcp_auth_samples,
                    index,
                    record,
                    decoded.get("payload") or b"",
                    target=target,
                    target_source=target_source,
                    frame_index=frame_index,
                    sample_limit=sample_limit,
                )
                envelope = try_decode_zime_payload_envelope(decoded)
                if envelope:
                    zime_envelope_counts["observed"] += 1
                    if envelope.get("channelPrefix") is not None:
                        zime_channel_prefix_counts[str(envelope["channelPrefix"])] += 1
                tunnel_counts[decoded["tunnelIdHex"]] += 1
                target_counts[target] += 1
                if _is_external_target(target):
                    target_source_counts.setdefault(target, Counter())[target_source] += 1
                frame_type_counts[f"0x{decoded['frameType']:02x}"] += 1
                if decoded["frameType"] in RAP_DATA_FRAME_TYPES:
                    rap_data_template_counts[(
                        decoded["flags"],
                        decoded["field06Le"],
                        decoded["word08"],
                        decoded["word12"],
                        (decoded.get("header16Prefix") or b"").hex(),
                        (decoded.get("postLengthBytes") or b"").hex(),
                    )] += 1
                    if record.get("direction") == "send" and len(rap_data_send_templates) < sample_limit:
                        rap_data_send_templates.append({
                            "sampleIndex": index,
                            "frameIndex": frame_index,
                            "frameType": decoded["frameType"],
                            "flags": decoded["flags"],
                            "field06": decoded["field06Le"],
                            "word08": decoded["word08"],
                            "word12": decoded["word12"],
                            "header16PrefixHex": (decoded.get("header16Prefix") or b"").hex(),
                            "postLengthHex": (decoded.get("postLengthBytes") or b"").hex(),
                            "payloadKind": payload_kind,
                            "payloadLength": decoded["payloadLength"],
                            "zimePayloadEnvelopeObserved": bool(envelope),
                            "traceOnly": True,
                        })
                _apply_progress(payload_kind, progress)
                if len(rap_samples) < sample_limit:
                    rap_samples.append(_sample_record(index, record, payload_kind, {
                        "target": target,
                        "targetSource": target_source,
                        "rap": {
                            "frameIndex": frame_index,
                            "datagramFrameCount": len(decoded_frames),
                            "tunnelIdHex": decoded["tunnelIdHex"],
                            "frameType": decoded["frameType"],
                            "flags": decoded["flags"],
                            "field06Be": decoded["field06Be"],
                            "field06Le": decoded["field06Le"],
                            "word08": decoded["word08"],
                            "word08Be": decoded["word08Be"],
                            "word12": decoded["word12"],
                            "word12Be": decoded["word12Be"],
                            "header16Prefix": (decoded.get("header16Prefix") or b"").hex(),
                            "postLengthBytes": (decoded.get("postLengthBytes") or b"").hex(),
                            "word16Be": decoded["word16Be"],
                            "payloadLength": decoded["payloadLength"],
                            "payloadLengthSource": decoded["payloadLengthSource"],
                            "payloadLengthMatches": decoded["payloadLengthMatches"],
                            "payloadKind": payload_kind,
                            "zimePayloadEnvelope": envelope,
                        }
                    }))

        if raw[0] == 0x0A and len(raw) >= LOCAL_SPICE_CLIENT_HEADER_SIZE:
            try:
                decoded = decode_local_spice_client_frame(raw)
            except ValueError:
                decoded = None
            if decoded:
                inner_kind = classify_payload(decoded["payload"])
                if inner_kind == "unknown" and recorded_kind:
                    inner_kind = recorded_kind
                local_prefix_counts[str(decoded["channelPrefix"])] += 1
                _apply_progress(inner_kind, progress)
                if len(local_samples) < sample_limit:
                    local_samples.append(_sample_record(index, record, inner_kind, {
                        "localSpice": {
                            "channelPrefix": decoded["channelPrefix"],
                            "payloadLength": decoded["payloadLength"],
                            "payloadKind": inner_kind,
                            "restLength": len(decoded["rest"]),
                        }
                    }))

    primary_tunnel = tunnel_counts.most_common(1)[0][0] if tunnel_counts else None
    candidate_targets = [target for target, _count in target_counts.most_common() if _is_external_target(target)]
    rap_data_template = None
    if rap_data_template_counts:
        (flags, field06, word08, word12, header16_prefix, post_length), count = rap_data_template_counts.most_common(1)[0]
        rap_data_template = {
            "frameType": 0x81,
            "flags": flags,
            "field06": field06,
            "word08": word08,
            "word12": word12,
            "header16PrefixHex": header16_prefix,
            "postLengthHex": post_length,
            "sampleCount": count,
            "traceOnly": True,
        }
    socket_lifecycle = []
    for (pid, fd), info in sorted(fd_lifecycle.items(), key=lambda item: (str(item[0][0]), str(item[0][1]))):
        events = info.get("events") or Counter()
        socket_lifecycle.append({
            "pid": pid,
            "fd": fd,
            "events": dict(events.most_common()),
            "domain": info.get("domain"),
            "type": info.get("type"),
            "protocol": info.get("protocol"),
            "requestedLocal": info.get("requestedLocal"),
            "local": info.get("local"),
            "remote": info.get("remote"),
            "peerAfter": info.get("peerAfter"),
            "lastExternalTarget": info.get("lastExternalTarget"),
            "lastExternalTargetSource": info.get("lastExternalTargetSource"),
        })
    family_flows = []
    for (fd, peer), counter in sorted(family_flow_counts.items(), key=lambda item: -sum(item[1].values()))[:20]:
        flow_progress = family_flow_progress[(fd, peer)]
        family_flows.append({
            "fd": fd,
            "peer": peer,
            "records": sum(counter.values()),
            "payloadKinds": dict(counter.most_common()),
            "progress": flow_progress,
            "displayPathObserved": _display_path_observed(flow_progress),
            "ackPongMaintenanceSeen": _ack_pong_observed(flow_progress),
        })
    rap_observed = bool(tunnel_counts or ztec_counts)
    family_observed = bool(family_kind_counts)
    external_tls_observed = bool(external_tls_counts)
    transport_decision = (
        "rap-zime-udp" if rap_observed else
        "family-native-spice-trace-only" if family_observed else
        "external-tls-trace-only" if external_tls_observed else
        "unknown"
    )
    report = {
        "ok": True,
        "inputFile": str(path),
        "records": len(records),
        "invalidLines": invalid,
        "payloadKindCounts": dict(kind_counts.most_common()),
        "ztec": {
            "counts": dict(ztec_counts.most_common()),
            "targets": dict(ztec_target_counts.most_common()),
            "samples": ztec_samples,
        },
        "rap": {
            "tunnelIds": dict(tunnel_counts.most_common()),
            "primaryTunnelId": primary_tunnel,
            "frameTypes": dict(frame_type_counts.most_common()),
            "targets": dict(target_counts.most_common()),
            "targetSources": {target: dict(counter.most_common()) for target, counter in target_source_counts.items()},
            "samples": rap_samples,
            "payloadLengthRule": "data-like RAP frames observed here use offset19_le16 with payload at offset24",
            "zimePayloadEnvelope": {
                "counts": dict(zime_envelope_counts.most_common()),
                "channelPrefixes": dict(zime_channel_prefix_counts.most_common()),
                "note": "Envelope facts only. The protected payload is not plaintext SPICE and must not be replayed.",
            },
        },
        "socketLifecycle": {
            "fds": socket_lifecycle,
            "samples": socket_lifecycle_samples,
        },
        "localSpice": {
            "channelPrefixes": dict(local_prefix_counts.most_common()),
            "samples": local_samples,
        },
        "familyNative": {
            "payloadKindCounts": dict(family_kind_counts.most_common()),
            "flows": family_flows,
            "samples": family_samples,
        },
        "externalTls": {
            "payloadKindCounts": dict(external_tls_counts.most_common()),
            "samples": external_tls_samples,
        },
        "kcpAuthPreflight": {
            "observed": bool(kcp_auth_counts),
            "counts": dict(kcp_auth_counts.most_common()),
            "samples": kcp_auth_samples,
            "payloadPolicy": "auth payload bytes are intentionally redacted; use only structure and freshness evidence.",
            "nextStep": (
                "Recover fresh auth payload source or prove auth disabled before expecting SYNACK."
                if kcp_auth_counts
                else "No KCP auth envelope was observed in this trace."
            ),
        },
        "progress": progress,
        "protocolEvidence": {
            "displayPathObserved": _display_path_observed(progress),
            "ackPongMaintenanceSeen": _ack_pong_observed(progress),
            "traceOnly": True,
        },
        "runnerInput": {
            "transport": transport_decision,
            "observedTransports": {
                "rapZimeUdpObserved": rap_observed,
                "familyNativeSpiceObserved": family_observed,
                "externalTlsObserved": external_tls_observed,
            },
            "primaryTunnelId": primary_tunnel,
            "candidateUdpTargets": candidate_targets,
            "candidateUdpTargetSources": {
                target: dict(target_source_counts.get(target, Counter()).most_common())
                for target in candidate_targets
            },
            "candidateZtecTargets": list(dict(ztec_target_counts.most_common()).keys()),
            "rapDataFrameTemplate": rap_data_template,
            "rapDataFrameSendTemplates": rap_data_send_templates,
            "needsTraceWithSocketRemote": bool(rap_observed and not candidate_targets),
            "localSpiceChannelPrefixes": list(dict(local_prefix_counts.most_common()).keys()),
            "zimePayloadChannelPrefixes": list(dict(zime_channel_prefix_counts.most_common()).keys()),
            "zimePayloadEnvelopeObserved": bool(zime_envelope_counts),
            "kcpAuthPreflightObserved": bool(kcp_auth_counts),
            "payloadLengthRule": "offset19_le16_payload_offset24",
            "implementationUse": (
                "Use this summary to parameterize the independent protocol runner only when the required "
                "transport fields are present. Family/native or TLS-only observations are trace evidence, "
                "not RAP/ZIME UDP runner input, not keepalive proof, and captured bytes must not be replayed."
            ),
        },
    }
    core.write_private_json_report(report, report_file)
    return report


def _run_tshark_fields(path, protocol):
    tshark = shutil.which("tshark")
    if not tshark:
        raise ValueError("tshark is required for pcap analysis")
    if protocol == "udp":
        fields = [
            "frame.time_epoch",
            "ip.src",
            "udp.srcport",
            "ip.dst",
            "udp.dstport",
            "frame.len",
            "udp.length",
        ]
        display_filter = "udp"
    elif protocol == "tcp":
        fields = [
            "frame.time_epoch",
            "ip.src",
            "tcp.srcport",
            "ip.dst",
            "tcp.dstport",
            "frame.len",
            "tcp.len",
        ]
        display_filter = "tcp"
    else:
        raise ValueError(f"unsupported pcap protocol: {protocol}")
    cmd = [
        tshark,
        "-r",
        str(path),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
    ]
    for field in fields:
        cmd.extend(["-e", field])
    result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout.splitlines()


def _parse_pcap_field_rows(lines, protocol):
    parsed = []
    for line in lines or []:
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 7:
            continue
        try:
            src_port = int(parts[2])
            dst_port = int(parts[4])
        except (TypeError, ValueError):
            continue
        try:
            frame_len = int(parts[5]) if parts[5] else 0
        except (TypeError, ValueError):
            frame_len = 0
        try:
            transport_len = int(parts[6]) if parts[6] else 0
        except (TypeError, ValueError):
            transport_len = 0
        try:
            ts = float(parts[0]) if parts[0] else None
        except (TypeError, ValueError):
            ts = None
        src = parts[1]
        dst = parts[3]
        if not src or not dst:
            continue
        parsed.append({
            "time": ts,
            "src": src,
            "srcPort": src_port,
            "dst": dst,
            "dstPort": dst_port,
            "frameLen": frame_len,
            "transportLen": transport_len,
            "protocol": protocol,
        })
    return parsed


def _endpoint(ip_text, port):
    return f"{ip_text}:{int(port)}"


def _conversation_key(row):
    left = _endpoint(row["src"], row["srcPort"])
    right = _endpoint(row["dst"], row["dstPort"])
    return tuple(sorted([left, right]))


def _external_endpoint_from_key(key):
    for endpoint in key:
        host = endpoint.rsplit(":", 1)[0]
        if _is_external_target(endpoint) or not _is_family_ip(host):
            return endpoint
    return key[1]


def _summarize_packet_rows(rows, *, protocol, focus_port=None, sample_limit=20):
    conversations = {}
    first_time = None
    last_time = None
    for row in rows:
        if row.get("time") is not None:
            first_time = row["time"] if first_time is None else min(first_time, row["time"])
            last_time = row["time"] if last_time is None else max(last_time, row["time"])
        key = _conversation_key(row)
        item = conversations.setdefault(key, {
            "endpoints": list(key),
            "protocol": protocol,
            "frames": 0,
            "bytes": 0,
            "transportBytes": 0,
            "startOffsetSeconds": None,
            "durationSeconds": 0.0,
            "directions": {},
            "frameLenTop": Counter(),
            "transportLenTop": Counter(),
            "focusPortMatched": False,
        })
        item["frames"] += 1
        item["bytes"] += row["frameLen"]
        item["transportBytes"] += row["transportLen"]
        item["frameLenTop"][row["frameLen"]] += 1
        item["transportLenTop"][row["transportLen"]] += 1
        direction = f"{_endpoint(row['src'], row['srcPort'])}->{_endpoint(row['dst'], row['dstPort'])}"
        direction_item = item["directions"].setdefault(direction, {"frames": 0, "bytes": 0, "transportBytes": 0})
        direction_item["frames"] += 1
        direction_item["bytes"] += row["frameLen"]
        direction_item["transportBytes"] += row["transportLen"]
        if focus_port and (row["srcPort"] == focus_port or row["dstPort"] == focus_port):
            item["focusPortMatched"] = True
        if row.get("time") is not None and first_time is not None:
            offset = max(0.0, row["time"] - first_time)
            if item["startOffsetSeconds"] is None:
                item["startOffsetSeconds"] = round(offset, 6)
            item["durationSeconds"] = round(max(item["durationSeconds"], offset - item["startOffsetSeconds"]), 6)

    summaries = []
    for item in conversations.values():
        item["directions"] = dict(sorted(
            item["directions"].items(),
            key=lambda pair: -pair[1]["frames"],
        )[:2])
        item["topFrameLengths"] = [
            {"length": length, "frames": count}
            for length, count in item.pop("frameLenTop").most_common(8)
        ]
        item["topTransportLengths"] = [
            {"length": length, "frames": count}
            for length, count in item.pop("transportLenTop").most_common(8)
        ]
        item["externalEndpointCandidate"] = _external_endpoint_from_key(tuple(item["endpoints"]))
        summaries.append(item)
    summaries.sort(key=lambda item: (not item.get("focusPortMatched"), -item["frames"], -item["bytes"]))
    return {
        "packetCount": len(rows),
        "firstTime": first_time,
        "lastTime": last_time,
        "durationSeconds": round(last_time - first_time, 6) if first_time is not None and last_time is not None else 0.0,
        "conversations": summaries[:sample_limit],
    }


def _extract_ss_peers(ss_log_text):
    peers = Counter()
    vdi_loopback_ports = Counter()
    for line in (ss_log_text or "").splitlines():
        if "users:((\"uSmartView_VDI_\"" in line:
            parts = line.split()
            if len(parts) >= 6:
                peer = parts[5]
                if peer.startswith("127.0.0.1:"):
                    vdi_loopback_ports[peer] += 1
                else:
                    peers[peer] += 1
        elif "users:((\"cmcc-jtydn\"" in line or "users:((\"bootCypc\"" in line:
            parts = line.split()
            if len(parts) >= 6:
                peer = parts[5]
                if peer and not peer.startswith("127.0.0.1:"):
                    peers[peer] += 1
    return {
        "externalPeersTop": [{"peer": peer, "samples": count} for peer, count in peers.most_common(20)],
        "vdiLoopbackPeersTop": [{"peer": peer, "samples": count} for peer, count in vdi_loopback_ports.most_common(20)],
    }


def analyze_external_pcap(path, *, ss_log=None, report_file=None, sample_limit=20, focus_udp_port=8899):
    """Summarize no-LD_PRELOAD external capture without reading packet payloads."""
    pcap_path = Path(os.path.expanduser(str(path)))
    if not pcap_path.exists():
        raise ValueError(f"pcap file not found: {path}")
    sample_limit = max(1, int(sample_limit))
    udp_rows = _parse_pcap_field_rows(_run_tshark_fields(pcap_path, "udp"), "udp")
    tcp_rows = _parse_pcap_field_rows(_run_tshark_fields(pcap_path, "tcp"), "tcp")
    udp_summary = _summarize_packet_rows(udp_rows, protocol="udp", focus_port=focus_udp_port, sample_limit=sample_limit)
    tcp_summary = _summarize_packet_rows(tcp_rows, protocol="tcp", sample_limit=sample_limit)
    focus_conversations = [
        item for item in udp_summary["conversations"]
        if item.get("focusPortMatched")
    ]
    candidate_udp_targets = []
    for item in focus_conversations:
        candidate = item.get("externalEndpointCandidate")
        if candidate and candidate not in candidate_udp_targets:
            candidate_udp_targets.append(candidate)
    ss_summary = None
    if ss_log:
        ss_path = Path(os.path.expanduser(str(ss_log)))
        if ss_path.exists():
            ss_summary = _extract_ss_peers(ss_path.read_text(encoding="utf-8", errors="replace"))
    report = {
        "ok": True,
        "inputFile": str(pcap_path),
        "analysis": "external_pcap_metadata_only",
        "payloadPolicy": {
            "payloadExtracted": False,
            "payloadFieldsRequested": False,
            "note": "Only frame times, endpoints, ports, and lengths are collected. UDP/TCP payload bytes are not read or written.",
        },
        "udp": udp_summary,
        "tcp": tcp_summary,
        "ss": ss_summary,
        "runnerInput": {
            "transport": "external-pcap-metadata-only",
            "candidateUdpTargets": candidate_udp_targets,
            "focusUdpPort": focus_udp_port,
            "runnerInputReady": False,
            "missing": [
                "primaryTunnelId",
                "candidateZtecTargets",
                "rapDataFrameTemplate",
                "rapDataFrameSendTemplates",
            ],
            "needsProbeJsonlOrStaticRecovery": True,
            "desktopKeepaliveProven": False,
            "traceOnly": True,
        },
        "nextStep": (
            "Use this metadata to identify stable no-probe RAP/ZIME outer flows. "
            "It cannot produce runner input by itself because RAP tunnel id and send templates require payload-aware probe evidence or static recovery."
        ),
    }
    core.write_private_json_report(report, report_file)
    return report
