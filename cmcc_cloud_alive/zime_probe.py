"""Analyze JSONL emitted by research/zime-probe.c."""

import json
import os
from collections import Counter, defaultdict
from pathlib import Path

from . import core


SPICE_TYPES = {
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
TLS_CONTENT_TYPES = {
    0x14: "tls-change-cipher-spec",
    0x15: "tls-alert",
    0x16: "tls-handshake",
    0x17: "tls-application-data",
}
ZIME_PACKET_OUT_SPEC_SIZE = 0x68
KCP_SEG_HEADER_SIZE = 21
KCP_AUTH_HEAD_CONV = 0x80000006
KCP_AUTH_DATA_CONV = 0x80000008
KCP_AUTH_HEAD_ACK_CMD = 7
KCP_AUTH_ACK_CMD = 9
KCP_CMD_FLAG_MASK = 0xFF


def _u16le(data, offset):
    return data[offset] | (data[offset + 1] << 8)


def _u32le(data, offset):
    return data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)


def _u64le(data, offset):
    value = 0
    for idx in range(8):
        value |= data[offset + idx] << (idx * 8)
    return value


def _ptr_text(value):
    return f"0x{int(value):x}"


def decode_zime_packet_specs(data, count=None, *, base_ptr=None):
    """Decode candidate ZIMEPacketOutSpec entries from probe memory snapshots.

    The layout is inferred from LsquicCallbacksImpl::PacketsOutBatch building
    stack entries before calling TransportBatchImplC::OnSendData_Batch:
    iov pointer, iov count, local/destination sockaddr pointers, a copied
    sockaddr-ish block, and an address-length byte.  This is trace metadata,
    not a replay format.
    """
    data = bytes(data or b"")
    if not data:
        return []
    max_entries = len(data) // ZIME_PACKET_OUT_SPEC_SIZE
    if count is not None:
        try:
            max_entries = min(max_entries, max(0, int(count)))
        except (TypeError, ValueError):
            pass
    specs = []
    for index in range(max_entries):
        off = index * ZIME_PACKET_OUT_SPEC_SIZE
        item = data[off:off + ZIME_PACKET_OUT_SPEC_SIZE]
        if len(item) < ZIME_PACKET_OUT_SPEC_SIZE:
            break
        iov = _u64le(item, 0)
        iov_count = _u64le(item, 8)
        local = _u64le(item, 16)
        dest = _u64le(item, 24)
        embedded_family = _u16le(item, 32)
        addr_len = item[96]
        spec = {
            "index": index,
            "layout": "ZIMEPacketOutSpec_candidate_v1",
            "specSize": ZIME_PACKET_OUT_SPEC_SIZE,
            "iov": _ptr_text(iov),
            "iovCount": iov_count,
            "localAddrPtr": _ptr_text(local),
            "destAddrPtr": _ptr_text(dest),
            "embeddedAddrFamily": embedded_family,
            "addrLen": addr_len,
            "rawHexPrefix": item[:32].hex(),
            "traceOnly": True,
        }
        if base_ptr is not None:
            spec["specPtr"] = f"{base_ptr}+0x{off:x}"
        specs.append(spec)
    return specs


def classify_tls_record(data):
    """Classify a TLS record before trying SPICE fallbacks.

    Transport traces often contain encrypted TLS records whose ciphertext can
    accidentally look like SPICE mini/data headers.  Treating TLS as the outer
    envelope first keeps protocol evidence from being inflated by ciphertext.
    """
    data = bytes(data or b"")
    if len(data) < 5:
        return None
    content_type = data[0]
    if content_type not in TLS_CONTENT_TYPES:
        return None
    major = data[1]
    minor = data[2]
    if major != 0x03 or minor > 0x04:
        return None
    length = (data[3] << 8) | data[4]
    if length <= max(0, len(data) - 5):
        return TLS_CONTENT_TYPES[content_type]
    return f"{TLS_CONTENT_TYPES[content_type]}-fragment"


def classify_quic_candidate(data):
    data = bytes(data or b"")
    if len(data) >= 6 and data[0] & 0x80:
        return "quic-long-header-candidate"
    if len(data) >= 10 and data[4] & 0x80:
        return "zime-udp-reserved4:quic-long-header-candidate"
    return None


def decode_kcp_auth_focus_segment(data):
    """Decode only KCP AUTH fields needed for official trace focus analysis."""
    data = bytes(data or b"")
    if len(data) < KCP_SEG_HEADER_SIZE:
        return None
    conv = _u32le(data, 0)
    cmd = data[4]
    wnd = _u16le(data, 5)
    declared_len = _u16le(data, 19)
    if conv not in {KCP_AUTH_HEAD_CONV, KCP_AUTH_DATA_CONV} and cmd not in {KCP_AUTH_HEAD_ACK_CMD, KCP_AUTH_ACK_CMD}:
        return None
    if cmd & ~KCP_CMD_FLAG_MASK:
        return None
    if wnd & 0xFFC0:
        return None
    if declared_len > len(data) - KCP_SEG_HEADER_SIZE:
        return None
    if cmd == KCP_AUTH_HEAD_ACK_CMD:
        kind = "kcp-auth-head-ack"
    elif cmd == KCP_AUTH_ACK_CMD:
        kind = "kcp-auth-ack"
    elif conv == KCP_AUTH_HEAD_CONV:
        kind = "kcp-auth-head"
    elif conv == KCP_AUTH_DATA_CONV:
        kind = "kcp-auth-data"
    else:
        kind = "kcp-auth"
    return {
        "kind": kind,
        "conv": conv,
        "cmd": cmd,
        "wnd": wnd,
        "ts": _u32le(data, 7),
        "sn": _u32le(data, 11),
        "una": _u32le(data, 15),
        "len": declared_len,
        "payloadStoredInReport": False,
    }


def classify_payload(data, allow_short_mini=False):
    data = bytes(data or b"")
    if not data:
        return "empty"
    if len(data) >= 4 and data[:4] == b"REDQ":
        return "spice-link"
    kcp_auth = decode_kcp_auth_focus_segment(data)
    if kcp_auth:
        return kcp_auth["kind"]
    tls_kind = classify_tls_record(data)
    if tls_kind:
        return tls_kind
    quic_kind = classify_quic_candidate(data)
    if quic_kind:
        return quic_kind
    if len(data) >= 24 and data[0] == 1 and data[1] in {1, 2, 3}:
        inner_len = _u16le(data, 2)
        inner = data[24:24 + inner_len]
        inner_kind = classify_payload(inner, allow_short_mini=allow_short_mini)
        return f"chuanyun-frame:{inner_kind}"
    mini_unknown = None
    if len(data) >= 6:
        msg_type = _u16le(data, 0)
        size = _u32le(data, 2)
        if msg_type in SPICE_TYPES and size <= max(0, len(data) - 6):
            return SPICE_TYPES[msg_type]
        if size <= max(0, len(data) - 6):
            mini_unknown = f"spice-mini-unknown:0x{msg_type:04x}"
        short_size = _u16le(data, 2)
        if allow_short_mini and short_size <= max(0, len(data) - 4):
            mini_unknown = f"spice-mini-unknown:0x{msg_type:04x}"
    if len(data) >= 18:
        msg_type = _u16le(data, 8)
        size = _u32le(data, 10)
        if msg_type in SPICE_TYPES and size <= max(0, len(data) - 18):
            return SPICE_TYPES[msg_type]
        if size <= max(0, len(data) - 18):
            return f"spice-data-unknown:0x{msg_type:04x}"
    if mini_unknown:
        return mini_unknown
    return "unknown"


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


def _decode_hex(record):
    value = record.get("hex") or ""
    if not isinstance(value, str) or not value:
        return b""
    try:
        return bytes.fromhex(value)
    except ValueError:
        return b""


def _select_samples(samples, limit=80):
    selected = []
    seen_indexes = set()

    def add(sample):
        idx = sample.get("index")
        if idx in seen_indexes:
            return
        selected.append(sample)
        seen_indexes.add(idx)

    for sample in samples[:24]:
        add(sample)
    for sample in samples:
        if sample.get("event") == "ssl_buffer" or sample.get("payloadKind") == "spice-mini-unknown:0x082a":
            add(sample)
    for sample in samples:
        if len(selected) >= limit:
            break
        add(sample)
    return selected[:limit]


def _record_identity(record):
    """Return stable transport identity fields used to group official-client traces."""
    return {
        "event": record.get("event"),
        "function": record.get("function"),
        "direction": str(record.get("direction") or "-"),
        "fd": record.get("fd"),
        "peer": record.get("peer"),
        "local": record.get("local"),
        "remote": record.get("remote"),
        "ssl": record.get("ssl"),
        "channelId": record.get("channelId"),
        "streamId": record.get("streamId"),
    }


def _record_kind(record):
    data = _decode_hex(record)
    computed = classify_payload(data, allow_short_mini=record.get("event") == "ssl_buffer")
    recorded = str(record.get("payloadKind") or "")
    return computed if computed != "unknown" else (recorded or computed)


def _redacted_frame_header(record):
    try:
        raw = bytes.fromhex(str(record.get("hex") or ""))
    except ValueError:
        raw = b""
    if len(raw) < 4:
        return None
    return {
        "u16Type": int.from_bytes(raw[0:2], "little"),
        "u16BodyLen": int.from_bytes(raw[2:4], "little"),
        "totalLenMatchesHeader": bool(record.get("len") == int.from_bytes(raw[2:4], "little") + 4),
        "commandByte": raw[0],
        "channelOrIdByte": raw[1],
        "lenAtOffset2": int.from_bytes(raw[2:4], "little"),
        "commandByteSchemaMatches": bool(raw[0] == 26 and raw[1] == 0 and record.get("len") == int.from_bytes(raw[2:4], "little") + 4),
        "sendTunnelLinkMessageDirectShape": bool(raw[0] == 26 and raw[1] != 0 and int.from_bytes(raw[2:4], "little") == 154 and record.get("len") == 158),
        "sendTunnelLinkMessageDirectShapeExcluded": bool(raw[0] == 26 and raw[1] == 0 and int.from_bytes(raw[2:4], "little") == 156 and record.get("len") == 160),
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


def _sequence_item(index, record):
    item = _record_identity(record)
    kind = _record_kind(record)
    item.update({
        "index": index,
        "len": record.get("len"),
        "ret": record.get("ret"),
        "payloadKind": kind,
        "recordedPayloadKind": record.get("payloadKind"),
        "payloadStoredInReport": False,
    })
    frame_header = _redacted_frame_header(record)
    if frame_header:
        item["frameHeader"] = frame_header
    if "kcp-auth" in kind:
        item["hexPrefix"] = "<redacted:kcp-auth>"
    if record.get("authFocus") is not None:
        item["authFocus"] = bool(record.get("authFocus"))
    if record.get("stack"):
        item["stack"] = record.get("stack")
    return item


def auth_head_ack_focus(records, *, pre_window=24):
    """Summarize the narrow AUTH_HEAD_ACK gate from an official probe log."""
    auth_head_indexes = []
    auth_head_ack_indexes = []
    auth_data_indexes = []
    auth_ack_indexes = []
    kind_by_index = {}
    for index, record in enumerate(records, 1):
        if record.get("event") not in {"transport_buffer", "ssl_buffer", "zime_buffer", "zime_callback_buffer"}:
            continue
        kind = _record_kind(record)
        kind_by_index[index] = kind
        if kind == "kcp-auth-head" and str(record.get("direction") or "") == "send":
            auth_head_indexes.append(index)
        elif kind == "kcp-auth-head-ack" and str(record.get("direction") or "") == "receive":
            auth_head_ack_indexes.append(index)
        elif kind == "kcp-auth-data" and str(record.get("direction") or "") == "send":
            auth_data_indexes.append(index)
        elif kind == "kcp-auth-ack" and str(record.get("direction") or "") == "receive":
            auth_ack_indexes.append(index)

    first_head_index = auth_head_indexes[0] if auth_head_indexes else None
    first_head = records[first_head_index - 1] if first_head_index else None
    first_fd = first_head.get("fd") if first_head else None
    first_remote = first_head.get("remote") if first_head else None
    first_peer = first_head.get("peer") if first_head else None
    first_local = first_head.get("local") if first_head else None

    ack_like_responses = []
    if first_head_index and first_fd is not None:
        for data_index in auth_data_indexes:
            if data_index <= first_head_index:
                continue
            data_record = records[data_index - 1]
            if data_record.get("fd") != first_fd:
                continue
            for index in range(first_head_index + 1, data_index):
                record = records[index - 1]
                if record.get("event") not in {"transport_buffer", "ssl_buffer"}:
                    continue
                if str(record.get("direction") or "") != "receive":
                    continue
                if record.get("fd") != first_fd:
                    continue
                if first_remote is not None and record.get("remote") != first_remote:
                    continue
                if first_peer is not None and record.get("peer") != first_peer:
                    continue
                ack_like_responses.append({
                    "index": index,
                    "fd": first_fd,
                    "local": record.get("local"),
                    "remote": record.get("remote"),
                    "peer": record.get("peer"),
                    "len": record.get("len"),
                    "ret": record.get("ret"),
                    "payloadKind": _record_kind(record),
                    "recordedPayloadKind": record.get("payloadKind"),
                    "followedByAuthDataIndex": data_index,
                    "followedByAuthDataLen": data_record.get("len"),
                    "evidence": "same_fd_receive_between_auth_head_and_auth_data",
                    "payloadStoredInReport": False,
                })
            break

    same_fd_auth_head_sends = []
    if first_head_index and first_fd is not None:
        stop_index = (
            ack_like_responses[0]["followedByAuthDataIndex"]
            if ack_like_responses
            else (auth_data_indexes[0] if auth_data_indexes else first_head_index + 1)
        )
        for index in auth_head_indexes:
            if index < first_head_index or index >= stop_index:
                continue
            record = records[index - 1]
            if record.get("fd") != first_fd:
                continue
            if first_remote is not None and record.get("remote") != first_remote:
                continue
            same_fd_auth_head_sends.append({
                "index": index,
                "fd": first_fd,
                "local": record.get("local"),
                "remote": record.get("remote"),
                "len": record.get("len"),
                "ret": record.get("ret"),
                "payloadKind": _record_kind(record),
                "payloadStoredInReport": False,
            })

    pre_same_fd = []
    pre_global = []
    auth_gate_window = []
    if first_head_index:
        start = max(1, first_head_index - max(0, int(pre_window)))
        for index in range(start, first_head_index):
            record = records[index - 1]
            if record.get("event") in {"transport_socket", "transport_bind", "transport_connect", "transport_buffer", "ssl_buffer"}:
                item = _sequence_item(index, record) if record.get("event") in {"transport_buffer", "ssl_buffer"} else {
                    "index": index,
                    "event": record.get("event"),
                    "function": record.get("function"),
                    "fd": record.get("fd"),
                    "requestedLocal": record.get("requestedLocal"),
                    "local": record.get("local"),
                    "remote": record.get("remote"),
                    "peerAfter": record.get("peerAfter"),
                    "ret": record.get("ret"),
                    "errno": record.get("errno"),
                }
                pre_global.append(item)
                if first_fd is not None and record.get("fd") == first_fd:
                    pre_same_fd.append(item)
        stop_index = first_head_index
        if auth_data_indexes:
            stop_index = auth_data_indexes[0]
        elif ack_like_responses:
            stop_index = ack_like_responses[0]["index"]
        stop_index = max(stop_index, first_head_index)
        for index in range(start, min(len(records), stop_index) + 1):
            record = records[index - 1]
            if record.get("event") in {"transport_socket", "transport_bind", "transport_connect", "transport_buffer", "ssl_buffer"}:
                item = _sequence_item(index, record) if record.get("event") in {"transport_buffer", "ssl_buffer"} else {
                    "index": index,
                    "event": record.get("event"),
                    "function": record.get("function"),
                    "fd": record.get("fd"),
                    "requestedLocal": record.get("requestedLocal"),
                    "local": record.get("local"),
                    "remote": record.get("remote"),
                    "peerAfter": record.get("peerAfter"),
                    "ret": record.get("ret"),
                    "errno": record.get("errno"),
                }
                auth_gate_window.append(item)

    same_fd_kinds = Counter(
        kind_by_index[index]
        for index in range(1, first_head_index or 1)
        if records[index - 1].get("fd") == first_fd and index in kind_by_index
    )
    missing = []
    if not auth_head_indexes:
        blocked = "auth_head_not_observed"
        missing.append("official trace does not contain a send-side kcp-auth-head packet")
    elif not auth_head_ack_indexes and not ack_like_responses:
        blocked = "auth_head_ack_missing"
        missing.append("no receive-side kcp-auth-head-ack cmd=7 after first AUTH_HEAD")
    else:
        blocked = None
    if first_head_index and not any(item.get("event") == "transport_bind" for item in pre_same_fd):
        missing.append("same-fd bind event before AUTH_HEAD not observed in probe log")
    if first_head_index and not any(item.get("event") == "transport_connect" for item in pre_same_fd):
        missing.append("same-fd connect event before AUTH_HEAD not observed in probe log")
    if first_head_index and not same_fd_kinds:
        missing.append("same-fd pre-AUTH payload history is empty")

    first_head_summary = None
    if first_head:
        decoded = decode_kcp_auth_focus_segment(_decode_hex(first_head))
        first_head_summary = {
            "index": first_head_index,
            "fd": first_fd,
            "remote": first_remote,
            "peer": first_peer,
            "local": first_local,
            "len": first_head.get("len"),
            "ret": first_head.get("ret"),
            "authFocus": bool(first_head.get("authFocus")),
            "stack": first_head.get("stack"),
            "kcp": decoded,
            "hexPrefix": "<redacted:kcp-auth>",
        }
    return {
        "observed": bool(auth_head_indexes or auth_head_ack_indexes),
        "stageBlocked": blocked,
        "firstAuthHead": first_head_summary,
        "authHeadSendIndexes": auth_head_indexes[:20],
        "sameFdAuthHeadSendsBeforeAckLike": same_fd_auth_head_sends[:20],
        "authHeadAckReceiveIndexes": auth_head_ack_indexes[:20],
        "authHeadAckLikeResponses": ack_like_responses[:20],
        "authHeadAckConfirmed": bool(auth_head_ack_indexes or ack_like_responses),
        "authDataSendIndexes": auth_data_indexes[:20],
        "authAckReceiveIndexes": auth_ack_indexes[:20],
        "sameFdPreAuthPayloadKinds": dict(same_fd_kinds.most_common()),
        "sameFdPreAuthEvents": pre_same_fd[-20:],
        "nearbyPreAuthEvents": pre_global[-20:],
        "authGateWindowEvents": auth_gate_window[-80:],
        "missingEvidence": missing,
        "nextQuestion": (
            "why official trace has no AUTH_HEAD"
            if blocked == "auth_head_not_observed"
            else (
                "which local proxy/outband/session state or packet makes server return cmd=7"
                if blocked == "auth_head_ack_missing"
                else "AUTH_HEAD_ACK or same-fd ACK-like response observed; proceed only after reproducing the AUTH_HEAD gate in Python"
            )
        ),
        "payloadStoredInReport": False,
    }


def auth_gate_replay_gap(auth_focus):
    """Return redacted implementation guidance for reproducing the AUTH gate.

    This intentionally avoids payload bytes.  It turns the official-client trace
    into constraints for the Python probe: fd lifecycle, packet lengths, and the
    causal receive-before-AUTH_DATA gate.
    """
    auth_focus = dict(auth_focus or {})
    first_head = auth_focus.get("firstAuthHead") or {}
    ack_like = list(auth_focus.get("authHeadAckLikeResponses") or [])
    first_ack_like = ack_like[0] if ack_like else None
    pre_events = list(auth_focus.get("authGateWindowEvents") or auth_focus.get("nearbyPreAuthEvents") or [])
    local_proxy_events = []
    for item in pre_events:
        local = str(item.get("local") or "")
        remote = str(item.get("remote") or "")
        peer = str(item.get("peer") or "")
        if "127.0.0.1:" in local or "127.0.0.1:" in remote or "127.0.0.1:" in peer:
            local_proxy_events.append({
                "index": item.get("index"),
                "event": item.get("event"),
                "function": item.get("function"),
                "fd": item.get("fd"),
                "direction": item.get("direction"),
                "len": item.get("len"),
                "ret": item.get("ret"),
                "errno": item.get("errno"),
                "local": item.get("local"),
                "remote": item.get("remote"),
                "peer": item.get("peer"),
                "peerAfter": item.get("peerAfter"),
                "payloadKind": item.get("payloadKind"),
                "frameHeader": item.get("frameHeader"),
                "payloadStoredInReport": False,
            })
    first_head_len = first_head.get("len")
    auth_data_len = first_ack_like.get("followedByAuthDataLen") if first_ack_like else None
    return {
        "readyForPythonAuthGateReproduction": bool(auth_focus.get("authHeadAckConfirmed") and first_ack_like),
        "stage": "auth_head_ack_gate",
        "firstExternalAuthHead": {
            "index": first_head.get("index"),
            "fd": first_head.get("fd"),
            "remote": first_head.get("remote"),
            "local": first_head.get("local"),
            "len": first_head_len,
            "ret": first_head.get("ret"),
            "payloadStoredInReport": False,
        },
        "sameFdAckLikeResponse": first_ack_like,
        "expectedAuthDataAfterAckLikeLen": auth_data_len,
        "officialPreAuthLocalProxyEvents": local_proxy_events[-8:],
        "localProxyBootstrapSchema": _local_proxy_bootstrap_schema(
            local_proxy_events,
            first_auth_head_index=first_head.get("index"),
            ack_like_index=first_ack_like.get("index") if first_ack_like else None,
        ),
        "localProxyWriterChainEvidence": _local_proxy_writer_chain_evidence(),
        "sameFdAuthHeadPump": {
            "sendCountBeforeAckLike": len(auth_focus.get("sameFdAuthHeadSendsBeforeAckLike") or []),
            "sends": list(auth_focus.get("sameFdAuthHeadSendsBeforeAckLike") or [])[:8],
            "interpretation": "official client pumps AUTH_HEAD from the same UDP fd while ZIME_DataChannelProcess2 runs; Python should not treat one datagram as proof of full official lifecycle",
            "payloadStoredInReport": False,
        },
        "pythonGap": [
            "direct_auth_head_without_official_local_proxy_session",
            "missing_repeated_local_proxy_bootstrap_cycles_before_ack_like",
            "first_external_auth_head_shape_not_yet_reproduced",
        ],
        "doNext": [
            "model or reproduce the local proxy/session bootstrap before external AUTH_HEAD",
            "make Python first external AUTH_HEAD match the official gate constraints before sending AUTH_DATA",
            "stop at authHeadAckConfirmed before attempting SYNACK/native bridge/DISPLAY_INIT",
        ],
        "doNotUseAs": [
            "payload replay material",
            "Python runner success",
            "40-minute keepalive proof",
        ],
        "payloadPolicy": "lengths and event ordering only; auth bytes are not stored in this summary",
    }


def _loopback_endpoint(value):
    value = str(value or "")
    return value if "127.0.0.1:" in value else ""


def _local_proxy_bootstrap_schema(local_proxy_events, *, first_auth_head_index=None, ack_like_index=None):
    """Describe the official loopback bootstrap without retaining payload bytes."""
    events = list(local_proxy_events or [])
    connects = [e for e in events if e.get("event") == "transport_connect"]
    sends = [e for e in events if e.get("direction") == "send" and e.get("len") == 160]
    receives = [e for e in events if e.get("direction") == "receive" and e.get("len") == 4]
    cycles = []
    for send in sends:
        send_local = _loopback_endpoint(send.get("local"))
        send_peer = _loopback_endpoint(send.get("peer") or send.get("remote"))
        if not send_local or not send_peer:
            continue
        matching_connect = next(
            (
                c for c in connects
                if c.get("fd") == send.get("fd")
                and _loopback_endpoint(c.get("local")) == send_local
                and _loopback_endpoint(c.get("remote") or c.get("peerAfter")) == send_peer
            ),
            None,
        )
        matching_recv = next(
            (
                r for r in receives
                if _loopback_endpoint(r.get("local")) == send_peer
                and _loopback_endpoint(r.get("peer") or r.get("remote")) == send_local
            ),
            None,
        )
        if matching_connect and matching_recv:
            send_header = dict(send.get("frameHeader") or {})
            recv_header = dict(matching_recv.get("frameHeader") or {})
            cycle = {
                "connectIndex": matching_connect.get("index"),
                "clientSendIndex": send.get("index"),
                "serverReceiveHeaderIndex": matching_recv.get("index"),
                "clientFd": send.get("fd"),
                "serverFd": matching_recv.get("fd"),
                "clientLocal": send.get("local"),
                "serverLocal": matching_recv.get("local"),
                "serverListenEndpoint": send_peer,
                "position": _auth_gate_cycle_position(
                    send.get("index"),
                    first_auth_head_index=first_auth_head_index,
                    ack_like_index=ack_like_index,
                ),
                "connectErrno": matching_connect.get("errno"),
                "connectErrnoMeaning": "EINPROGRESS/nonblocking connect" if matching_connect.get("errno") == 115 else None,
                "clientSendLen": send.get("len"),
                "serverReceiveLen": matching_recv.get("len"),
                "frameHeader": {
                    "u16Type": send_header.get("u16Type"),
                    "u16BodyLen": send_header.get("u16BodyLen"),
                    "totalLenMatchesHeader": send_header.get("totalLenMatchesHeader"),
                    "serverHeaderMatches": bool(
                        send_header.get("u16Type") == recv_header.get("u16Type")
                        and send_header.get("u16BodyLen") == recv_header.get("u16BodyLen")
                    ),
                },
                "payloadStoredInReport": False,
            }
            if cycle not in cycles:
                cycles.append(cycle)
    if not cycles:
        return {
            "observed": False,
            "reason": "loopback connect + send160 + reverse recv4 sequence not present in the auth focus window",
            "payloadStoredInReport": False,
        }
    best = cycles[0]
    send = next(e for e in sends if e.get("index") == best["clientSendIndex"])
    recv = next(e for e in receives if e.get("index") == best["serverReceiveHeaderIndex"])
    connect = next(e for e in connects if e.get("index") == best["connectIndex"])
    send_header = dict(send.get("frameHeader") or {})
    recv_header = dict(recv.get("frameHeader") or {})
    position_counts = dict(Counter(cycle.get("position") for cycle in cycles).most_common())
    listen_endpoints = sorted(set(cycle.get("serverListenEndpoint") for cycle in cycles if cycle.get("serverListenEndpoint")))
    return {
        "observed": True,
        "sequence": [
            "client_loopback_socket_connect_nonblocking",
            "client_send_local_proxy_frame_len_160",
            "server_side_recv_local_proxy_frame_header_len_4",
        ],
        "cycleCountInAuthGateWindow": len(cycles),
        "cyclesBeforeAckLike": cycles[:8],
        "cyclePositionCounts": position_counts,
        "serverListenEndpoints": listen_endpoints,
        "repeatedBeforeAckLike": bool(len(cycles) > 1 and any(c.get("position") == "between_first_auth_head_and_ack_like" for c in cycles)),
        "clientFd": send.get("fd"),
        "serverFd": recv.get("fd"),
        "clientLocal": send.get("local"),
        "serverLocal": recv.get("local"),
        "connect": {
            "index": connect.get("index"),
            "fd": connect.get("fd"),
            "ret": connect.get("ret"),
            "errno": connect.get("errno"),
            "errnoMeaning": "EINPROGRESS/nonblocking connect" if connect.get("errno") == 115 else None,
        },
        "clientSend": {
            "index": send.get("index"),
            "len": send.get("len"),
            "ret": send.get("ret"),
            "payloadKind": send.get("payloadKind"),
            "frameHeader": {
                **send_header,
            },
        },
        "serverReceiveHeader": {
            "index": recv.get("index"),
            "len": recv.get("len"),
            "ret": recv.get("ret"),
            "payloadKind": recv.get("payloadKind"),
            "frameHeader": {
                **recv_header,
                "matchesClientHeader": bool(
                    send_header.get("u16Type") == recv_header.get("u16Type")
                    and send_header.get("u16BodyLen") == recv_header.get("u16BodyLen")
                ),
            },
        },
        "interpretation": (
            "the official client establishes local proxy/session state around the external AUTH gate; "
            "the 4-byte receive is the local frame header, not the cloud ACK"
        ),
        "stateImplication": (
            "a Python probe that only sends the 199-byte external AUTH_HEAD can collide with or replace the official cloud session, "
            "but it has not reproduced the local proxy fd/session lifecycle that precedes the official 71-byte ACK-like gate"
        ),
        "payloadStoredInReport": False,
    }


def _auth_gate_cycle_position(index, *, first_auth_head_index=None, ack_like_index=None):
    try:
        index = int(index)
    except (TypeError, ValueError):
        return "unknown"
    try:
        first_auth_head_index = int(first_auth_head_index)
    except (TypeError, ValueError):
        first_auth_head_index = None
    try:
        ack_like_index = int(ack_like_index)
    except (TypeError, ValueError):
        ack_like_index = None
    if first_auth_head_index is not None and index < first_auth_head_index:
        return "before_first_auth_head"
    if (
        first_auth_head_index is not None
        and ack_like_index is not None
        and first_auth_head_index < index < ack_like_index
    ):
        return "between_first_auth_head_and_ack_like"
    if ack_like_index is not None and index > ack_like_index:
        return "after_ack_like"
    return "auth_gate_window"


def extract_sequence(path, *, focus_kind="spice-mini-unknown:0x082a", window=6, limit=160, report_file=None):
    """Extract runner-oriented protocol context windows from a ZIME probe JSONL.

    This does not replay captured traffic.  It turns official-client trace evidence
    into compact implementation input for the independent RAP/ZIME/SPICE runner:
    fd/peer/ssl identity, direction, payload class, and bytes around critical
    SSL/SPICE control events.
    """
    records, invalid = _load_jsonl(path)
    window = max(0, int(window))
    limit = max(1, int(limit))

    key_indexes = []
    kind_counts = Counter()
    identity_counts = Counter()
    for index, record in enumerate(records):
        kind = _record_kind(record)
        kind_counts[kind] += 1
        ident = _record_identity(record)
        identity_counts[(
            ident.get("fd"),
            ident.get("peer"),
            ident.get("remote"),
            ident.get("ssl"),
            ident.get("channelId"),
            ident.get("streamId"),
        )] += 1
        if (
            kind == focus_kind
            or focus_kind in kind
            or str(record.get("event") or "") == focus_kind
            or str(record.get("function") or "") == focus_kind
        ):
            key_indexes.append(index)

    selected_indexes = set()
    for key in key_indexes:
        for idx in range(max(0, key - window), min(len(records), key + window + 1)):
            selected_indexes.add(idx)

    if not selected_indexes:
        interesting = ("spice-", "chuanyun-frame", "ssl_buffer")
        for index, record in enumerate(records):
            kind = _record_kind(record)
            if str(record.get("event") or "") == "ssl_buffer" or any(token in kind for token in interesting):
                selected_indexes.add(index)
            if len(selected_indexes) >= limit:
                break

    sequence = [_sequence_item(index, records[index]) for index in sorted(selected_indexes)[:limit]]
    identities = [
        {"fd": fd, "peer": peer, "remote": remote, "ssl": ssl, "channelId": channel, "streamId": stream, "records": count}
        for (fd, peer, remote, ssl, channel, stream), count in identity_counts.most_common(20)
    ]
    runner_input = {
        "sourceTrace": str(path),
        "focusKind": focus_kind,
        "focusMatches": key_indexes[:80],
        "contextWindow": window,
        "sequenceRecords": len(sequence),
        "sequence": sequence,
        "transportIdentities": identities,
        "implementationUse": (
            "Use these official-client fd/peer/ssl/channel/stream context windows to map "
            "the independent RAP/ZIME/SPICE runner state machine; do not replay captured bytes "
            "as a keepalive shortcut."
        ),
    }
    report = {
        "ok": True,
        "inputFile": str(path),
        "records": len(records),
        "invalidLines": invalid,
        "focusKind": focus_kind,
        "focusMatches": key_indexes[:80],
        "window": window,
        "sequenceRecords": len(sequence),
        "transportIdentities": identities,
        "payloadKindCounts": dict(kind_counts.most_common()),
        "sequence": sequence,
        "runnerInput": runner_input,
        "runnerInputUse": runner_input["implementationUse"],
        "analyzedAt": core.shanghai_now().isoformat(),
    }
    core.write_private_json_report(report, report_file)
    return report


def _event_progress(kind, direction, progress):
    if "spice-link" in kind:
        progress["spiceLinkSeen"] = True
    if "chuanyun-frame" in kind:
        progress["chuanyunFrameSeen"] = True
    if "spice-display-init" in kind:
        progress["displayInitSeen"] = True
        if direction == "send":
            progress["displayInitSent"] = True
    if "spice-set-ack" in kind and direction == "receive":
        progress["setAckReceived"] = True
    if "spice-ack-sync" in kind and direction == "send":
        progress["ackSyncSent"] = True
    if "spice-ping" in kind and direction == "receive":
        progress["pingReceived"] = True
    if "spice-pong" in kind and direction == "send":
        progress["pongSent"] = True
    if "spice-surface-create" in kind and direction == "receive":
        progress["surfaceCreateReceived"] = True
    if "spice-draw-copy" in kind and direction == "receive":
        progress["drawCopyReceived"] = True
    if "spice-mark" in kind and direction == "receive":
        progress["markReceived"] = True


def analyze(path, report_file=None):
    records, invalid = _load_jsonl(path)
    function_counts = Counter(str(item.get("function") or "-") for item in records)
    event_counts = Counter(str(item.get("event") or "-") for item in records)
    kind_counts = Counter()
    direction_counts = Counter()
    memory_counts = Counter()
    struct_counts = Counter()
    ptr_table_counts = Counter()
    ptr_symbol_counts = Counter()
    callback_counts = Counter()
    packet_spec_counts = Counter()
    packet_spec_payload_counts = Counter()
    packet_spec_iov_counts = Counter()
    packet_spec_total_iov_bytes = 0
    packet_spec_event_samples = []
    packet_spec_memory_samples = []
    channels = defaultdict(lambda: {"send": 0, "receive": 0, "streams": defaultdict(lambda: {"send": 0, "receive": 0})})
    samples = []
    memory_samples = []
    struct_samples = []
    ptr_table_samples = []
    ptr_symbol_samples = []
    callback_samples = []
    progress = {
        "spiceLinkSeen": False,
        "chuanyunFrameSeen": False,
        "displayInitSeen": False,
        "displayInitSent": False,
        "setAckReceived": False,
        "ackSyncSent": False,
        "pingReceived": False,
        "pongSent": False,
        "surfaceCreateReceived": False,
        "drawCopyReceived": False,
        "markReceived": False,
    }

    buffer_events = {"zime_buffer", "transport_buffer", "ssl_buffer", "zime_callback_buffer"}
    for index, record in enumerate(records, 1):
        if record.get("event") == "zime_memory":
            key = f"{record.get('function') or '-'}:{record.get('label') or '-'}"
            memory_counts[key] += 1
            decoded_specs = []
            if record.get("label") == "packet_specs":
                decoded_specs = decode_zime_packet_specs(_decode_hex(record), base_ptr=record.get("ptr"))
                if decoded_specs:
                    packet_spec_counts[f"{record.get('function') or '-'}:memory"] += len(decoded_specs)
                    for spec in decoded_specs:
                        packet_spec_iov_counts[str(spec.get("iovCount"))] += 1
                    if len(packet_spec_memory_samples) < 20:
                        packet_spec_memory_samples.append({
                            "index": index,
                            "function": record.get("function"),
                            "ptr": record.get("ptr"),
                            "decoded": decoded_specs[:4],
                        })
            if len(memory_samples) < 40:
                sample = {
                    "index": index,
                    "function": record.get("function"),
                    "label": record.get("label"),
                    "ptr": record.get("ptr"),
                    "requested": record.get("requested"),
                    "dumped": record.get("dumped"),
                    "hexPrefix": str(record.get("hex") or "")[:160],
                }
                if decoded_specs:
                    sample["decodedPacketSpecs"] = decoded_specs[:2]
                memory_samples.append(sample)
            continue
        if record.get("event") == "zime_struct":
            key = f"{record.get('function') or '-'}:{record.get('label') or '-'}:{record.get('struct') or '-'}"
            struct_counts[key] += 1
            if len(struct_samples) < 80:
                keep = {
                    "index": index,
                    "function": record.get("function"),
                    "label": record.get("label"),
                    "struct": record.get("struct"),
                    "ptr": record.get("ptr"),
                }
                for field in (
                    "eZIMEDCRole",
                    "eZIMESupportDCProtocol",
                    "bUDPPayloadReserve4Bytes",
                    "eDCProtocol",
                    "u16BaseMTU",
                    "bSavePcap",
                    "bOpenStat",
                    "eBusinessType",
                    "baseOffset",
                    "localAddr",
                    "remoteAddr",
                    "nOpaqueLen",
                    "mode",
                    "supportDropData",
                    "latencyThreshMs",
                    "u8Priority",
                    "u32MaxBandwidth",
                    "payloadTypeHex",
                ):
                    if field in record:
                        keep[field] = record.get(field)
                struct_samples.append(keep)
            continue
        if record.get("event") == "zime_ptr_table":
            fn = record.get("function") or "-"
            ptr_table_counts[fn] += 1
            if len(ptr_table_samples) < 40:
                keep = {
                    "index": index,
                    "function": record.get("function"),
                    "engine": record.get("engine"),
                    "table": record.get("table"),
                    "ret": record.get("ret"),
                }
                for slot in range(8):
                    field = f"ptr{slot}"
                    if field in record:
                        keep[field] = record.get(field)
                ptr_table_samples.append(keep)
            continue
        if record.get("event") == "zime_ptr_symbol":
            fn = record.get("function") or "-"
            slot = record.get("slot")
            symbol = record.get("symbol") or "-"
            ptr_symbol_counts[f"{fn}:slot{slot}:{symbol}"] += 1
            if len(ptr_symbol_samples) < 80:
                ptr_symbol_samples.append({
                    "index": index,
                    "function": record.get("function"),
                    "slot": record.get("slot"),
                    "ptr": record.get("ptr"),
                    "object": record.get("object"),
                    "symbol": record.get("symbol"),
                    "symbolOffset": record.get("symbolOffset"),
                })
            continue
        if record.get("event") in {"zime_callback", "zime_callback_wrap"}:
            fn = record.get("function") or "-"
            callback_counts[fn] += 1
            if len(callback_samples) < 80:
                keep = {
                    "index": index,
                    "event": record.get("event"),
                    "function": record.get("function"),
                    "slot": record.get("slot"),
                    "channelId": record.get("channelId"),
                    "streamId": record.get("streamId"),
                    "ret": record.get("ret"),
                }
                for field in (
                    "socketParam",
                    "packetSpecs",
                    "count",
                    "len",
                    "value",
                    "status",
                    "err",
                    "protocol",
                    "blocked",
                    "reason",
                    "originalTable",
                    "originalSlot",
                    "wrappedTable",
                    "engine",
                    "self",
                ):
                    if field in record:
                        keep[field] = record.get(field)
                callback_samples.append(keep)
            continue
        if record.get("event") == "zime_packet_spec":
            fn = record.get("function") or "-"
            packet_spec_counts[f"{fn}:event"] += 1
            if "firstIovPayloadKind" in record:
                packet_spec_payload_counts[str(record.get("firstIovPayloadKind") or "-")] += 1
            if "iovCount" in record:
                packet_spec_iov_counts[str(record.get("iovCount"))] += 1
            try:
                packet_spec_total_iov_bytes += int(record.get("totalIovBytes") or 0)
            except (TypeError, ValueError):
                pass
            if len(packet_spec_event_samples) < 80:
                keep = {
                    "index": index,
                    "function": record.get("function"),
                    "specIndex": record.get("index"),
                    "count": record.get("count"),
                    "layout": record.get("layout"),
                    "specPtr": record.get("specPtr"),
                    "iov": record.get("iov"),
                    "iovCount": record.get("iovCount"),
                    "totalIovBytes": record.get("totalIovBytes"),
                    "firstIovLen": record.get("firstIovLen"),
                    "firstIovPayloadKind": record.get("firstIovPayloadKind"),
                    "firstIovHexPrefix": str(record.get("firstIovHexPrefix") or "")[:160],
                    "localAddr": record.get("localAddr"),
                    "destAddr": record.get("destAddr"),
                    "embeddedAddrFamily": record.get("embeddedAddrFamily"),
                    "embeddedAddr": record.get("embeddedAddr"),
                    "addrLen": record.get("addrLen"),
                    "traceOnly": record.get("traceOnly", True),
                }
                packet_spec_event_samples.append(keep)
            continue
        if record.get("event") not in buffer_events:
            continue
        raw = _decode_hex(record)
        computed_kind = classify_payload(raw, allow_short_mini=record.get("event") == "ssl_buffer")
        recorded_kind = str(record.get("payloadKind") or "")
        kind = computed_kind if computed_kind != "unknown" else (recorded_kind or computed_kind)
        direction = str(record.get("direction") or "-")
        channel_value = record.get("channelId")
        if channel_value is None:
            channel_value = record.get("fd")
        if channel_value is None:
            channel_value = record.get("ssl")
        stream_value = record.get("streamId")
        if stream_value is None:
            stream_value = record.get("peer")
        channel_id = str(channel_value if channel_value is not None else "-")
        stream_id = str(stream_value if stream_value is not None else "-")
        kind_counts[kind] += 1
        direction_counts[direction] += 1
        channels[channel_id][direction] += 1
        channels[channel_id]["streams"][stream_id][direction] += 1
        _event_progress(kind, direction, progress)
        if len(samples) < 24 or kind != "unknown":
            samples.append({
                "index": index,
                "event": record.get("event"),
                "function": record.get("function"),
                "direction": direction,
                "channelId": record.get("channelId"),
                "streamId": record.get("streamId"),
                "fd": record.get("fd"),
                "peer": record.get("peer"),
                "remote": record.get("remote"),
                "ssl": record.get("ssl"),
                "len": record.get("len"),
                "ret": record.get("ret"),
                "payloadKind": kind,
                "recordedPayloadKind": recorded_kind,
                "hexPrefix": str(record.get("hex") or "")[:96],
            })

    channel_report = {}
    for channel_id, item in channels.items():
        channel_report[channel_id] = {
            "send": item["send"],
            "receive": item["receive"],
            "streams": dict(item["streams"]),
        }

    display_activity = (
        (progress["surfaceCreateReceived"] and progress["markReceived"])
        or (progress["surfaceCreateReceived"] and progress["drawCopyReceived"])
        or (progress["drawCopyReceived"] and progress["markReceived"])
    )
    auth_focus = auth_head_ack_focus(records)
    auth_replay_gap = auth_gate_replay_gap(auth_focus)
    report = {
        "ok": True,
        "inputFile": str(path),
        "records": len(records),
        "invalidLines": invalid,
        "eventCounts": dict(event_counts.most_common()),
        "functionCounts": dict(function_counts.most_common()),
        "bufferDirectionCounts": dict(direction_counts.most_common()),
        "payloadKindCounts": dict(kind_counts.most_common()),
        "channels": channel_report,
        "zimeMemory": {
            "counts": dict(memory_counts.most_common()),
            "samples": memory_samples,
            "note": "Bounded raw ZIME API structure snapshots from the LD_PRELOAD probe; local analysis aid only.",
        },
        "zimeStruct": {
            "counts": dict(struct_counts.most_common()),
            "samples": struct_samples,
            "note": "Decoded ZIME C ABI fields inferred from libspice-client-glib-zte DWARF metadata.",
        },
        "zimePtrTable": {
            "counts": dict(ptr_table_counts.most_common()),
            "symbols": dict(ptr_symbol_counts.most_common()),
            "samples": ptr_table_samples,
            "symbolSamples": ptr_symbol_samples,
            "note": "Function-pointer table slots from ZIME callbacks/transports; symbol names are best-effort dladdr results from the probe.",
        },
        "zimeCallbacks": {
            "counts": dict(callback_counts.most_common()),
            "samples": callback_samples,
            "note": "Runtime ZIME callback and callback-wrapper observations. Buffer callbacks are also counted in payloadKindCounts and channels.",
        },
        "zimePacketSpecs": {
            "counts": dict(packet_spec_counts.most_common()),
            "iovCounts": dict(packet_spec_iov_counts.most_common()),
            "firstIovPayloadKinds": dict(packet_spec_payload_counts.most_common()),
            "totalIovBytesObserved": packet_spec_total_iov_bytes,
            "eventSamples": packet_spec_event_samples,
            "memorySamples": packet_spec_memory_samples,
            "layout": "ZIMEPacketOutSpec_candidate_v1_size_0x68",
            "note": (
                "Candidate packet-spec fields inferred from LsquicCallbacksImpl::PacketsOutBatch. "
                "These are protected UDP payload descriptors and trace-only metadata, not replayable SPICE bytes."
            ),
        },
        "authHeadAckFocus": auth_focus,
        "authGateReplayGap": auth_replay_gap,
        "progress": progress,
        "protocolEvidence": {
            "displayInitAndDisplayActivitySeen": bool(progress["displayInitSeen"] and display_activity),
            "ackPongMaintenanceSeen": bool((progress["ackSyncSent"] or progress["setAckReceived"]) and (progress["pongSent"] or progress["pingReceived"])),
            "traceOnly": True,
            "note": "This is transport/protocol trace evidence only. It is not power-state keepalive proof without a verified-run or power-monitor report.",
        },
        "samples": _select_samples(samples, limit=80),
        "nextStep": (
            "Focus only on AUTH_HEAD_ACK: compare same-fd pre-AUTH lifecycle against the official client and reproduce that minimal path."
            if auth_focus.get("observed") and auth_focus.get("stageBlocked") in {"auth_head_not_observed", "auth_head_ack_missing"} else
            "Reproduce the official local proxy/session bootstrap and first external AUTH_HEAD gate in Python; do not proceed to SYNACK/native bridge/DISPLAY_INIT yet."
            if auth_replay_gap.get("readyForPythonAuthGateReproduction") else
            "Use this trace to map channel/stream IDs and implement the minimal RAP/ZIME/SPICE runner, then prove it with verified-run."
            if progress["displayInitSeen"] else
            "Capture a longer official connected desktop session; DISPLAY_INIT was not observed in this probe log."
        ),
        "analyzedAt": core.shanghai_now().isoformat(),
    }
    core.write_private_json_report(report, report_file)
    return report
