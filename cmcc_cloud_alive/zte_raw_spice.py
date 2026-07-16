#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZTE raw SPICE helpers for CAG TCP/TLS product route.

Port of B's internal/spice/raw.go.  This module intentionally keeps the same
wire-layout quirks as the official ZTE tunnel: REDQ link packets, zero ticket
raw auth, 8-byte ZTE data-message prefix, and 5-byte suffix preservation.
"""

from __future__ import annotations

import os
import socket
import struct
import time
import logging
from dataclasses import dataclass
from typing import Optional, Tuple

TERMINAL_GUID = "31BF5444-86E0-4D5D-B1AB-A42FFBAC72C9"
TERMINAL_GUID_BYTES = bytes([
    0x44, 0x54, 0xBF, 0x31, 0xE0, 0x86, 0x5D, 0x4D,
    0xB1, 0xAB, 0xA4, 0x2F, 0xFB, 0xAC, 0x72, 0xC9,
])


def _put_u16(buf: bytearray, off: int, v: int) -> None:
    struct.pack_into("<H", buf, off, v & 0xFFFF)


def _put_u32(buf: bytearray, off: int, v: int) -> None:
    struct.pack_into("<I", buf, off, v & 0xFFFFFFFF)


def _u16(b: bytes) -> int:
    return struct.unpack_from("<H", b, 0)[0]


def _u32(b: bytes) -> int:
    return struct.unpack_from("<I", b, 0)[0]


def _zte_main_init_connection_id(payload: bytes) -> int:
    # Ported from Go raw.go:207 zteMainInitConnectionID.
    # ZTE MAIN_INIT connection_id is NOT at payload[:4]; locate via marker
    # 0x02 0x00 0x00 0x00 0x01 and take the 4 bytes preceding it, else
    # fall back to payload[3:7].
    marker = b"\x02\x00\x00\x00\x01"
    idx = payload.find(marker)
    if idx >= 4:
        return _u32(payload[idx - 4:idx])
    if len(payload) >= 7:
        return _u32(payload[3:7])
    return 0


def copy_c_string(dst: memoryview, s: str) -> None:
    data = s.encode("utf-8", "ignore")
    n = min(len(dst), len(data))
    dst[:n] = data[:n]
    if n < len(dst):
        dst[n] = 0


def buildZTERawMainREDQ(key: str, vmid: str, linkUUID: Optional[bytes], traceID: str, spanID: str) -> bytes:
    if not linkUUID or len(linkUUID) != 16:
        linkUUID = os.urandom(16)
    redq = bytearray(729)
    redq[0:4] = b"REDQ"
    _put_u32(redq, 4, 2)
    _put_u32(redq, 8, 2)
    _put_u32(redq, 12, 713)
    redq[20] = 1
    _put_u32(redq, 22, 1)
    _put_u32(redq, 26, 1)
    _put_u32(redq, 30, 705)
    _put_u32(redq, 42, 0x1400)
    _put_u32(redq, 46, 0x10000)
    copy_c_string(memoryview(redq)[50:95], key + vmid)
    redq[95:111] = linkUUID[:16]
    redq[127:143] = TERMINAL_GUID_BYTES
    copy_c_string(memoryview(redq)[159:192], traceID)
    copy_c_string(memoryview(redq)[192:209], spanID)
    _put_u32(redq, 717, 0x800)
    _put_u32(redq, 721, 0x232900)
    return bytes(redq)


def BuildZTERawChannelREDQ(
    key: str,
    vmid: str,
    linkUUID: Optional[bytes],
    traceID: str,
    spanID: str,
    connectionID: int,
    channelType: int,
    channelID: int,
) -> bytes:
    length = 725
    size = 709
    cap_count = 0
    caps = [0x800]
    if channelType == 2:
        length = 733
        size = 717
        cap_count = 2
        caps = [0xA00, 0xFFC30DEC, 0x48]
    elif channelType == 5:
        length = 729
        size = 713
        cap_count = 1
        caps = [0x800, 0x0E]
    elif channelType == 6:
        length = 729
        size = 713
        cap_count = 1
        caps = [0x800, 0x07]
    if not linkUUID or len(linkUUID) != 16:
        linkUUID = os.urandom(16)
    redq = bytearray(length)
    redq[0:4] = b"REDQ"
    _put_u32(redq, 4, 2)
    _put_u32(redq, 8, 2)
    _put_u32(redq, 12, size)
    _put_u32(redq, 16, connectionID)
    redq[20] = channelType & 0xFF
    redq[21] = channelID & 0xFF
    _put_u32(redq, 22, 1)
    _put_u32(redq, 26, cap_count)
    _put_u32(redq, 30, 705)
    _put_u32(redq, 42, 0x1400)
    _put_u32(redq, 46, 0x10000)
    copy_c_string(memoryview(redq)[50:95], key + vmid)
    redq[95:111] = linkUUID[:16]
    copy_c_string(memoryview(redq)[159:192], traceID)
    copy_c_string(memoryview(redq)[192:209], spanID)
    cap_off = length - len(caps) * 4
    for i, cap in enumerate(caps):
        _put_u32(redq, cap_off + i * 4, cap)
    return bytes(redq)


def buildTerminalInfoMessage() -> bytes:
    msg = bytearray(68)
    _put_u16(msg, 0, 0x7C)
    _put_u32(msg, 2, 57)
    msg[11:11 + len(TERMINAL_GUID)] = TERMINAL_GUID.encode("ascii")
    return bytes(msg)


def BuildZTERawDisplayInit() -> bytes:
    return bytes.fromhex("65001300000000000000000100004001000000000100fc5f000000000003")


def BuildZTERawInputInit() -> bytes:
    return bytes.fromhex("67000200000000000000000200")


def BuildZTERawDisplayHeartbeat(counter: int) -> bytes:
    """Build a ZTE raw SPICE display heartbeat (type=3, 12-byte body).

    Reverse-engineered from pcapng stream analysis (T7-C-fix).  The display
    channel carries a periodic type=3 message whose body is::

        [0:u32][0xffffff00:u32][varying_u32]

    The third u32 is a monotonic counter that increments ~250 every ~5
    packets (~21 Hz), mimicking a screen-refresh timestamp.
    """
    msg = bytearray(18)  # type(2) + size(4) + body(12)
    _put_u16(msg, 0, 0x0003)
    _put_u32(msg, 2, 12)
    _put_u32(msg, 6, 0)                       # body[0:4]  = 0
    _put_u32(msg, 10, 0xFFFFFF00)             # body[4:8]  = 0xffffff00
    _put_u32(msg, 14, counter & 0xFFFFFFFF)   # body[8:12] = varying counter
    return bytes(msg)


def rawMessageWithPrefix(serial: int, msg: bytes) -> bytes:
    out = bytearray(8 + len(msg))
    _put_u32(out, 0, serial)
    out[8:] = msg
    return bytes(out)


def _set_timeout(conn, timeout: Optional[float]) -> None:
    if hasattr(conn, "settimeout"):
        conn.settimeout(timeout)


def _read_exact(conn, n: int) -> bytes:
    chunks = []
    got = 0
    while got < n:
        part = conn.recv(n - got)
        if not part:
            raise EOFError("connection closed")
        chunks.append(part)
        got += len(part)
    return b"".join(chunks)


def readRawLinkReply(conn, timeout: float = 8.0) -> bytes:
    _set_timeout(conn, timeout)
    head = _read_exact(conn, 16)
    if head[:4] != b"REDQ":
        raise ValueError(f"invalid REDQ magic: {head[:4].hex()}")
    size = _u32(head[12:16])
    if size > 4096:
        raise ValueError(f"invalid REDQ reply size {size}")
    return head + _read_exact(conn, size)


@dataclass
class RawState:
    LastSerial: int = 0
    LastSuffix: bytes = b""
    NextSerial: int = 0

    def ReadMessage(self, conn, timeout: float = 2.0) -> Tuple[int, bytes]:
        _set_timeout(conn, timeout)
        head = _read_exact(conn, 6)
        has_zte_prefix = False
        msg_type = _u16(head[:2])
        size = _u32(head[2:6])
        if size == 0:
            serial = _u32(head[:4])
            _ = _read_exact(conn, 2)  # prefix tail
            head = _read_exact(conn, 6)
            msg_type = _u16(head[:2])
            size = _u32(head[2:6])
            self.LastSerial = serial
            self.LastSuffix = b""
            has_zte_prefix = True
        if size > (1 << 20):
            raise ValueError(f"raw SPICE message too large: {size}")
        payload = _read_exact(conn, size)
        if has_zte_prefix and hasattr(conn, "TakeReadBufferN"):
            self.LastSuffix = conn.TakeReadBufferN(5) or b""
        return msg_type, payload

    def AutoReply(self, conn, msgType: int, payload: bytes) -> bool:
        if msgType == 0x04:
            pong = bytearray(6 + len(payload))
            _put_u16(pong, 0, 0x03)
            _put_u32(pong, 2, len(payload))
            pong[6:] = payload
            self.WriteMessage(conn, self.LastSerial, bytes(pong))
            return True
        if msgType == 0x03:
            generation = _u32(payload[:4]) if len(payload) >= 4 else 0
            ack = bytearray(10)
            _put_u16(ack, 0, 0x01)
            _put_u32(ack, 2, 4)
            _put_u32(ack, 6, generation)
            self.WriteMessage(conn, self.LastSerial, bytes(ack))
            return True
        if msgType == 0x74:
            reply = bytearray(7)
            _put_u16(reply, 0, 0x79)
            _put_u32(reply, 2, 1)
            self.WriteMessage(conn, self.nextSerial(), bytes(reply))
            return True
        return False

    def WriteMessage(self, conn, serial: int, msg: bytes) -> int:
        data = rawMessageWithPrefix(serial, msg) + (self.LastSuffix or b"")
        return conn.send(data) if hasattr(conn, "send") else conn.write(data)

    def nextSerial(self) -> int:
        if self.NextSerial == 0:
            self.NextSerial = 4
        serial = self.NextSerial
        self.NextSerial += 1
        return serial


_last_state = RawState()


def ReadRawMessage(conn, timeout: float = 2.0) -> Tuple[int, bytes]:
    global _last_state
    return _last_state.ReadMessage(conn, timeout)


def RawAutoReply(conn, msgType: int, payload: bytes) -> bool:
    return _last_state.AutoReply(conn, msgType, payload)


def WriteRawMessage(conn, serial: int, msg: bytes) -> int:
    data = rawMessageWithPrefix(serial, msg)
    return conn.send(data) if hasattr(conn, "send") else conn.write(data)


@dataclass
class RawHandshakeResult:
    SpiceSessionID: int = 0
    OK: bool = False
    error: Optional[str] = None


def RawMainHandshake(conn, key: str, vmid: str, linkUUID: Optional[bytes], traceID: str, spanID: str) -> RawHandshakeResult:
    state = RawState()
    try:
        conn.sendall(buildZTERawMainREDQ(key, vmid, linkUUID, traceID, spanID))
        reply = readRawLinkReply(conn, 8.0)
        pk_off = reply.find(bytes([0x30, 0x81, 0x9F, 0x30, 0x0D]))
        if pk_off < 0:
            pk_off = reply.find(bytes([0x30, 0x81]))
        if pk_off < 0:
            return RawHandshakeResult(error="raw SPICE link reply has no RSA key")
        # B parses the RSA key as a sanity check; product tunnel still sends a
        # 128-byte zero ticket with no auth-type prefix.  Keep the wire behavior.
        conn.sendall(b"\x00" * 128)
        result = _read_exact(conn, 4)
        code = _u32(result)
        if code != 0:
            return RawHandshakeResult(error=f"raw SPICE auth failed: result={code}")

        spice_session_id = 0
        for _ in range(15):
            msg_type, payload = state.ReadMessage(conn, 2.0)
            if msg_type == 0x67 and len(payload) >= 10:
                spice_session_id = _zte_main_init_connection_id(payload)
                if hasattr(conn, "DiscardReadBuffer"):
                    conn.DiscardReadBuffer()
                break
            state.AutoReply(conn, msg_type, payload)
        if spice_session_id == 0:
            return RawHandshakeResult(error="raw SPICE MAIN_INIT not received")

        attach = bytes.fromhex("680000000000")
        attach_sent = False
        for i in range(4):
            try:
                msg_type, payload = state.ReadMessage(conn, 2.0)
            except Exception:
                break
            if msg_type == 0x04:
                if state.LastSerial == 3 or i == 3:
                    state.WriteMessage(conn, state.LastSerial, attach)
                    attach_sent = True
                    break
                continue
            state.AutoReply(conn, msg_type, payload)
        if not attach_sent:
            conn.sendall(rawMessageWithPrefix(3, attach) + b"\x00" * 5)

        client_info = bytes.fromhex("72000800000000000000000100000001000000")
        conn.sendall(rawMessageWithPrefix(1, client_info))
        conn.sendall(rawMessageWithPrefix(2, buildTerminalInfoMessage()))

        init_ok = False
        for _ in range(5):
            try:
                msg_type, payload = state.ReadMessage(conn, 1.0)
            except Exception:
                break
            if msg_type != 0x04:
                state.AutoReply(conn, msg_type, payload)
            if msg_type in (0x68, 0x73):
                init_ok = True
                if msg_type == 0x73:
                    break
        if not init_ok:
            return RawHandshakeResult(SpiceSessionID=spice_session_id, error="raw SPICE init did not reach CHANNELS_LIST/info")
        return RawHandshakeResult(SpiceSessionID=spice_session_id, OK=True)
    except Exception as exc:
        return RawHandshakeResult(error=str(exc))


def keepaliveRawSpiceLoop(conn, interval: float = 25.0, stop_after: Optional[float] = None,
                          heartbeat_hz: float = 21.0,
                          display_links: Optional[list] = None) -> dict:
    """Read/auto-reply raw messages and periodically send display/input init.

    This is the Python route's conservative product keepalive loop: it preserves
    B's raw auto replies and injects screen/input channel init bytes as outbound
    traffic when idle.  It returns counters for reports/tests.

    When *heartbeat_hz* > 0 the loop also injects display type=3 heartbeat
    messages at that cadence, mimicking the screen-refresh traffic observed in
    pcapng captures (T7-C-fix).  The read timeout is shrunk to the heartbeat
    interval so the loop can honour the cadence.
    """
    state = RawState()
    started = time.time()
    next_tick = started
    counters = {"messages": 0, "autoReplies": 0, "ticks": 0, "errors": 0,
                "heartbeats": 0, "display_type3_heartbeat_frames": 0,
                "heartbeat_hz": heartbeat_hz}
    # Display heartbeat (type=3) injection — mimics screen-refresh traffic
    # observed in pcapng at ~21 Hz.  The body's varying u32 increments
    # ~250 every ~5 packets.
    hb_interval = (1.0 / heartbeat_hz) if heartbeat_hz and heartbeat_hz > 0 else None
    next_hb = started
    hb_counter = 0
    hb_seq = 0
    hb_burst_start = started
    hb_burst_frames = 0
    # Keep the read timeout short enough to honour the heartbeat cadence.
    if hb_interval:
        read_timeout = min(hb_interval, 1.0)
    else:
        read_timeout = min(1.0, max(0.1, interval))
    while stop_after is None or time.time() - started < stop_after:
        try:
            msg_type, payload = state.ReadMessage(conn, read_timeout)
            counters["messages"] += 1
            if state.AutoReply(conn, msg_type, payload):
                counters["autoReplies"] += 1
        except (socket.timeout, TimeoutError):
            pass
        except Exception:
            counters["errors"] += 1
            break
        now = time.time()
        if now >= next_tick:
            try:
                conn.sendall(rawMessageWithPrefix(state.nextSerial(), BuildZTERawDisplayInit()))
                conn.sendall(rawMessageWithPrefix(state.nextSerial(), BuildZTERawInputInit()))
                counters["ticks"] += 1
            except Exception:
                counters["errors"] += 1
                break
            next_tick = now + interval
        if hb_interval and now >= next_hb:
            try:
                suffix = state.LastSuffix if state.LastSuffix else b"\x00" * 5
                hb_msg = rawMessageWithPrefix(state.nextSerial(),
                                              BuildZTERawDisplayHeartbeat(hb_counter)) + suffix
                # Send on display sub-links (link 5/7) when available;
                # fall back to the main link for backward compatibility.
                targets = display_links if display_links else [conn]
                for link in targets:
                    link.sendall(hb_msg)
                counters["heartbeats"] += 1
                counters["display_type3_heartbeat_frames"] += len(targets)
                hb_seq += 1
                if hb_seq % 5 == 0:
                    hb_counter = (hb_counter + 250) & 0xFFFFFFFF
                # Burst-window logging: every 60 s report frame count / approx Hz.
                hb_burst_frames += len(targets)
                if now - hb_burst_start >= 60.0:
                    burst_dur = now - hb_burst_start
                    approx_hz = hb_burst_frames / burst_dur if burst_dur > 0 else 0.0
                    logging.getLogger(__name__).info(
                        "display type=3 heartbeat burst: frames=%d duration=%.1fs "
                        "approx_hz=%.1f channel=display type=3",
                        hb_burst_frames, burst_dur, approx_hz)
                    hb_burst_start = now
                    hb_burst_frames = 0
            except Exception:
                counters["errors"] += 1
                break
            next_hb = now + hb_interval
    return counters



def RawSubChannelHandshake(
    conn,
    key: str,
    vmid: str,
    linkUUID: Optional[bytes],
    traceID: str,
    spanID: str,
    spiceSessionID: int,
    channelType: int,
    channelID: int,
) -> bool:
    """Authenticate a ZTE raw SPICE sub-channel (P10-006/007/008).

    Mirrors the auth portion of :func:`RawMainHandshake` but uses the
    channel-scoped REDQ builder (:func:`BuildZTERawChannelREDQ`) and skips the
    MAIN_INIT / attach / init phases that only apply to the main link.

    Wire sequence (identical to the product tunnel for every sub link):
      1. send ``BuildZTERawChannelREDQ`` (725-byte REDQ with channel caps)
      2. ``readRawLinkReply`` → locate the RSA public-key marker
      3. send a 128-byte zero ticket (no auth-type prefix)
      4. read a 4-byte little-endian auth result; ``0`` means success

    Returns ``True`` on success, ``False`` otherwise.
    """
    try:
        conn.sendall(
            BuildZTERawChannelREDQ(
                key, vmid, linkUUID, traceID, spanID,
                spiceSessionID, channelType, channelID,
            )
        )
        reply = readRawLinkReply(conn, 8.0)
        pk_off = reply.find(bytes([0x30, 0x81, 0x9F, 0x30, 0x0D]))
        if pk_off < 0:
            pk_off = reply.find(bytes([0x30, 0x81]))
        if pk_off < 0:
            return False
        # Product tunnel sends a 128-byte zero ticket with no auth-type prefix.
        conn.sendall(b"\x00" * 128)
        result = _read_exact(conn, 4)
        code = _u32(result)
        return code == 0
    except Exception:
        return False
