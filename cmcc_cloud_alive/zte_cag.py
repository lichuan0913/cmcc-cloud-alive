#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pure-Python port of B's internal/zte/cag.go + cag_tcp.go (line-by-line fork).

ZTE CAG TCP/TLS transport (P7).  Once product_router decides route==ZTE and
zte_route.run_material has produced an ``OuterCAGTarget`` (firm CAG endpoint)
plus an ``InnerConnectParams`` (parsed from the connectStr), this module
performs the CAG TCP pre-auth handshake and upgrades the same socket to TLS.

The handshake is a strict byte-for-byte port of B's ``DialCAGTCPTLS``:

  1. TCP connect to outer CAG (cagIp:cagPort).
  2. Send 178-byte local-key packet (``build_cag_auth_head_packet`` payload).
  3. Read 50-byte local-key ack; verify magic ``ZTEC``; parse conv @ [14:18].
  4. Send 220-byte auth blob (``build_cag_auth_blob``).
  5. Read 36-byte auth ack; verify ``ack[4] == 0x01``.
  6. TLS upgrade on the *same* socket (InsecureSkipVerify, TLS 1.2+).
  7. Return (tls_stream, CAGSessionInfo(conv)).

Outer/inner separation (P6): ``dial_cag_tcp_tls`` accepts an
``OuterCAGTarget`` for the dial address and an ``InnerConnectParams`` for the
auth blob — they are never mixed.
"""

import os
import socket
import ssl
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

from .zte_connect_params import InnerConnectParams


# --- session info ----------------------------------------------------------

@dataclass
class CAGSessionInfo:
    """Mirror of Go CAGSessionInfo (cag.go:19)."""
    syn_id: bytes = b""
    conv: int = 0


# --- low-level fill helpers (cag.go:271-285) -------------------------------

def _fill_random(dst) -> None:
    """Fill ``dst`` with cryptographic random (cag.go fillRandom).

    ``dst`` must be a writable buffer (bytearray or memoryview slice).
    """
    data = os.urandom(len(dst))
    dst[:] = data


def _fill_ascii_hex(dst) -> None:
    """Fill ``dst`` with lowercase ASCII hex of random bytes (cag.go fillASCIIHex).

    ``len(dst)`` must be even; half as many random bytes are hex-encoded.
    ``dst`` must be a writable buffer (bytearray or memoryview slice).
    """
    n = len(dst)
    if n % 2 != 0:
        raise ValueError("fill_ascii_hex requires even length, got %d" % n)
    raw = os.urandom(n // 2)
    dst[:] = raw.hex().encode("ascii")


# --- auth head packet (cag.go:191-210) -------------------------------------

def build_cag_auth_head_packet() -> Tuple[bytes, bytes]:
    """Build the 199-byte CAG auth-head packet (cag.go buildCAGAuthHeadPacket).

    Returns ``(packet_199, syn_id_4)``.  The TCP first-send payload is
    ``packet[21:]`` (178 bytes).
    """
    packet = bytearray(21 + 178)  # 199 bytes
    mv = memoryview(packet)
    mv[0:4] = b"\x06\x00\x00\x80"
    syn_id = mv[11:15]  # writable view
    _fill_random(syn_id)

    payload = mv[21:]  # 178 bytes, writable view
    payload[0:4] = b"ZTEC"
    struct.pack_into("<H", payload, 4, 0x00ac)       # payload[4:6]
    struct.pack_into("<I", payload, 6, 101)           # payload[6:10]
    _fill_random(payload[10:14])
    payload[14:18] = b"\xdc\x00\x00\x00"
    _fill_random(payload[18:38])
    payload[38:42] = b"\x07\x00\x0b\x0b"
    _fill_ascii_hex(payload[54:86])    # 32 bytes
    _fill_ascii_hex(payload[118:134])  # 16 bytes
    return bytes(packet), bytes(syn_id)


# --- auth template (cag.go:136-151) ----------------------------------------

def parse_auth_template(template_hex: str) -> Optional[bytes]:
    """Parse a CAG auth template hex string (cag.go parseAuthTemplate).

    Returns ``None`` when ``template_hex`` is empty (build-from-scratch path).
    Accepts 241-byte (stripped to 220) or 220-byte templates.
    """
    if template_hex == "":
        return None
    try:
        template = bytes.fromhex(template_hex)
    except ValueError as exc:
        raise ValueError("decode CAG auth template: %s" % exc)
    if len(template) == 241 and template[0] == 0x08:
        return bytes(template)
    if len(template) == 220:
        return bytes(template)
    raise ValueError("invalid CAG auth template length %d" % len(template))


# --- auth blob (cag.go:153-189) --------------------------------------------

def build_cag_auth_blob(inner: InnerConnectParams,
                        template: Optional[bytes] = None) -> bytes:
    """Build the 220-byte CAG auth blob (cag.go buildCAGAuthBlob).

    ``inner`` is the frozen InnerConnectParams (P6).  When ``template`` is
    provided (220 or 241 bytes) the vmId is patched into ``blob[20:56]``;
    otherwise the blob is built from scratch using host/proxySport/vmId.
    """
    if inner is None:
        raise ValueError("missing connect params")
    if template is not None and len(template) == 241:
        template = template[21:]
    if template is not None and len(template) == 220:
        blob = bytearray(template)
        if len(inner.vm_id) == 36:
            blob[20:56] = inner.vm_id.encode("ascii")
        return bytes(blob)
    if template is not None and len(template) != 0:
        raise ValueError(
            "invalid CAG auth template length %d" % len(template))

    # build from scratch
    try:
        ip = socket.inet_aton(inner.host)
    except OSError:
        raise ValueError("CAG auth blob requires IPv4 host: %s" % inner.host)
    if inner.proxy_sport <= 0:
        raise ValueError("CAG auth blob requires proxySport")
    if len(inner.vm_id) != 36:
        raise ValueError("CAG auth blob requires 36-byte vmId")

    blob = bytearray(220)
    bmv = memoryview(blob)
    struct.pack_into("<I", bmv, 0, inner.proxy_sport)  # blob[0:4]
    bmv[4:8] = ip                                      # blob[4:8]
    bmv[20:56] = inner.vm_id.encode("ascii")           # blob[20:56]
    _fill_random(bmv[60:188])
    blob[188] = 0x50
    return bytes(blob)


# --- TCP read helper (cag_tcp.go:101-107) ----------------------------------

def _read_cag_tcp_packet(sock: socket.socket, want: int) -> bytes:
    """Read exactly ``want`` bytes from ``sock`` (cag_tcp.go readCAGTCPPacket)."""
    buf = bytearray()
    while len(buf) < want:
        chunk = sock.recv(want - len(buf))
        if not chunk:
            raise EOFError(
                "short read: got %d of %d bytes" % (len(buf), want))
        buf.extend(chunk)
    return bytes(buf)


# --- dial options ----------------------------------------------------------

@dataclass
class CAGDialOptions:
    """Mirror of Go CAGDialOptions (cag_tcp.go)."""
    address: str = ""               # outer CAG host:port
    inner: Optional[InnerConnectParams] = None
    auth_template_hex: str = ""
    timeout: float = 15.0


# --- main entry (cag_tcp.go:15-94) -----------------------------------------

def dial_cag_tcp_tls(opts: CAGDialOptions) -> Tuple[ssl.SSLSocket, CAGSessionInfo]:
    """Perform the ZTE CAG TCP pre-auth handshake + TLS upgrade.

    Returns ``(tls_stream, CAGSessionInfo)``.  Raises on any protocol error.
    """
    if opts.inner is None:
        raise ValueError("missing connect params")
    if opts.address == "":
        raise ValueError("missing CAG address")
    if opts.timeout == 0:
        opts.timeout = 15.0

    auth_template = parse_auth_template(opts.auth_template_hex)

    raw = socket.create_connection(_split_address(opts.address),
                                   timeout=opts.timeout)
    try:
        raw.settimeout(opts.timeout)

        # 1. send 178-byte local-key
        first_udp, _syn_id = build_cag_auth_head_packet()
        first = first_udp[21:]  # 178 bytes
        raw.sendall(first)

        # 2. read 50-byte local-key ack
        head_ack = _read_cag_tcp_packet(raw, 50)
        if len(head_ack) < 50 or head_ack[:4] != b"ZTEC":
            raise ValueError("invalid CAG TCP local-key ack")

        conv = struct.unpack_from("<I", head_ack, 14)[0]  # head_ack[14:18]

        # 3. send 220-byte auth blob
        second = build_cag_auth_blob(opts.inner, auth_template)
        raw.sendall(second)

        # 4. read 36-byte auth ack
        auth_ack = _read_cag_tcp_packet(raw, 36)
        if len(auth_ack) < 8 or auth_ack[4] != 0x01:
            prefix_len = min(16, len(auth_ack))
            raise ValueError(
                "invalid CAG TCP auth ack: %s"
                % auth_ack[:prefix_len].hex())

        # 5. TLS upgrade on the same socket
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        tls_stream = ctx.wrap_socket(raw, server_hostname=None)

        tls_stream.settimeout(None)
        info = CAGSessionInfo(conv=conv)
        # success — prevent the finally Close
        raw = None  # type: ignore
        return tls_stream, info
    finally:
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass


def _split_address(address: str) -> Tuple[str, int]:
    """Split ``host:port`` into ``(host, int(port))``."""
    host, _, port_s = address.rpartition(":")
    if not host or not port_s:
        raise ValueError("invalid CAG address: %r" % address)
    return host, int(port_s)
