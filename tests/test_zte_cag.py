#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Byte-level fixture tests for P6 (outer/inner split) and P7 (CAG transport).

Covers:
  - P6-001 OuterCAGTarget frozen contract + outer_from_firm factory
  - P6-002 InnerConnectParams frozen contract + inner_from_connect_params
  - P6-003 outer_from_firm extracts cag_ip/cag_port from firm auth
  - P7    build_cag_auth_head_packet byte layout (199B / 178B payload)
  - P7    build_cag_auth_blob (scratch / template-220 / template-241)
  - P7    parse_auth_template (empty / 220 / 241 / invalid)
  - P7    dial_cag_tcp_tls handshake flow (mocked socket + ssl)
"""
import os
import socket
import ssl
import struct
import unittest
from unittest import mock

from cmcc_cloud_alive.zte_connect_params import (
    ConnectParams, InnerConnectParams, inner_from_connect_params,
)
from cmcc_cloud_alive.zte_route import ZTEFirmAuth, OuterCAGTarget, outer_from_firm
from cmcc_cloud_alive.product_router import redacted_firm_auth_summary
from cmcc_cloud_alive.zte_cag import (
    CAGDialOptions, CAGSessionInfo,
    build_cag_auth_head_packet, build_cag_auth_blob, parse_auth_template,
    dial_cag_tcp_tls,
)


# ---------------------------------------------------------------------------
# P6-001 / P6-003 : OuterCAGTarget
# ---------------------------------------------------------------------------

class OuterCAGTargetTests(unittest.TestCase):
    def test_frozen_contract(self):
        t = OuterCAGTarget(cag_ip="111.31.165.10", cag_port=443)
        self.assertEqual(t.cag_ip, "111.31.165.10")
        self.assertEqual(t.cag_port, 443)
        with self.assertRaises(Exception):
            t.cag_ip = "x"  # frozen

    def test_address_property(self):
        t = OuterCAGTarget(cag_ip="111.31.165.10", cag_port=443)
        self.assertEqual(t.address, "111.31.165.10:443")

    def test_outer_from_firm_extracts_cag(self):
        firm = ZTEFirmAuth(vm_user_name="u", vm_password="p",
                           vm_id="v", vmc_ip="1.1.1.1", vmc_port=8000,
                           cag_ip="111.31.165.10", cag_port=443)
        outer = outer_from_firm(firm)
        self.assertEqual(outer.cag_ip, "111.31.165.10")
        self.assertEqual(outer.cag_port, 443)


# ---------------------------------------------------------------------------
# P6-002 : InnerConnectParams
# ---------------------------------------------------------------------------

class InnerConnectParamsTests(unittest.TestCase):
    VMID = "11111111-2222-3333-4444-555555555555"

    def _cp(self, **kw):
        cp = ConnectParams()
        cp.host = "10.0.0.1"
        cp.port = 10072
        cp.key = "abc123"
        cp.vm_id = self.VMID
        cp.access_token = "tok"
        cp.proxy_sport = 5100
        cp.vm_ip = "10.0.0.1"
        for k, v in kw.items():
            setattr(cp, k, v)
        return cp

    def test_frozen_contract(self):
        icp = InnerConnectParams(host="10.0.0.1", port=10072, key="abc123",
                                 vm_id=self.VMID, access_token="tok",
                                 proxy_sport=5100, vm_ip="10.0.0.1")
        self.assertEqual(icp.host, "10.0.0.1")
        self.assertEqual(icp.proxy_sport, 5100)
        with self.assertRaises(Exception):
            icp.host = "x"  # frozen

    def test_inner_from_connect_params(self):
        cp = self._cp()
        icp = inner_from_connect_params(cp)
        self.assertEqual(icp.host, "10.0.0.1")
        self.assertEqual(icp.port, 10072)
        self.assertEqual(icp.key, "abc123")
        self.assertEqual(icp.vm_id, self.VMID)
        self.assertEqual(icp.access_token, "tok")
        self.assertEqual(icp.proxy_sport, 5100)
        self.assertEqual(icp.vm_ip, "10.0.0.1")


# ---------------------------------------------------------------------------
# P7 : build_cag_auth_head_packet  (cag.go buildCAGAuthHeadPacket)
# ---------------------------------------------------------------------------

class BuildCAGAuthHeadPacketTests(unittest.TestCase):
    def test_packet_length_and_header(self):
        packet, syn_id = build_cag_auth_head_packet()
        self.assertEqual(len(packet), 199)
        self.assertEqual(packet[0:4], b"\x06\x00\x00\x80")

    def test_syn_id_is_packet_slice(self):
        packet, syn_id = build_cag_auth_head_packet()
        self.assertEqual(len(syn_id), 4)
        self.assertEqual(bytes(syn_id), packet[11:15])

    def test_payload_layout(self):
        packet, _ = build_cag_auth_head_packet()
        payload = packet[21:]
        self.assertEqual(len(payload), 178)
        self.assertEqual(payload[0:4], b"ZTEC")
        self.assertEqual(struct.unpack_from("<H", payload, 4)[0], 0x00ac)
        self.assertEqual(struct.unpack_from("<I", payload, 6)[0], 101)
        self.assertEqual(payload[14:18], b"\xdc\x00\x00\x00")
        self.assertEqual(payload[38:42], b"\x07\x00\x0b\x0b")

    def test_random_regions_nonzero(self):
        # call many times; random regions must (almost surely) be nonzero
        for _ in range(20):
            packet, _ = build_cag_auth_head_packet()
            payload = packet[21:]
            self.assertTrue(any(payload[10:14]))
            self.assertTrue(any(payload[18:38]))

    def test_ascii_hex_regions(self):
        packet, _ = build_cag_auth_head_packet()
        payload = packet[21:]
        seg1 = payload[54:86]
        seg2 = payload[118:134]
        self.assertEqual(len(seg1), 32)
        self.assertEqual(len(seg2), 16)
        # all chars must be lowercase hex [0-9a-f]
        hexset = set(b"0123456789abcdef")
        self.assertTrue(set(seg1).issubset(hexset))
        self.assertTrue(set(seg2).issubset(hexset))

    def test_two_calls_differ(self):
        p1, _ = build_cag_auth_head_packet()
        p2, _ = build_cag_auth_head_packet()
        # random regions differ (syn_id at [11:15] almost surely differs)
        self.assertNotEqual(p1[11:15], p2[15:19])


# ---------------------------------------------------------------------------
# P7 : build_cag_auth_blob  (cag.go buildCAGAuthBlob)
# ---------------------------------------------------------------------------

class BuildCAGAuthBlobTests(unittest.TestCase):
    VMID = "11111111-2222-3333-4444-555555555555"

    def _inner(self, **kw):
        base = dict(host="10.0.0.1", port=10072, key="abc123",
                    vm_id=self.VMID, access_token="tok",
                    proxy_sport=5100, vm_ip="10.0.0.1")
        base.update(kw)
        return InnerConnectParams(**base)

    def test_scratch_length_and_fields(self):
        blob = build_cag_auth_blob(self._inner(), None)
        self.assertEqual(len(blob), 220)
        self.assertEqual(struct.unpack_from("<I", blob, 0)[0], 5100)
        self.assertEqual(blob[4:8], socket.inet_aton("10.0.0.1"))
        self.assertEqual(blob[20:56], self.VMID.encode("ascii"))
        self.assertEqual(blob[188], 0x50)

    def test_scratch_random_region(self):
        blob = build_cag_auth_blob(self._inner(), None)
        self.assertTrue(any(blob[60:188]))

    def test_template_220_overwrites_vmid(self):
        tmpl = bytearray(220)
        tmpl[20:56] = b"z" * 36
        blob = build_cag_auth_blob(self._inner(), bytes(tmpl))
        self.assertEqual(len(blob), 220)
        self.assertEqual(blob[20:56], self.VMID.encode("ascii"))

    def test_template_241_strips_head(self):
        tmpl = bytearray(241)
        tmpl[0] = 0x08
        tmpl[21] = 0xcd
        blob = build_cag_auth_blob(self._inner(), bytes(tmpl))
        self.assertEqual(len(blob), 220)
        self.assertEqual(blob[0], 0xcd)  # head stripped
        self.assertEqual(blob[20:56], self.VMID.encode("ascii"))

    def test_invalid_template_length_rejected(self):
        with self.assertRaises(ValueError):
            build_cag_auth_blob(self._inner(), b"\x00" * 100)

    def test_scratch_requires_ipv4(self):
        with self.assertRaises(ValueError):
            build_cag_auth_blob(self._inner(host="not.an.ip"), None)

    def test_scratch_requires_proxy_sport(self):
        with self.assertRaises(ValueError):
            build_cag_auth_blob(self._inner(proxy_sport=0), None)

    def test_scratch_requires_36_vmid(self):
        with self.assertRaises(ValueError):
            build_cag_auth_blob(self._inner(vm_id="short"), None)


# ---------------------------------------------------------------------------
# P7 : parse_auth_template  (cag.go parseAuthTemplate)
# ---------------------------------------------------------------------------

class ParseAuthTemplateTests(unittest.TestCase):
    def test_empty_returns_none(self):
        self.assertIsNone(parse_auth_template(""))

    def test_220_bytes(self):
        raw = b"\xab" * 220
        out = parse_auth_template(raw.hex())
        self.assertEqual(len(out), 220)
        self.assertEqual(out, raw)

    def test_241_with_08_prefix(self):
        raw = b"\x08" + b"\xcd" * 240
        out = parse_auth_template(raw.hex())
        self.assertEqual(len(out), 241)
        self.assertEqual(out, raw)

    def test_invalid_length_rejected(self):
        with self.assertRaises(ValueError):
            parse_auth_template(("ab" * 100))

    def test_241_without_08_prefix_rejected(self):
        raw = b"\x09" + b"\xcd" * 240
        with self.assertRaises(ValueError):
            parse_auth_template(raw.hex())


# ---------------------------------------------------------------------------
# P7 : dial_cag_tcp_tls  (cag_tcp.go DialCAGTCPTLS) — mocked flow
# ---------------------------------------------------------------------------

class _FakeSock:
    """Minimal socket double: returns canned recv data, records sends."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.sent = bytearray()
        self._closed = False

    def settimeout(self, t):
        pass

    def sendall(self, data):
        self.sent.extend(data)

    def recv(self, n):
        if not self._responses:
            return b""
        chunk = self._responses.pop(0)
        return chunk[:n]

    def close(self):
        self._closed = True

    def fileno(self):
        return -1


def _make_head_ack(conv=0x12345678):
    ack = bytearray(50)
    ack[0:4] = b"ZTEC"
    struct.pack_into("<I", ack, 14, conv)
    return bytes(ack)


def _make_auth_ack(ok=True):
    ack = bytearray(36)
    ack[4] = 0x01 if ok else 0x00
    return bytes(ack)


class DialCAGTCPTLSTests(unittest.TestCase):
    VMID = "11111111-2222-3333-4444-555555555555"

    def _inner(self):
        return InnerConnectParams(host="10.0.0.1", port=10072, key="abc123",
                                  vm_id=self.VMID, access_token="tok",
                                  proxy_sport=5100, vm_ip="10.0.0.1")

    def _opts(self, **kw):
        base = dict(address="111.31.165.10:443", inner=self._inner(),
                    auth_template_hex="", timeout=5.0)
        base.update(kw)
        return CAGDialOptions(**base)

    def test_missing_inner_raises(self):
        opts = CAGDialOptions(address="1.2.3.4:443", inner=None)
        with self.assertRaises(ValueError):
            dial_cag_tcp_tls(opts)

    def test_missing_address_raises(self):
        opts = CAGDialOptions(address="", inner=self._inner())
        with self.assertRaises(ValueError):
            dial_cag_tcp_tls(opts)

    def test_full_handshake_success(self):
        fake = _FakeSock([_make_head_ack(0xdeadbeef), _make_auth_ack(True)])
        fake_tls = mock.MagicMock(spec=ssl.SSLSocket)
        with mock.patch("cmcc_cloud_alive.zte_cag.socket.create_connection",
                        return_value=fake) as m_conn, \
             mock.patch("cmcc_cloud_alive.zte_cag.ssl.SSLContext") as m_ctx:
            m_ctx.return_value.wrap_socket.return_value = fake_tls
            tls, info = dial_cag_tcp_tls(self._opts())
        self.assertIs(tls, fake_tls)
        self.assertEqual(info.conv, 0xdeadbeef)
        # two packets sent: 178-byte head + 220-byte blob
        self.assertEqual(len(fake.sent), 178 + 220)
        self.assertEqual(len(fake.sent[:178]), 178)
        self.assertEqual(fake.sent[:178][:4], b"ZTEC")
        m_conn.assert_called_once()

    def test_invalid_head_ack_raises(self):
        fake = _FakeSock([b"\x00" * 50, _make_auth_ack(True)])
        with mock.patch("cmcc_cloud_alive.zte_cag.socket.create_connection",
                        return_value=fake), \
             mock.patch("cmcc_cloud_alive.zte_cag.ssl.SSLContext"):
            with self.assertRaises(ValueError):
                dial_cag_tcp_tls(self._opts())

    def test_auth_rejected_raises(self):
        fake = _FakeSock([_make_head_ack(), _make_auth_ack(False)])
        with mock.patch("cmcc_cloud_alive.zte_cag.socket.create_connection",
                        return_value=fake), \
             mock.patch("cmcc_cloud_alive.zte_cag.ssl.SSLContext"):
            with self.assertRaises(ValueError):
                dial_cag_tcp_tls(self._opts())

    def test_short_head_ack_raises(self):
        # server closes early -> EOFError on read
        fake = _FakeSock([b"\x00" * 10])
        with mock.patch("cmcc_cloud_alive.zte_cag.socket.create_connection",
                        return_value=fake), \
             mock.patch("cmcc_cloud_alive.zte_cag.ssl.SSLContext"):
            with self.assertRaises((EOFError, ValueError)):
                dial_cag_tcp_tls(self._opts())


class RedactedSummaryTests(unittest.TestCase):
    """P6-006: route report shows outer/inner present, never the values."""

    def _auth(self):
        return {
            "spuCode": "SPU001",
            "vmType": "zte",
            "scAuthCode": "super-secret-sc-code",
            "vmUserName": "admin",
            "vmPassword": "p@ssw0rd",
            "vmId": "11111111-2222-3333-4444-555555555555",
            "vmcIp": "10.1.2.3",
            "vmcPort": "8000",
            "cagIp": "111.31.165.10",
            "cagPort": "443",
            "connectStr": "deadbeef-encrypted-connect-string",
            "accessToken": "tok-xyz",
        }

    def test_outer_inner_present_are_booleans(self):
        s = redacted_firm_auth_summary(self._auth())
        self.assertIs(s["outerPresent"], True)
        self.assertIs(s["innerPresent"], True)

    def test_outer_absent_when_cag_missing(self):
        a = self._auth()
        a["cagIp"] = ""
        s = redacted_firm_auth_summary(a)
        self.assertIs(s["outerPresent"], False)

    def test_inner_absent_when_connectstr_missing(self):
        a = self._auth()
        del a["connectStr"]
        s = redacted_firm_auth_summary(a)
        self.assertIs(s["innerPresent"], False)

    def test_no_sensitive_values_leaked(self):
        import json
        a = self._auth()
        s = redacted_firm_auth_summary(a)
        blob = json.dumps(s)
        for secret in ("super-secret-sc-code", "p@ssw0rd",
                       "deadbeef-encrypted-connect-string", "tok-xyz",
                       "111.31.165.10"):
            self.assertNotIn(secret, blob,
                             "sensitive value leaked into redacted summary: %s" % secret)


if __name__ == "__main__":
    unittest.main()
