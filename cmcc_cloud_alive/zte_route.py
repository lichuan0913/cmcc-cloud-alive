#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pure-Python port of B's internal/zte/client.go (line-by-line fork).

ZTE material control plane: once product_router decides route==ZTE, this
module talks to the CAG HTTPS endpoint (firm cagIp:cagPort) to obtain an
access token, list desktops, start the target desktop (畅享版月包 vmId) and
parse the SPICE connect string.

All HTTP goes to https://<cagIp>:<cagPort>/<path> with Content-Type
application/xml; request bodies are JSON-encoded (B's encodeRequestBody),
responses are AES-CBC security envelopes decoded by zte_security.
"""

import json
import os
import ssl
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .zte_security import (
    decode_security_json,
    encode_vdi_password,
)

# --- constants (mirror Go client.go) ---------------------------------------

CLIENT_VERSION = "V7.24.11"
REQUEST_FROM = "2"
DEFAULT_MAC = "8C-04-BA-9C-C2-E7"
DEFAULT_IP = "192.168.1.165"
DEFAULT_HOST = "wangpeng-pc"
DEFAULT_U_STR = "31BF5444-86E0-4D5D-B1AB-A42FFBAC72C9"

# Target desktop (畅享版月包) — only this vmId is ever started.
TARGET_VM_ID = os.environ.get(
    "CMCC_ZTE_TARGET_VMID", "163c68a9-5e1e-4cba-b9bb-68ad599a8abf"
)


# --- dataclasses -----------------------------------------------------------

@dataclass
class ZTEFirmAuth:
    """Mirror of Go FirmAuth struct (client.go:27)."""
    vm_user_name: str = ""
    vm_password: str = ""
    vm_id: str = ""
    vmc_ip: str = ""
    vmc_port: int = 0
    cag_ip: str = ""
    cag_port: int = 0

    @classmethod
    def from_auth_dict(cls, auth: Dict[str, Any]) -> "ZTEFirmAuth":
        """Build from the raw getFirmAuth data dict (multi-key tolerant)."""
        vm_id = auth.get("vmId") or auth.get("vmID") or auth.get("uuid") or ""
        return cls(
            vm_user_name=auth.get("vmUserName") or "",
            vm_password=auth.get("vmPassword") or "",
            vm_id=vm_id,
            vmc_ip=auth.get("vmcIp") or auth.get("vmcIP") or "",
            vmc_port=_int_value(auth.get("vmcPort") or auth.get("vmcPORT")),
            cag_ip=auth.get("cagIp") or auth.get("cagIP") or "",
            cag_port=_int_value(auth.get("cagPort") or auth.get("cagPORT")),
        )


# --- P6: outer/inner strict separation -------------------------------------
#
# ``OuterCAGTarget`` carries ONLY the *outer* firm CAG endpoint (cagIp:cagPort).
# It is the sole argument the CAG transport dial (zte_cag.dial_cag_tcp_tls)
# accepts — never the inner desktop host/port.  This is the counterpart of
# ``InnerConnectParams`` (zte_connect_params); together they enforce that the
# outer CAG socket and the inner SPICE link cannot be cross-wired.
@dataclass(frozen=True)
class OuterCAGTarget:
    cag_ip: str
    cag_port: int

    def __repr__(self):
        return "OuterCAGTarget(cag_ip=%r, cag_port=%d)" % (self.cag_ip, self.cag_port)

    @property
    def address(self) -> str:
        """``host:port`` string suitable for socket.connect()."""
        return "%s:%d" % (self.cag_ip, self.cag_port)


def outer_from_firm(firm: ZTEFirmAuth) -> OuterCAGTarget:
    """Build the frozen outer target from a ZTEFirmAuth (P6-001)."""
    return OuterCAGTarget(cag_ip=firm.cag_ip, cag_port=firm.cag_port)


@dataclass
class TokenInfo:
    """Mirror of Go TokenInfo struct (client.go:44)."""
    access_token: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MaterialReport:
    """Redacted material-plane report (P5-017)."""
    stage: str = ""
    ok: bool = False
    error: str = ""
    next_step: str = ""
    has_token: bool = False
    desktop_count: int = 0
    target_desktop_found: bool = False
    has_connect_str: bool = False
    # never include raw connectStr / key / password / token values
    redacted: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "route": "zte",
            "stage": self.stage,
            "ok": self.ok,
            "error": self.error,
            "nextStep": self.next_step,
            "hasToken": self.has_token,
            "desktopCount": self.desktop_count,
            "targetDesktopFound": self.target_desktop_found,
            "hasConnectStr": self.has_connect_str,
        }


# --- helpers (mirror Go client.go helpers) ---------------------------------

def _int_value(v: Any) -> int:
    return _int_value_default(v, 0)


def _int_value_default(v: Any, default: int) -> int:
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(v)
    if isinstance(v, str):
        try:
            return int(v)
        except ValueError:
            return default
    return default


def _string_value(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    return str(v)


def _new_uuid() -> str:
    """Mirror of Go newUUID (RFC 4122 v4)."""
    b = os.urandom(16)
    ba = bytearray(b)
    ba[6] = (ba[6] & 0x0F) | 0x40
    ba[8] = (ba[8] & 0x3F) | 0x80
    return "%08x-%04x-%04x-%04x-%012x" % (
        int.from_bytes(ba[0:4], "big"),
        int.from_bytes(ba[4:6], "big"),
        int.from_bytes(ba[6:8], "big"),
        int.from_bytes(ba[8:10], "big"),
        int.from_bytes(ba[10:16], "big"),
    )


def _encode_query(values: List[Dict[str, str]]) -> str:
    """Mirror of Go encodeQuery: hostName gets '-' -> '%2D' after escape."""
    if not values:
        return ""
    parts = []
    for item in values:
        value = urllib.parse.quote_plus(item["value"])
        if item["key"] == "hostName":
            value = value.replace("-", "%2D")
        parts.append(urllib.parse.quote_plus(item["key"]) + "=" + value)
    return "&".join(parts)


def _encode_request_body(body: Any) -> str:
    """Mirror of Go encodeRequestBody."""
    if body is None:
        return ""
    if isinstance(body, str):
        return body
    if isinstance(body, (bytes, bytearray)):
        return body.decode("utf-8", "replace")
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False)


def _compact_json(v: Any) -> str:
    try:
        return json.dumps(v, separators=(",", ":"), ensure_ascii=False).strip()
    except (TypeError, ValueError):
        return str(v)


def first_desktop(list_obj: Dict[str, Any], vm_id: str) -> Optional[Dict[str, Any]]:
    """Mirror of Go FirstDesktop (client.go:279): strict vmId match.

    If vm_id is empty, returns the first desktop; otherwise returns the first
    desktop whose vmId equals vm_id, or None. Non-target vmIds are skipped.
    """
    desktops = list_obj.get("desktopList")
    if not isinstance(desktops, list):
        return None
    for item in desktops:
        desktop = item if isinstance(item, dict) else None
        if desktop is None:
            continue
        if vm_id == "" or _string_value(desktop.get("vmId")) == vm_id:
            return desktop
    return None


# --- CAG HTTPS client ------------------------------------------------------

class ZTEClient:
    """Mirror of Go Client (client.go:37)."""

    def __init__(self, firm: ZTEFirmAuth, timeout: float = 30.0):
        self.firm = firm
        self.terminal_uuid = _new_uuid()
        self.serial_number = _new_uuid()
        self.timeout = timeout
        # ZTE CAG uses bundled client trust store -> skip verify (Go InsecureSkipVerify).
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    # -- request core (client.go:158) --

    def _request(self, path: str, values: List[Dict[str, str]],
                 body: Any) -> Dict[str, Any]:
        query = _encode_query(values)
        req_url = "https://%s:%d%s" % (self.firm.cag_ip, self.firm.cag_port, path)
        if query:
            req_url += "?" + query

        encrypted_body = _encode_request_body(body)
        data = encrypted_body.encode("utf-8") if encrypted_body else None
        req = urllib.request.Request(req_url, data=data, method="POST")
        self._set_headers(req)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=self._ssl_ctx) as resp:
                resp_body = resp.read()
                status = resp.getcode()
        except urllib.error.HTTPError as err:
            err_body = err.read() if hasattr(err, "read") else b""
            raise ZTEError("zte %s failed: status=%d body=%s"
                           % (path, err.code, err_body.decode("utf-8", "replace"))) from err
        except urllib.error.URLError as err:
            raise ZTEError("zte %s network failed: %s" % (path, err.reason)) from err
        except TimeoutError as err:
            raise ZTEError("zte %s timed out" % path) from err
        except OSError as err:
            raise ZTEError("zte %s socket failed: %s" % (path, err)) from err

        if status < 200 or status >= 300:
            raise ZTEError("zte %s failed: status=%d body=%s"
                           % (path, status, resp_body.decode("utf-8", "replace")))

        try:
            result = decode_security_json(resp_body)
        except Exception as err:
            raise ZTEError("zte %s: %s" % (path, err)) from err

        if not result.get("success"):
            raise ZTEError("zte %s failed: %s" % (path, _compact_json(result)))
        return result

    def _set_headers(self, req: urllib.request.Request) -> None:
        """Mirror of Go setHeaders (client.go:216)."""
        req.add_header("Content-Type", "application/xml")
        req.add_header("Accept", "*/*")

    def _serial_number(self) -> str:
        return self.serial_number if self.serial_number else DEFAULT_U_STR

    # -- API methods --

    def sys_config(self) -> Dict[str, Any]:
        """Mirror of Go SysConfig (client.go:74)."""
        values = [
            {"key": "version", "value": CLIENT_VERSION},
            {"key": "language", "value": "zh"},
            {"key": "requestFrom", "value": REQUEST_FROM},
            {"key": "name", "value": self.firm.vm_user_name},
            {"key": "RspSecurity", "value": "1"},
        ]
        return self._request("/cs/cs_sysConfig.action", values, "")

    def get_access_token(self) -> TokenInfo:
        """Mirror of Go GetAccessToken (client.go:85)."""
        f = self.firm
        password = encode_vdi_password(f.vm_password)
        values = [
            {"key": "username", "value": f.vm_user_name},
            {"key": "password", "value": password},
            {"key": "version", "value": CLIENT_VERSION},
            {"key": "language", "value": "zh"},
            {"key": "clientId", "value": ""},
            {"key": "encrypt", "value": "4"},
            {"key": "token", "value": ""},
            {"key": "requestFrom", "value": REQUEST_FROM},
            {"key": "mac", "value": DEFAULT_MAC},
            {"key": "clientIp", "value": DEFAULT_IP},
            {"key": "hostName", "value": DEFAULT_HOST},
            {"key": "newVersionCtrl", "value": "1"},
            {"key": "netflags", "value": "1"},
            {"key": "unityType", "value": "1"},
            {"key": "isvm", "value": "0"},
            {"key": "RspSecurity", "value": "1"},
        ]
        body = {"clienttype": 0, "hardware": 4, "nettype": 2, "ostype": 1}
        result = self._request("/cs/cs_getToken.action", values, body)
        token = result.get("accessToken")
        if not isinstance(token, str) or token == "":
            raise ZTEError("missing accessToken in response: %s" % _compact_json(result))
        return TokenInfo(access_token=token, raw=result)

    def get_desktop_list(self, access_token: str) -> Dict[str, Any]:
        """Mirror of Go GetDesktopList (client.go:126)."""
        values = [
            {"key": "accessToken", "value": access_token},
            {"key": "type", "value": "7"},
            {"key": "version", "value": CLIENT_VERSION},
            {"key": "language", "value": "zh"},
            {"key": "clientIp", "value": DEFAULT_IP},
            {"key": "requestFrom", "value": REQUEST_FROM},
            {"key": "isvm", "value": "0"},
            {"key": "RspSecurity", "value": "1"},
        ]
        return self._request("/cs/cs_getDesktopList.action", values, "")

    def _start_desktop_body(self, access_token: str,
                            desktop: Dict[str, Any]) -> Dict[str, Any]:
        """Mirror of Go startDesktopBody (client.go:221)."""
        user_id = _int_value(desktop.get("userId"))
        group_id = _int_value(desktop.get("groupId"))
        pool_id = _int_value(desktop.get("poolId"))
        assign_relation = "%d,%d,%d" % (user_id, group_id, pool_id)
        if user_id == 0 and group_id == 0 and pool_id == 0:
            assign_relation = ""
        return {
            "RspSecurity": 1,
            "SNcode": self._serial_number(),
            "accessToken": access_token,
            "allowExtUSBPolicy": 1,
            "allowSwitchRap": 1,
            "assignRelationtoString": assign_relation,
            "connectionType": _int_value_default(desktop.get("connectionType"), 0),
            "diskNo": "2250008001546",
            "encryption": 1,
            "hostName": DEFAULT_HOST,
            "isvm": 0,
            "language": "zh",
            "localipandmac": DEFAULT_IP + "," + DEFAULT_MAC,
            "netType": 2,
            "newcharsetparse": 1,
            "newpara": 1,
            "prover": 1,
            "raptype": 2,
            "requestFrom": _int_value_default(REQUEST_FROM, 2),
            "supportAsync": 1,
            "supportCustomConfig": "00000000000000000000000000000011",
            "type": _int_value_default(desktop.get("desktopType"), 1),
            "upmnew": 1,
            "uuid": _string_value(desktop.get("uuid")),
            "verifyTerminalBind": "11",
            "version": CLIENT_VERSION,
            "vmid": self.firm.vm_id,
            "watermarkType": 1,
        }

    def start_desktop(self, access_token: str,
                      desktop: Dict[str, Any]) -> Dict[str, Any]:
        """Mirror of Go StartDesktop (client.go:140)."""
        body = self._start_desktop_body(access_token, desktop)
        return self._request("/cs/cs_startDesktop.action", [], body)

    def start_desktop_async_query(self, access_token: str) -> Dict[str, Any]:
        """Mirror of Go StartDesktopAsyncQuery (client.go:145)."""
        values = [
            {"key": "accessToken", "value": access_token},
            {"key": "language", "value": "zh"},
            {"key": "isvm", "value": "0"},
            {"key": "vmid", "value": self.firm.vm_id},
            {"key": "RspSecurity", "value": "1"},
            {"key": "prover", "value": "1"},
            {"key": "allowSwitchRap", "value": "1"},
        ]
        return self._request("/cs/cs_startDesktop_async_query.action", values, "")


class ZTEError(Exception):
    """Raised when a ZTE CAG control-plane call fails."""


# --- orchestration (P5-011 async query loop) -------------------------------

def run_material(firm: ZTEFirmAuth, *, target_vm_id: str = TARGET_VM_ID,
                 async_retries: int = 30, async_interval: float = 2.0,
                 do_start: bool = True) -> MaterialReport:
    """Run the full ZTE material control-plane sequence and return a redacted report.

    Stages: zte_sys_config -> zte_get_token -> zte_get_desktop_list ->
    zte_start_desktop -> zte_async_query (connectStr).
    """
    report = MaterialReport()
    client = ZTEClient(firm)
    try:
        report.stage = "zte_sys_config"
        client.sys_config()

        report.stage = "zte_get_token"
        token_info = client.get_access_token()
        report.has_token = bool(token_info.access_token)

        report.stage = "zte_get_desktop_list"
        desktop_list = client.get_desktop_list(token_info.access_token)
        desktops = desktop_list.get("desktopList")
        report.desktop_count = len(desktops) if isinstance(desktops, list) else 0

        desktop = first_desktop(desktop_list, target_vm_id)
        report.target_desktop_found = desktop is not None
        if desktop is None:
            report.error = "target vmId %s not found in desktopList" % target_vm_id
            report.next_step = "check vmId / account binding"
            return report

        if do_start:
            report.stage = "zte_start_desktop"
            start_result = client.start_desktop(token_info.access_token, desktop)
            connect_str = _string_value(start_result.get("connectStr"))

            if not connect_str:
                report.stage = "zte_async_query"
                connect_str = _async_query_connect_str(
                    client, token_info.access_token,
                    retries=async_retries, interval=async_interval)

            report.has_connect_str = bool(connect_str)
            if not connect_str:
                report.error = "connectStr empty after start + async query"
                report.next_step = "retry start or inspect desktop state"
                return report

        report.ok = True
        report.stage = "zte_material_done"
        report.next_step = "P6/P7: dial outer CAG, build inner SPICE link"
        return report
    except ZTEError as err:
        report.error = str(err)
        report.next_step = "inspect stage %s response" % report.stage
        return report
    except Exception as err:  # noqa: BLE001 - surface any unexpected failure
        report.error = "%s: %s" % (type(err).__name__, err)
        report.next_step = "inspect stage %s" % report.stage
        return report


def _async_query_connect_str(client: ZTEClient, access_token: str, *,
                             retries: int = 30, interval: float = 2.0) -> str:
    """Poll cs_startDesktop_async_query until connectStr appears (P5-011)."""
    import time
    for _ in range(retries):
        result = client.start_desktop_async_query(access_token)
        connect_str = _string_value(result.get("connectStr"))
        if connect_str:
            return connect_str
        time.sleep(interval)
    return ""
