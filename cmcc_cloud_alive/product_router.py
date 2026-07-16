"""Product route classification for the family cloud PC control plane.

Forks B (cloud-computer-keepalive/cmd/keepalive.go) route decision:
  - scAuthCode non-empty  -> SCG route
  - else ZTE fields present (vmUserName/vmPassword/vmId/cagIp/cagPort) -> ZTE route
  - else -> error

This module only judges the route from a firmAuth dict; it never builds live
links (no socket / no TLS). It is the gate that must pass before any live run.
"""

import enum
import json
from dataclasses import dataclass, asdict
from pathlib import Path

from . import cloud, core


class RouteKind(str, enum.Enum):
    SCG = "scg"
    ZTE = "zte"
    ERROR = "error"


@dataclass
class ProductRoute:
    kind: RouteKind
    reason: str
    userServiceId: str = ""
    vmId: str = ""

    def as_dict(self):
        d = asdict(self)
        d["kind"] = self.kind.value
        return d


def _truthy_port(value):
    try:
        return int(value or 0) > 0
    except (TypeError, ValueError):
        return False


def _first(auth, *names):
    """Multi-key extraction: return first truthy value among names."""
    for name in names:
        value = auth.get(name)
        if value not in (None, "", 0):
            return value
    return ""


def extract_sc_auth_code(auth):
    return str(auth.get("scAuthCode") or "")


def extract_zte_fields(auth):
    """Extract ZTE-required fields with multi-key fallbacks.

    Mirrors B keepaliveZTESession FirmAuth struct + the required-fields guard.
    """
    return {
        "vmUserName": str(auth.get("vmUserName") or ""),
        "vmPassword": str(auth.get("vmPassword") or ""),
        "vmId": str(_first(auth, "vmId", "vmID", "uuid") or ""),
        "vmcIp": str(_first(auth, "vmcIp", "vmcIP") or ""),
        "vmcPort": str(_first(auth, "vmcPort", "vmcPORT") or ""),
        "cagIp": str(auth.get("cagIp") or ""),
        "cagPort": str(auth.get("cagPort") or ""),
    }


def zte_fields_complete(zte):
    """B guard: VMUserName/VMPassword/VMID/CAGIP/CAGPort all required."""
    return bool(
        zte["vmUserName"]
        and zte["vmPassword"]
        and zte["vmId"]
        and zte["cagIp"]
        and _truthy_port(zte["cagPort"])
    )


def classify_firm_auth_route(auth):
    """Classify a firmAuth dict into a ProductRoute.

    scAuthCode has priority over ZTE fields (B line 56-63): if scAuthCode is
    non-empty the SCG route is taken regardless of ZTE fields.
    """
    sc_auth_code = extract_sc_auth_code(auth)
    zte = extract_zte_fields(auth)
    if sc_auth_code:
        return ProductRoute(
            kind=RouteKind.SCG,
            reason="scAuthCode present; SCG route (B keepalive.go:56-63)",
            vmId=zte["vmId"],
        )
    if zte_fields_complete(zte):
        return ProductRoute(
            kind=RouteKind.ZTE,
            reason="scAuthCode empty and ZTE fields complete (B keepalive.go:127)",
            vmId=zte["vmId"],
        )
    missing = [k for k in ("vmUserName", "vmPassword", "vmId", "cagIp", "cagPort")
               if not zte.get(k) or (k == "cagPort" and not _truthy_port(zte.get(k)))]
    return ProductRoute(
        kind=RouteKind.ERROR,
        reason=f"no scAuthCode and ZTE fields incomplete: {','.join(missing)}",
        vmId=zte["vmId"],
    )


# Keys that must never appear in a redacted summary.
_SENSITIVE_KEYS = {"token", "password", "connectStr", "vmPassword", "scAuthCode",
                   "accessToken", "bizCode", "connectId"}


def redacted_firm_auth_summary(auth):
    """Presence-only summary; never outputs raw token/password/connectStr.

    P6-006: reports outer (CAG endpoint) / inner (connectStr) presence as
    booleans only — never the values themselves.
    """
    zte = extract_zte_fields(auth)
    outer_present = bool(zte["cagIp"]) and _truthy_port(zte["cagPort"])
    inner_present = bool(auth.get("connectStr") or auth.get("connectStrEnc") or "")
    return {
        "spuCode": auth.get("spuCode") or "",
        "vmType": auth.get("vmType"),
        "scAuthCodePresent": bool(extract_sc_auth_code(auth)),
        "vmIdPresent": bool(zte["vmId"]),
        "vmCredentialPresent": bool(zte["vmUserName"]) and bool(zte["vmPassword"]),
        "vmcEndpointPresent": bool(zte["vmcIp"]) and _truthy_port(zte["vmcPort"]),
        "cagEndpointPresent": outer_present,
        "outerPresent": outer_present,
        "innerPresent": inner_present,
    }


def route_check(user_service_id=None, state_path=None, report_file=None):
    """Run firmAuth once and produce a redacted route report.

    Report schema contains route/stage/ok/error/nextStep (no-spin rule 4).
    """
    stage = "route-check"
    selected = cloud.selected_user_service_id(state_path, user_service_id)
    args = core.argparse.Namespace(state=state_path, user_service_id=selected)
    try:
        auth = core.get_firm_auth(args)
    except Exception as exc:  # noqa: BLE001 - gate must report, not crash
        report = {
            "route": "product-route-check",
            "stage": stage,
            "ok": False,
            "error": str(exc),
            "nextStep": "fix login/account/firmAuth; do not touch protocol",
            "targetProduct": cloud.TARGET_SKU_KEYWORDS[0],
            "targetUserServiceIdPresent": bool(selected),
            "kind": RouteKind.ERROR.value,
            "reason": f"firmAuth failed: {exc}",
            "firmAuthSummary": {},
        }
        if report_file:
            _write_report(report_file, report)
        return report

    route = classify_firm_auth_route(auth)
    route.userServiceId = str(selected or "")
    if not route.vmId:
        route.vmId = str(auth.get("vmId") or auth.get("vmID") or auth.get("uuid") or "")

    next_step = {
        RouteKind.SCG: "proceed to SCG keepalive (cem exchange + scg connect)",
        RouteKind.ZTE: "proceed to ZTE keepalive (sysConfig/token/startDesktop/CAG)",
        RouteKind.ERROR: "stop; fix firmAuth fields before any protocol work",
    }[route.kind]

    report = {
        "route": "product-route-check",
        "stage": stage,
        "ok": route.kind != RouteKind.ERROR,
        "error": "" if route.kind != RouteKind.ERROR else route.reason,
        "nextStep": next_step,
        "targetProduct": cloud.TARGET_SKU_KEYWORDS[0],
        "targetUserServiceIdPresent": bool(selected),
        "kind": route.kind.value,
        "reason": route.reason,
        "userServiceId": route.userServiceId,
        "vmId": route.vmId,
        "firmAuthSummary": redacted_firm_auth_summary(auth),
    }
    if report_file:
        _write_report(report_file, report)
    return report


def _write_report(report_file, report):
    core.write_private_json_report(report, report_file)
