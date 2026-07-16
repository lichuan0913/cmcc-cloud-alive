"""Keepalive strategy selection.

The HTTP timer and CAG HTTPS routes are retained only as evidence/research
tools. The active implementation target is the native RAP/ZIME/SPICE display
protocol route described by the Codming analysis.
"""

from . import core


HTTP_TIMERS = "http-timers"
CAG_HTTPS = "cag-https"
SPICE = "spice"

STRATEGIES = {
    HTTP_TIMERS: {
        "label": "rejected visible official SOHO HTTP timers",
        "desktopKeepaliveProven": False,
        "sessionOwning": False,
        "risk": "rejected_by_power_state_tests",
    },
    CAG_HTTPS: {
        "label": "rejected CAG HTTPS connect-material refresh",
        "desktopKeepaliveProven": False,
        "sessionOwning": True,
        "risk": "rejected_by_power_state_tests_and_session_takeover",
    },
    SPICE: {
        "label": "RAP/ZIME/SPICE display protocol keepalive",
        "desktopKeepaliveProven": False,
        "sessionOwning": True,
        "risk": "active_target_not_implemented",
    },
}


def describe(name):
    if name not in STRATEGIES:
        raise core.CmccError(f"unknown keepalive strategy: {name}")
    result = dict(STRATEGIES[name])
    result["name"] = name
    return result


def run(
    strategy,
    user_service_id=None,
    state_path=None,
    run_seconds=0,
    cycle_interval=300,
    cycle_duration=60,
    heartbeat_interval=30,
    info_interval=121,
    log_config_interval=120,
    status_interval=300,
    token_check_interval=300,
    account_relogin_hours=24,
    boot_if_off=True,
    boot_wait=180,
    boot_timeout=15,
    cag_interval=60,
    allow_session_takeover=False,
):
    """Run a named keepalive strategy."""
    selected = strategy
    if selected == "auto":
        selected = SPICE

    info = describe(selected)
    print(
        f"[{core.short_time()}] keepalive strategy={selected} "
        f"risk={info['risk']} sessionOwning={info['sessionOwning']}",
        flush=True,
    )

    if selected == HTTP_TIMERS:
        raise core.CmccError(
            "http-timers has been rejected as desktop keepalive: accepted "
            "heartbeat/infoReport/logConfig responses did not prevent power-off "
            "in long tests. Use it only through explicit capture/replay research "
            "commands, not as a keepalive strategy."
        )
    elif selected == CAG_HTTPS:
        raise core.CmccError(
            "cag-https has been rejected as a keepalive strategy: it refreshes "
            "boot/connect material, can replace the official desktop session, "
            "and independent monitoring observed shutdown. Keep it only for "
            "boot/material acquisition research."
        )
    elif selected == SPICE:
        raise core.CmccError(
            "spice protocol keepalive is the active target but is not implemented "
            "yet. Next required step: capture and reproduce the family Linux "
            "RAP/ZIME/SPICE display channel through the native client, then prove "
            "DISPLAY_INIT + ACK/PONG keeps power state running with an independent "
            "per-minute monitor."
        )
    else:
        raise core.CmccError(f"unknown keepalive strategy: {strategy}")
