"""Legacy HTTP workflow retained for negative-evidence tests.

The active keepalive target is RAP/ZIME/SPICE. This module remains only so old
tests and explicit research commands can reproduce rejected HTTP behavior.
"""

import time

from . import account_keepalive, cag_boot, cloud, core, desktop_keepalive, token


def _status_summary(item):
    return {
        "vmStatus": item.get("vmStatus"),
        "vmStatusShow": item.get("vmStatusShow"),
        "running": cloud.is_running(item),
        "off": cloud.is_off(item),
    }


def ensure_desktop_running(user_service_id=None, state_path=None, boot_if_off=True, boot_wait=180, boot_timeout=15):
    target = cloud.selected_user_service_id(state_path, user_service_id)
    item = cloud.status(target, state_path)
    if cloud.is_running(item):
        return {
            "userServiceId": str(target),
            "booted": False,
            "alreadyRunning": True,
            "status": _status_summary(item),
            "bootReport": None,
        }
    if not boot_if_off:
        return {
            "userServiceId": str(target),
            "booted": False,
            "alreadyRunning": False,
            "status": _status_summary(item),
            "bootReport": None,
        }
    boot_result = cag_boot.ensure_running(
        target,
        state_path=state_path,
        boot_wait=boot_wait,
        timeout=boot_timeout,
    )
    return {
        "userServiceId": str(target),
        "booted": not bool(boot_result.get("alreadyRunning")),
        "alreadyRunning": bool(boot_result.get("alreadyRunning")),
        "status": _status_summary(boot_result.get("status") or {}),
        "bootReport": boot_result.get("bootReport"),
    }


def run(
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
):
    """Run the legacy HTTP lifecycle for controlled negative-evidence tests."""
    target = cloud.selected_user_service_id(state_path, user_service_id)
    started = time.time()
    next_account_refresh = started + max(1, int(account_relogin_hours * 3600)) if account_relogin_hours else float("inf")
    next_token_check = started
    cycle = 0
    final_result = {
        "accepted": False,
        "desktopKeepaliveProven": False,
        "experimental": True,
        "userServiceId": str(target),
    }

    while True:
        now = time.time()
        if run_seconds and now - started >= run_seconds:
            return final_result

        if token_check_interval and now >= next_token_check:
            token.ensure_token(state_path, relogin=True)
            next_token_check = now + max(1, int(token_check_interval))

        if account_relogin_hours and now >= next_account_refresh:
            account_keepalive.refresh_once(state_path)
            next_account_refresh = now + max(1, int(account_relogin_hours * 3600))

        boot_state = ensure_desktop_running(
            target,
            state_path=state_path,
            boot_if_off=boot_if_off,
            boot_wait=boot_wait,
            boot_timeout=boot_timeout,
        )
        if not boot_state["status"].get("running"):
            if boot_state.get("booted"):
                raise core.CmccError("desktop is not running after CAG boot attempt", response=boot_state)
            raise core.CmccError("desktop is not running and boot is disabled", response=boot_state)

        cycle += 1
        elapsed = int(time.time() - started)
        print(
            f"[{core.short_time()}] [cycle {cycle}] HTTP主流程: {core.format_duration(elapsed)} "
            f"status={boot_state['status'].get('vmStatusShow')} booted={boot_state['booted']}",
            flush=True,
        )

        remaining = None
        if run_seconds:
            remaining = max(1, int(run_seconds - (time.time() - started)))
        if cycle_interval <= 0:
            burst_seconds = remaining or 0
        else:
            burst_seconds = min(max(1, int(cycle_duration)), remaining) if remaining else max(1, int(cycle_duration))

        final_result = desktop_keepalive.run_official_http_loop(
            target,
            state_path=state_path,
            run_seconds=burst_seconds,
            heartbeat_interval=heartbeat_interval,
            info_interval=info_interval,
            log_config_interval=log_config_interval,
            status_interval=status_interval,
            token_check_interval=0,
            relogin_on_token_expired=False,
        )

        if run_seconds and time.time() - started >= run_seconds:
            return final_result
        if cycle_interval <= 0:
            return final_result

        cycle_elapsed = time.time() - now
        sleep_seconds = max(1, int(cycle_interval - cycle_elapsed))
        time.sleep(sleep_seconds)
