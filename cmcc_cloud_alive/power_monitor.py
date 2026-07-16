"""Independent cloud-PC power-state monitor.

This module deliberately sends no keepalive, boot, CAG, or analytics request.
It only polls the cloud status endpoint so long-running experiments have a
separate proof of whether the desktop actually stayed powered on.
"""

import json
import os
import time
from pathlib import Path

from . import cloud, core, token


def snapshot(user_service_id=None, state_path=None, started=None, index=None):
    target = cloud.selected_user_service_id(state_path, user_service_id)
    item = cloud.status(target, state_path)
    snap = {
        "index": index,
        "userServiceId": str(target),
        "at": core.shanghai_now().isoformat(),
        "vmStatus": item.get("vmStatus"),
        "vmStatusShow": item.get("vmStatusShow"),
        "running": cloud.is_running(item),
        "off": cloud.is_off(item),
        "deducting": item.get("deducting"),
        "consumeTime": item.get("consumeTime"),
    }
    if started is not None:
        snap["elapsedSeconds"] = int(time.time() - started)
    return snap


def summarize(snapshots, errors=None, requested_duration=0, duration_seconds=0):
    errors = errors or []
    first_off = next((item for item in snapshots if item.get("off")), None)
    first_non_running = next((item for item in snapshots if not item.get("running")), None)
    powered_throughout = bool(snapshots) and not errors and all(item.get("running") and not item.get("off") for item in snapshots)
    ran_requested_duration = not requested_duration or int(duration_seconds) >= int(requested_duration)
    summary = {
        "poweredThroughout": powered_throughout,
        "ranRequestedDuration": ran_requested_duration,
        "firstOffAt": first_off.get("at") if first_off else None,
        "firstOffElapsedSeconds": first_off.get("elapsedSeconds") if first_off else None,
        "firstOffSnapshot": first_off,
        "firstNonRunningAt": first_non_running.get("at") if first_non_running else None,
        "firstNonRunningElapsedSeconds": first_non_running.get("elapsedSeconds") if first_non_running else None,
        "firstNonRunningSnapshot": first_non_running,
        "errorCount": len(errors),
    }
    summary["ok"] = powered_throughout and ran_requested_duration
    return summary


def write_report(report, report_file):
    core.write_private_json_report(report, report_file)


def monitor(
    user_service_id=None,
    state_path=None,
    interval=60,
    duration=2400,
    report_file=None,
    stop_on_off=False,
    fail_on_off=False,
    relogin=True,
    stop_on_error=True,
):
    target = cloud.selected_user_service_id(state_path, user_service_id)
    interval = max(1, int(interval))
    duration = int(duration)
    started = time.time()
    report = {
        "ok": False,
        "monitorOnly": True,
        "userServiceId": str(target),
        "requestedDurationSeconds": duration,
        "intervalSeconds": interval,
        "stopOnOff": bool(stop_on_off),
        "failOnOff": bool(fail_on_off),
        "authMaintenance": {
            "relogin": bool(relogin),
            "note": "Only token-check/login maintenance is allowed here; no keepalive, boot, CAG, or analytics request is sent.",
        },
        "stopOnError": bool(stop_on_error),
        "startedAt": core.shanghai_now().isoformat(),
        "endedAt": None,
        "durationSeconds": 0,
        "snapshots": [],
        "errors": [],
        "stoppedEarly": False,
        "stopReason": "",
        "poweredThroughout": False,
        "firstOffAt": None,
        "firstOffElapsedSeconds": None,
        "firstNonRunningAt": None,
        "firstNonRunningElapsedSeconds": None,
    }
    count = 0

    while True:
        elapsed = int(time.time() - started)
        if duration and elapsed > duration and count > 0:
            break
        count += 1
        try:
            if relogin:
                valid, response = token.ensure_token(state_path, relogin=True)
                if not valid:
                    raise core.CmccError("token invalid while monitoring power state", response=response)
            snap = snapshot(target, state_path, started=started, index=count)
            report["snapshots"].append(snap)
            status_text = snap.get("vmStatusShow") or snap.get("vmStatus") or "-"
            print(
                f"[{core.short_time()}] [{count}] 状态验证: {status_text} "
                f"elapsed={core.format_duration(snap.get('elapsedSeconds', 0))} "
                f"running={snap.get('running')} off={snap.get('off')}",
                flush=True,
            )
            if stop_on_off and (snap.get("off") or not snap.get("running")):
                report["stoppedEarly"] = True
                report["stopReason"] = "power_state_not_running"
                break
        except Exception as err:
            error = {
                "index": count,
                "elapsedSeconds": int(time.time() - started),
                "at": core.shanghai_now().isoformat(),
                "error": str(err),
            }
            report["errors"].append(error)
            print(
                f"[{core.short_time()}] [{count}] 状态验证失败: {err} "
                f"elapsed={core.format_duration(error['elapsedSeconds'])}",
                flush=True,
            )
            if stop_on_error or fail_on_off:
                report["stoppedEarly"] = True
                report["stopReason"] = "status_check_error"
                break

        if duration and time.time() - started >= duration:
            break
        next_elapsed = count * interval
        if duration:
            next_elapsed = min(next_elapsed, duration)
        sleep_seconds = max(1, next_elapsed - int(time.time() - started))
        time.sleep(sleep_seconds)

    report["endedAt"] = core.shanghai_now().isoformat()
    report["durationSeconds"] = int(time.time() - started)
    summary = summarize(
        report["snapshots"],
        errors=report["errors"],
        requested_duration=duration,
        duration_seconds=report["durationSeconds"],
    )
    report.update(summary)

    args = core.argparse.Namespace(state=state_path)
    core.merge_state({
        "lastPowerMonitorAt": report["endedAt"],
        "lastPowerMonitor": {
            "ok": report["ok"],
            "poweredThroughout": report["poweredThroughout"],
            "durationSeconds": report["durationSeconds"],
            "firstOffAt": report["firstOffAt"],
            "firstOffElapsedSeconds": report["firstOffElapsedSeconds"],
            "firstNonRunningAt": report["firstNonRunningAt"],
            "firstNonRunningElapsedSeconds": report["firstNonRunningElapsedSeconds"],
            "stoppedEarly": report["stoppedEarly"],
            "stopReason": report["stopReason"],
        },
    }, args)
    write_report(report, report_file)
    if fail_on_off and not report["ok"]:
        raise core.CmccError("power monitor detected non-running/offline status", response=report)
    return report
