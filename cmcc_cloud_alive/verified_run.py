"""Run an experiment under an independent cloud power-state verifier."""

import json
import os
import signal
import subprocess
import time
from pathlib import Path

from . import cloud, core, power_monitor, token


def _terminate_process(process, grace_seconds=5):
    if process.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except Exception:
        pass
    if process.poll() is None:
        try:
            process.terminate()
        except Exception:
            pass
    if process.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except Exception:
        process.terminate()
    deadline = time.time() + max(1, int(grace_seconds))
    while time.time() < deadline:
        if process.poll() is not None:
            return
        time.sleep(0.2)
    if process.poll() is None:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except Exception:
            process.kill()


def _write_report(report, report_file):
    core.write_private_json_report(report, report_file)


def run(
    command,
    user_service_id=None,
    state_path=None,
    duration=2400,
    interval=60,
    report_file=None,
    allow_command_exit=False,
    relogin=True,
    stop_on_error=True,
    cwd=None,
):
    """Run ``command`` while polling cloud power state independently.

    Success requires all three conditions:
    - the command does not fail;
    - the monitor runs for the requested duration;
    - every collected power-state snapshot is running and not off.
    """
    if not command:
        raise core.CmccError("verified-run requires a command after --")
    target = cloud.selected_user_service_id(state_path, user_service_id)
    duration = int(duration)
    interval = max(1, int(interval))
    started = time.time()
    process = None
    report = {
        "ok": False,
        "verifiedRun": True,
        "monitorOnly": False,
        "userServiceId": str(target),
        "command": list(command),
        "cwd": str(cwd or os.getcwd()),
        "requestedDurationSeconds": duration,
        "intervalSeconds": interval,
        "allowCommandExit": bool(allow_command_exit),
        "authMaintenance": {
            "relogin": bool(relogin),
            "note": "The verifier only performs token maintenance and cloud status checks; it sends no keepalive, CAG, boot, or analytics request.",
        },
        "startedAt": core.shanghai_now().isoformat(),
        "endedAt": None,
        "durationSeconds": 0,
        "snapshots": [],
        "errors": [],
        "process": {
            "pid": None,
            "exitCode": None,
            "terminatedByVerifier": False,
            "exitedBeforeDuration": False,
        },
        "stoppedEarly": False,
        "stopReason": "",
        "poweredThroughout": False,
        "firstOffAt": None,
        "firstOffElapsedSeconds": None,
        "firstNonRunningAt": None,
        "firstNonRunningElapsedSeconds": None,
        "successCriteria": {
            "commandOk": False,
            "poweredThroughout": False,
            "ranRequestedDuration": False,
            "noStatusErrors": False,
        },
    }

    try:
        process = subprocess.Popen(
            list(command),
            cwd=str(cwd or os.getcwd()),
            start_new_session=True,
        )
        report["process"]["pid"] = process.pid
        count = 0
        while True:
            elapsed = int(time.time() - started)
            if duration and elapsed > duration and count > 0:
                break

            exit_code = process.poll()
            if exit_code is not None and not allow_command_exit and (not duration or elapsed < duration):
                report["stoppedEarly"] = True
                report["stopReason"] = "command_exited_before_requested_duration"
                report["process"]["exitedBeforeDuration"] = True
                break

            count += 1
            try:
                if relogin:
                    valid, response = token.ensure_token(state_path, relogin=True)
                    if not valid:
                        raise core.CmccError("token invalid while monitoring verified run", response=response)
                snap = power_monitor.snapshot(target, state_path, started=started, index=count)
                snap["stage"] = "verified_run"
                report["snapshots"].append(snap)
                status_text = snap.get("vmStatusShow") or snap.get("vmStatus") or "-"
                print(
                    f"[{core.short_time()}] [{count}] 独立状态验证: {status_text} "
                    f"elapsed={core.format_duration(snap.get('elapsedSeconds', 0))} "
                    f"running={snap.get('running')} off={snap.get('off')}",
                    flush=True,
                )
                if snap.get("off") or not snap.get("running"):
                    report["stoppedEarly"] = True
                    report["stopReason"] = "power_state_not_running"
                    report["process"]["terminatedByVerifier"] = process.poll() is None
                    _terminate_process(process)
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
                    f"[{core.short_time()}] [{count}] 独立状态验证失败: {err} "
                    f"elapsed={core.format_duration(error['elapsedSeconds'])}",
                    flush=True,
                )
                if stop_on_error:
                    report["stoppedEarly"] = True
                    report["stopReason"] = "status_check_error"
                    report["process"]["terminatedByVerifier"] = process.poll() is None
                    _terminate_process(process)
                    break

            if duration and time.time() - started >= duration:
                break
            next_elapsed = count * interval
            if duration:
                next_elapsed = min(next_elapsed, duration)
            sleep_seconds = max(1, next_elapsed - int(time.time() - started))
            time.sleep(sleep_seconds)

        if process.poll() is None:
            report["process"]["terminatedByVerifier"] = True
            _terminate_process(process)
        report["process"]["exitCode"] = process.poll()
    except FileNotFoundError as err:
        report["errors"].append({
            "stage": "start",
            "elapsedSeconds": int(time.time() - started),
            "at": core.shanghai_now().isoformat(),
            "error": str(err),
        })
        report["stoppedEarly"] = True
        report["stopReason"] = "command_start_failed"
    except KeyboardInterrupt:
        report["stoppedEarly"] = True
        report["stopReason"] = "interrupted"
        if process is not None:
            report["process"]["terminatedByVerifier"] = process.poll() is None
            _terminate_process(process)
        raise
    finally:
        report["endedAt"] = core.shanghai_now().isoformat()
        report["durationSeconds"] = int(time.time() - started)
        summary = power_monitor.summarize(
            report["snapshots"],
            errors=report["errors"],
            requested_duration=duration,
            duration_seconds=report["durationSeconds"],
        )
        report.update(summary)
        exit_code = report["process"].get("exitCode")
        command_ok = exit_code == 0 or (allow_command_exit and exit_code is not None)
        report["successCriteria"] = {
            "commandOk": bool(command_ok or (
                report["process"].get("terminatedByVerifier")
                and not report["stoppedEarly"]
                and summary.get("ranRequestedDuration")
            )),
            "poweredThroughout": bool(report["poweredThroughout"]),
            "ranRequestedDuration": bool(report["ranRequestedDuration"]),
            "noStatusErrors": not report["errors"],
        }
        report["ok"] = all(report["successCriteria"].values()) and not report["stoppedEarly"]
        args = core.argparse.Namespace(state=state_path)
        core.merge_state({
            "lastVerifiedRunAt": report["endedAt"],
            "lastVerifiedRun": {
                "ok": report["ok"],
                "durationSeconds": report["durationSeconds"],
                "stopReason": report["stopReason"],
                "firstOffAt": report["firstOffAt"],
                "firstOffElapsedSeconds": report["firstOffElapsedSeconds"],
                "firstNonRunningAt": report["firstNonRunningAt"],
                "firstNonRunningElapsedSeconds": report["firstNonRunningElapsedSeconds"],
                "successCriteria": report["successCriteria"],
            },
        }, args)
        _write_report(report, report_file)
    return report
