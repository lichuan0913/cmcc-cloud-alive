"""CAG HTTPS boot/connect-material research helpers.

This route is no longer treated as desktop keepalive. Independent monitoring
showed CAG refreshes can mask a shutdown by pulling the VM back to running, and
GUI cross-checks showed it can replace the official desktop session. Keep this
module for boot/material acquisition and negative evidence only.
"""

import json
import os
import time
from pathlib import Path

from . import cag_boot, cloud, core, power_monitor, token


OFFICIAL_PROCESS_NAMES = {"cmcc-jtydn", "bootCypc", "uSmartView_VDI_Client"}
HTTP_PRIME_HEARTBEAT_OK_CODES = {2000, 4039, 4040, 4041, 4042}
OTHER_LOGIN_CODE = 4043


def _process_name(entry, cmdline):
    try:
        exe_name = (entry / "exe").resolve(strict=True).name
        if exe_name:
            return exe_name
    except OSError:
        pass
    argv0 = cmdline.split(" ", 1)[0] if cmdline else ""
    return Path(argv0).name


def official_session_processes():
    processes = []
    proc = Path("/proc")
    if not proc.exists():
        return processes
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        if not raw:
            continue
        cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        name = _process_name(entry, cmdline)
        if name in OFFICIAL_PROCESS_NAMES:
            processes.append({
                "pid": int(entry.name),
                "cmdline": cmdline,
                "processName": name,
                "matched": [name],
                "desktopSessionProcess": name == "uSmartView_VDI_Client",
                "sdkBrokerProcess": name == "bootCypc",
                "clientShellProcess": name == "cmcc-jtydn",
            })
    return processes


def official_session_snapshot(stage):
    processes = official_session_processes()
    return {
        "stage": stage,
        "at": core.shanghai_now().isoformat(),
        "processes": processes,
        "clientShellPresent": any(item["clientShellProcess"] for item in processes),
        "sdkBrokerPresent": any(item["sdkBrokerProcess"] for item in processes),
        "desktopSessionPresent": any(item["desktopSessionProcess"] for item in processes),
    }


def _connect_summary(report):
    final_connect = report.get("finalConnect") or {}
    decoded = final_connect.get("decoded") or {}
    connect_info = decoded.get("connectInfo") or {}
    rap = ((connect_info.get("connectStrDecoded") or {}).get("summary") or {})
    return {
        "businessOk": final_connect.get("businessOk") is True,
        "connectStr": bool(connect_info.get("hasConnectStr")),
        "vmStatus": connect_info.get("vmStatus"),
        "rap": {
            "host": rap.get("host") or "",
            "port": rap.get("port") or 0,
            "type": rap.get("type") or "",
            "serverType": rap.get("serverType") or "",
            "accessTokenPresent": bool(rap.get("accessTokenPresent")),
            "cpsidPresent": bool(rap.get("cpsidPresent")),
        },
    }


def _post_http_prime(user_service_id, state_path=None):
    from . import desktop_keepalive
    return desktop_keepalive.official_http_once(
        user_service_id,
        state_path=state_path,
        include_status=False,
        do_heartbeat=True,
        do_info=True,
        do_log_config=True,
    )


def _http_code(result, key):
    value = result.get(key) if isinstance(result, dict) else None
    if isinstance(value, dict):
        return int(value.get("code") or 0)
    return 0


def _http_prime_accepted(result):
    if not isinstance(result, dict) or result.get("error"):
        return False
    heartbeat = _http_code(result, "heartbeat")
    info = _http_code(result, "infoReport")
    log_config = _http_code(result, "logReportConfig")
    if heartbeat == OTHER_LOGIN_CODE:
        return False
    return heartbeat in HTTP_PRIME_HEARTBEAT_OK_CODES and info == 2000 and log_config == 2000


def once(user_service_id=None, state_path=None, boot_wait=180, timeout=30, observe_seconds=0, post_http_prime=False):
    target = cloud.selected_user_service_id(state_path, user_service_id)
    before = official_session_snapshot("before")
    report = cag_boot.boot(target, state_path, boot_wait=boot_wait, timeout=timeout)
    http_prime = None
    if post_http_prime:
        try:
            http_prime = _post_http_prime(target, state_path)
        except Exception as err:
            http_prime = {"error": str(err)}
    if observe_seconds:
        time.sleep(max(1, int(observe_seconds)))
    after = official_session_snapshot("after")
    status = cloud.status(target, state_path)
    protocol = _connect_summary(report)
    protocol_accepted = protocol["businessOk"] and protocol["connectStr"] and cloud.is_running(status)
    http_prime_accepted = (not post_http_prime) or _http_prime_accepted(http_prime)
    material_accepted = protocol_accepted and http_prime_accepted
    session_takeover_observed = before["desktopSessionPresent"] and not after["desktopSessionPresent"]
    result = {
        "accepted": False,
        "materialAccepted": material_accepted,
        "protocolAccepted": protocol_accepted,
        "desktopKeepaliveProven": False,
        "routeRejected": True,
        "sessionOwning": True,
        "sessionTakeoverObserved": session_takeover_observed,
        "unsafeReason": (
            "CAG HTTPS refresh obtains desktop connection material, but it is "
            "rejected as keepalive: it owns/replaces the desktop session and "
            "can mask shutdown by pulling the VM back to running."
        ),
        "userServiceId": str(target),
        "protocol": protocol,
        "postHttpPrime": {
            "enabled": bool(post_http_prime),
            "accepted": bool(http_prime_accepted),
            "result": http_prime,
            "note": (
                "Optional replay of the official connected-client visible HTTP timers "
                "after CAG refresh: heartbeat, infoReport, logReport config."
            ),
        },
        "officialSession": {
            "observeSeconds": int(observe_seconds or 0),
            "before": before,
            "after": after,
        },
        "status": {
            "vmStatus": status.get("vmStatus"),
            "vmStatusShow": status.get("vmStatusShow"),
            "running": cloud.is_running(status),
            "deducting": status.get("deducting"),
            "consumeTime": status.get("consumeTime"),
        },
        "at": core.shanghai_now().isoformat(),
    }
    args = core.argparse.Namespace(state=state_path)
    core.merge_state({
        "lastCagKeepaliveAt": result["at"],
        "lastCagKeepalive": result,
        "selectedUserServiceId": str(target),
    }, args)
    return result


def run_loop(user_service_id=None, state_path=None, interval=60, run_seconds=0, account_relogin_hours=24, boot_wait=180, timeout=30, post_http_prime=False):
    raise core.CmccError(
        "cag-keepalive loop is disabled: CAG HTTPS is retained only for "
        "boot/connect-material research and is rejected as desktop keepalive."
    )
    target = cloud.selected_user_service_id(state_path, user_service_id)
    started = time.time()
    last_account_refresh = 0
    count = 0
    while True:
        token.ensure_token(state_path, relogin=True)
        now = time.time()
        if account_relogin_hours and now - last_account_refresh >= account_relogin_hours * 3600:
            try:
                from . import auth
                auth.login_from_cached_credentials(state_path)
            except Exception:
                pass
            last_account_refresh = now
        count += 1
        result = once(target, state_path, boot_wait=boot_wait, timeout=timeout, post_http_prime=post_http_prime)
        elapsed = int(time.time() - started)
        status_text = "保活成功" if result["accepted"] else "保活失败"
        proto = result["protocol"]
        print(
            f"[{core.short_time()}] [{count}] {status_text}: {core.format_duration(elapsed)} "
            f"cagBusiness={proto['businessOk']} connectStr={proto['connectStr']} "
            f"vmStatus={result['status']['vmStatusShow']}",
            flush=True,
        )
        if not result["accepted"]:
            raise core.CmccError(
                f"CAG HTTPS keepalive failed; status={result['status'].get('vmStatusShow')} "
                f"businessOk={proto['businessOk']} connectStr={proto['connectStr']}",
                response=result,
            )
        if run_seconds and time.time() - started >= run_seconds:
            return result
        time.sleep(max(1, int(interval)))


def run_verify(
    user_service_id=None,
    state_path=None,
    duration=2400,
    min_proof_seconds=2400,
    interval=60,
    account_relogin_hours=24,
    boot_wait=180,
    timeout=30,
    report_file=None,
    allow_official_client_present=False,
    stop_on_off=True,
    post_http_prime=False,
):
    target = cloud.selected_user_service_id(state_path, user_service_id)
    started = time.time()
    before_processes = official_session_processes()
    interval = max(1, int(interval))
    report = {
        "ok": False,
        "accepted": False,
        "cagKeepaliveProven": False,
        "desktopKeepaliveProven": False,
        "routeRejected": True,
        "rejectedReason": (
            "CAG HTTPS is rejected as desktop keepalive. It is session-owning, "
            "can kick/replace official desktop sessions, and independent "
            "monitoring observed shutdown during CAG+HTTP-prime testing."
        ),
        "sessionOwning": True,
        "nonKicking": False,
        "experimental": False,
        "aborted": False,
        "abortReason": "",
        "userServiceId": str(target),
        "requestedDurationSeconds": int(duration),
        "minProofSeconds": int(min_proof_seconds),
        "intervalSeconds": interval,
        "bootWaitSeconds": int(boot_wait),
        "timeoutSeconds": int(timeout),
        "statusVerification": {
            "intervalSeconds": interval,
            "stopOnOff": bool(stop_on_off),
            "note": "Each CAG round records cloud power state; run scripts/power-monitor.sh in parallel for fully independent evidence.",
        },
        "postHttpPrime": {
            "enabled": bool(post_http_prime),
            "mode": "official_visible_timers_once_after_each_cag",
            "endpoints": [
                "/cc/cloudPc/heartbeat/v2",
                "/cc/cloudPc/infoReport/v2",
                "/system/logReport/config/v2",
            ],
            "note": (
                "Rejected hypothesis retained for evidence: after CAG pulls/refreshes "
                "the desktop, one replay of captured HTTP timer packets was tested "
                "and still did not prove desktop keepalive."
            ),
        },
        "processProofPolicy": {
            "allowOfficialClientPresent": bool(allow_official_client_present),
            "note": (
                "CAG is session-owning. A clean proof should have no official client/SDK "
                "processes, otherwise native transport may contaminate the power-state proof."
            ),
        },
        "startedAt": core.shanghai_now().isoformat(),
        "endedAt": None,
        "durationSeconds": 0,
        "attempts": [],
        "statusSnapshots": [],
        "officialClientProcessSnapshots": [
            {
                "stage": "before",
                "elapsedSeconds": 0,
                "at": core.shanghai_now().isoformat(),
                "processes": before_processes,
            }
        ],
        "errors": [],
        "stoppedEarly": False,
        "stopReason": "",
        "firstOffAt": None,
        "firstOffElapsedSeconds": None,
        "firstNonRunningAt": None,
        "firstNonRunningElapsedSeconds": None,
        "successCriteria": {
            "allCagAttemptsAccepted": False,
            "allPostHttpPrimeAccepted": False,
            "poweredThroughout": False,
            "ranAtLeastMinProofSeconds": False,
            "noOfficialClientProcess": False,
        },
        "unsafeReason": (
            "CAG HTTPS obtains/refreshes desktop connection material and is treated as a "
            "session-owning fallback. It can replace an active official desktop session."
        ),
    }

    def finish_report():
        report["endedAt"] = report["endedAt"] or core.shanghai_now().isoformat()
        report["durationSeconds"] = int(time.time() - started)
        if not report["officialClientProcessSnapshots"] or report["officialClientProcessSnapshots"][-1]["stage"] != "after":
            report["officialClientProcessSnapshots"].append({
                "stage": "after",
                "elapsedSeconds": report["durationSeconds"],
                "at": report["endedAt"],
                "processes": official_session_processes(),
            })
        status_errors = [item for item in report["errors"] if str(item.get("stage", "")).startswith("status")]
        status_summary = power_monitor.summarize(
            report["statusSnapshots"],
            errors=status_errors,
            requested_duration=int(min_proof_seconds),
            duration_seconds=report["durationSeconds"],
        )
        report["firstOffAt"] = status_summary["firstOffAt"]
        report["firstOffElapsedSeconds"] = status_summary["firstOffElapsedSeconds"]
        report["firstNonRunningAt"] = status_summary["firstNonRunningAt"]
        report["firstNonRunningElapsedSeconds"] = status_summary["firstNonRunningElapsedSeconds"]
        all_cag_ok = bool(report["attempts"]) and all((item.get("protocol") or {}).get("businessOk") and (item.get("protocol") or {}).get("connectStr") for item in report["attempts"])
        all_prime_ok = (not post_http_prime) or (bool(report["attempts"]) and all(((item.get("postHttpPrime") or {}).get("accepted") is True) for item in report["attempts"]))
        powered = status_summary["poweredThroughout"]
        ran_enough = report["durationSeconds"] >= int(min_proof_seconds)
        no_official = not any(snapshot.get("processes") for snapshot in report["officialClientProcessSnapshots"])
        report["successCriteria"] = {
            "allCagAttemptsAccepted": all_cag_ok,
            "allPostHttpPrimeAccepted": all_prime_ok,
            "poweredThroughout": powered,
            "ranAtLeastMinProofSeconds": ran_enough,
            "noOfficialClientProcess": no_official,
        }
        report["candidateAccepted"] = all_cag_ok and all_prime_ok and powered and ran_enough and no_official and not report["aborted"]
        report["accepted"] = False
        report["cagKeepaliveProven"] = False
        report["desktopKeepaliveProven"] = False
        report["ok"] = False
        args = core.argparse.Namespace(state=state_path)
        core.merge_state({
            "lastCagVerifyAt": report["endedAt"],
            "lastCagVerify": {
                "ok": report["ok"],
                "accepted": report["accepted"],
                "cagKeepaliveProven": report["cagKeepaliveProven"],
                "desktopKeepaliveProven": report["desktopKeepaliveProven"],
                "sessionOwning": report["sessionOwning"],
                "durationSeconds": report["durationSeconds"],
                "stoppedEarly": report["stoppedEarly"],
                "stopReason": report["stopReason"],
                "firstOffAt": report["firstOffAt"],
                "firstOffElapsedSeconds": report["firstOffElapsedSeconds"],
                "successCriteria": report["successCriteria"],
            },
        }, args)
        core.write_private_json_report(report, report_file)
        return report

    if before_processes and not allow_official_client_present:
        report["aborted"] = True
        report["abortReason"] = "official_client_process_present_before_verify"
        report["errors"].append({
            "stage": "preflight",
            "error": "official client/SDK process is already running; stop it for a clean CAG proof",
            "at": core.shanghai_now().isoformat(),
        })
        report["endedAt"] = core.shanghai_now().isoformat()
        return finish_report()

    report["aborted"] = True
    report["abortReason"] = "cag_https_route_rejected"
    report["errors"].append({
        "stage": "preflight",
        "error": report["rejectedReason"],
        "at": core.shanghai_now().isoformat(),
    })
    report["endedAt"] = core.shanghai_now().isoformat()
    return finish_report()

    count = 0
    last_account_refresh = 0
    while not report["stoppedEarly"] and time.time() - started < int(duration):
        token.ensure_token(state_path, relogin=True)
        now = time.time()
        if account_relogin_hours and now - last_account_refresh >= account_relogin_hours * 3600:
            try:
                from . import auth
                auth.login_from_cached_credentials(state_path)
            except Exception as err:
                report["errors"].append({"stage": "accountRelogin", "error": str(err), "at": core.shanghai_now().isoformat()})
            last_account_refresh = now
        count += 1
        event = {
            "index": count,
            "elapsedSeconds": int(time.time() - started),
            "at": core.shanghai_now().isoformat(),
            "accepted": False,
            "protocol": None,
            "statusBeforeCag": None,
            "status": None,
            "error": None,
        }
        try:
            pre_status = power_monitor.snapshot(target, state_path, started=started, index=count)
            pre_status["stage"] = "before_cag"
            event["statusBeforeCag"] = pre_status
            report["statusSnapshots"].append(pre_status)
            if pre_status.get("off") or not pre_status.get("running"):
                report["stoppedEarly"] = True
                report["stopReason"] = "power_state_not_running_before_cag"
                print(
                    f"[{core.short_time()}] [{count}] CAG前状态失败: "
                    f"{pre_status.get('vmStatusShow')} elapsed={core.format_duration(pre_status.get('elapsedSeconds', 0))}",
                    flush=True,
                )
                report["attempts"].append(event)
                break
            result = once(target, state_path, boot_wait=boot_wait, timeout=timeout, post_http_prime=post_http_prime)
            event["accepted"] = bool(result.get("accepted"))
            event["protocol"] = result.get("protocol")
            event["status"] = result.get("status")
            event["postHttpPrime"] = result.get("postHttpPrime")
            status_snapshot = power_monitor.snapshot(target, state_path, started=started, index=count)
            status_snapshot["stage"] = "after_cag"
            report["statusSnapshots"].append(status_snapshot)
            report["officialClientProcessSnapshots"].append({
                "stage": "attempt",
                "index": count,
                "elapsedSeconds": int(time.time() - started),
                "at": core.shanghai_now().isoformat(),
                "processes": official_session_processes(),
            })
            proto = event["protocol"] or {}
            print(
                f"[{core.short_time()}] [{count}] CAG验证: {core.format_duration(event['elapsedSeconds'])} "
                f"accepted={event['accepted']} cagBusiness={proto.get('businessOk')} "
                f"connectStr={proto.get('connectStr')} status={status_snapshot.get('vmStatusShow')}",
                flush=True,
            )
            if not event["accepted"]:
                report["stoppedEarly"] = True
                report["stopReason"] = "cag_attempt_failed"
            if stop_on_off and (status_snapshot.get("off") or not status_snapshot.get("running")):
                report["stoppedEarly"] = True
                report["stopReason"] = "power_state_not_running"
        except Exception as err:
            event["error"] = str(err)
            report["errors"].append({"stage": "cag", "error": str(err), "at": core.shanghai_now().isoformat()})
            report["stoppedEarly"] = True
            report["stopReason"] = "cag_exception"
        report["attempts"].append(event)
        if report["stoppedEarly"] or time.time() - started >= int(duration):
            break
        time.sleep(interval)

    report["endedAt"] = core.shanghai_now().isoformat()
    return finish_report()
