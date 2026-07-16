"""CAG HTTPS desktop boot/connect-material flow."""

import time

from . import cloud, core


def firm_auth(user_service_id=None, state_path=None):
    args = core.argparse.Namespace(state=state_path, user_service_id=cloud.selected_user_service_id(state_path, user_service_id))
    return core.get_firm_auth(args)


def boot(user_service_id=None, state_path=None, boot_wait=180, timeout=15):
    args = core.argparse.Namespace(
        state=state_path,
        user_service_id=cloud.selected_user_service_id(state_path, user_service_id),
        boot_wait=boot_wait,
        timeout=timeout,
        version="V7.25.40-HY",
        client_ip="",
        mac="",
        host_name="",
    )
    auth = core.get_firm_auth(args)
    if not auth.get("cagIp") or not auth.get("cagPort"):
        raise core.CmccError("selected desktop does not expose CAG HTTPS material")
    report = core.cag_https_connect_report(auth, args)
    core.merge_state({
        "lastCagBootAt": core.shanghai_now().isoformat(),
        "lastCagBootUserServiceId": args.user_service_id,
        "lastCagBootReport": report,
    }, args)
    return report


def ensure_running(user_service_id=None, state_path=None, boot_wait=180, timeout=15, refresh_wait=5):
    target = cloud.selected_user_service_id(state_path, user_service_id)
    item = cloud.status(target, state_path)
    if cloud.is_running(item):
        return {"alreadyRunning": True, "status": item, "bootReport": None}
    report = boot(target, state_path, boot_wait=boot_wait, timeout=timeout)
    if refresh_wait:
        time.sleep(refresh_wait)
    refreshed = cloud.status(target, state_path)
    return {"alreadyRunning": False, "status": refreshed, "bootReport": report}
