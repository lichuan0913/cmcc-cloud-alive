"""Periodic account token refresh."""

import time

from . import auth, core, token


def refresh_once(state_path=None):
    return auth.login_from_cached_credentials(state_path)


def refresh_if_due(state_path=None, hours=24):
    args = core.argparse.Namespace(state=state_path)
    state = core.load_state(args)
    last = state.get("lastAccountKeepaliveAt")
    if last:
        try:
            last_ts = core.datetime.fromisoformat(last).timestamp()
            if time.time() - last_ts < hours * 3600:
                return False, state
        except ValueError:
            pass
    refreshed = refresh_once(state_path)
    core.merge_state({"lastAccountKeepaliveAt": core.shanghai_now().isoformat()}, args)
    return True, refreshed


def check_or_refresh(state_path=None):
    valid, response = token.check_token(state_path)
    if valid:
        return False, response
    # Gateway/network blip: keep existing token, do not re-login into a 502.
    if isinstance(response, dict) and response.get("transient"):
        return False, response
    refreshed = refresh_once(state_path)
    return True, {"code": 2000, "msg": "re-login ok", "userId": refreshed.get("userId")}
