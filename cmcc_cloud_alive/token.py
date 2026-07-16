"""SOHO token validity checks."""

import os
import re
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from . import auth, core


INVALID_TOKEN_CODES = {4014, 4015, 4016, 4017, 4200, 4201}

# openresty / gateway blips and plain transport failures must NOT be treated
# as "token expired" — re-login against a 502 just cascades into a full crash.
_TRANSIENT_HTTP_RE = re.compile(r"HTTP\s+(5\d\d)\b", re.I)
_TRANSIENT_HINTS = (
    "network failed",
    "timed out",
    "timeout",
    "temporarily",
    "connection reset",
    "connection refused",
    "broken pipe",
    "bad gateway",
    "service unavailable",
    "gateway time",
)

# HARD_GATE#871d-relogin-serial1: same-account re-login flock.
# Multiple live children may share acct_<user>.json; concurrent password_login
# invalidates the peer token (4015 thrash). Serialize re-login by username and
# re-check after lock so the waiter adopts the winner's token without re-login.
# fcntl is Unix-only — Windows uses msvcrt.locking (see _lock_fd/_unlock_fd).
_RELOGIN_LOCK_TIMEOUT_S = 90.0
_tls = threading.local()
_IS_WIN = sys.platform.startswith("win")


def _lock_fd(fd: int) -> None:
    """Non-blocking exclusive lock; raise BlockingIOError if busy."""
    if _IS_WIN:
        import msvcrt

        # msvcrt.locking locks by byte range; lock 1 byte from start.
        # LK_NBLCK = non-blocking; raises OSError if already locked.
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            # Windows: errno 13/36 when region already locked
            raise BlockingIOError(exc.errno, str(exc)) from exc
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_fd(fd: int) -> None:
    if _IS_WIN:
        import msvcrt

        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
    else:
        import fcntl

        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass


def is_transient_error(exc_or_msg) -> bool:
    """Return True for gateway/network blips that say nothing about token validity."""
    msg = str(exc_or_msg or "")
    if not msg:
        return False
    if _TRANSIENT_HTTP_RE.search(msg):
        return True
    lower = msg.lower()
    return any(hint in lower for hint in _TRANSIENT_HINTS)


def _token_response_from_exc(exc):
    return {
        "code": 0,
        "msg": str(exc),
        "businessCode": "",
        "transient": is_transient_error(exc),
    }


def account_key(username: str) -> str:
    """Normalize phone/username for same-account re-login flock key."""
    s = str(username or "").strip()
    if not s:
        return ""
    digits = "".join(ch for ch in s if ch.isdigit())
    if len(digits) >= 11:
        return digits[-11:]
    out = []
    for ch in s.lower():
        if ch.isalnum() or ch in ("-", "_", "."):
            out.append(ch)
        else:
            out.append("_")
    return "".join(out) or "unknown"


def _held_keys():
    keys = getattr(_tls, "keys", None)
    if keys is None:
        keys = set()
        _tls.keys = keys
    return keys


def _locks_dir() -> Path:
    """Prefer durable data root (profiles sibling), fall back to ~/.cmcc-cloud-alive/locks."""
    env = (os.environ.get("CMCC_ALIVE_DATA") or "").strip()
    if env:
        return Path(env) / "locks"
    try:
        sp = core.state_path(None)
        if sp.parent.name == "profiles":
            return sp.parent.parent / "locks"
        return sp.parent / "locks"
    except Exception:
        return Path.home() / ".cmcc-cloud-alive" / "locks"


def relogin_lock_path(username: str) -> Path:
    key = account_key(username) or "unknown"
    return _locks_dir() / f"relogin_{key}.lock"


@contextmanager
def account_relogin_lock(username: str, timeout_s: float = _RELOGIN_LOCK_TIMEOUT_S):
    """Cross-process exclusive lock for same-account re-login (reentrant in-process)."""
    key = account_key(username)
    if not key:
        yield
        return
    held = _held_keys()
    if key in held:
        yield
        return

    path = relogin_lock_path(username)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Windows msvcrt.locking needs a non-empty region; ensure ≥1 byte exists.
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if os.fstat(fd).st_size < 1:
            os.write(fd, b"0")
            os.lseek(fd, 0, os.SEEK_SET)
    except OSError:
        pass
    deadline = time.time() + max(1.0, float(timeout_s or _RELOGIN_LOCK_TIMEOUT_S))
    locked = False
    try:
        while True:
            try:
                _lock_fd(fd)
                locked = True
                break
            except BlockingIOError:
                if time.time() >= deadline:
                    raise core.CmccError(
                        f"account re-login lock busy for {key} after {timeout_s}s"
                    )
                time.sleep(0.2)
        try:
            # Stamp pid without emptying the file first (Windows msvcrt needs
            # a non-empty locked region for the duration of the lock).
            data = f"{os.getpid()}\n".encode("ascii", "replace") or b"0\n"
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, data)
            try:
                os.ftruncate(fd, len(data))
            except OSError:
                pass
        except OSError:
            pass
        held.add(key)
        try:
            yield
        finally:
            held.discard(key)
    finally:
        if locked:
            _unlock_fd(fd)
        try:
            os.close(fd)
        except OSError:
            pass


def _state_token_fingerprint(state: dict) -> str:
    if not isinstance(state, dict):
        return ""
    for k in ("sohoToken", "token", "accessToken", "Authorization"):
        v = state.get(k)
        if v:
            return str(v)
    return ""


def check_token(state_path=None, retries=3, retry_delay=1.5):
    """Check SOHO token.

    Retries a few times on HTTP 5xx / network blips.  If the gateway is still
    down after retries, the response is marked ``transient=True`` so callers
    skip re-login (re-login would just hit the same 502 and abort the loop).
    """
    args = core.argparse.Namespace(state=state_path)
    attempts = max(1, int(retries or 1))
    delay = max(0.0, float(retry_delay or 0.0))
    response = None

    for attempt in range(attempts):
        try:
            response = core.api_request("/token/checkToken/v1", None, args)
            break
        except Exception as exc:  # network/API errors
            response = _token_response_from_exc(exc)
            if response.get("transient") and attempt + 1 < attempts:
                time.sleep(delay * (attempt + 1))
                continue
            break

    if not isinstance(response, dict):
        response = {"code": 0, "msg": "empty token check response", "businessCode": "", "transient": True}

    try:
        code = int(response.get("code") or 0)
    except (TypeError, ValueError):
        code = 0

    # Real token validity only comes from a successful JSON business response.
    # Transient transport failures leave validity unknown — never force re-login.
    if response.get("transient"):
        valid = False
    else:
        valid = code == 2000 and code not in INVALID_TOKEN_CODES

    core.merge_state({
        "lastTokenCheckAt": core.shanghai_now().isoformat(),
        "lastTokenCheckResponse": {
            "code": response.get("code"),
            "msg": response.get("msg"),
            "businessCode": response.get("businessCode") or "",
            "transient": bool(response.get("transient")),
        },
    }, args)
    return valid, response


def ensure_token(state_path=None, relogin=True, force=False):
    """Ensure token is valid; on expiry serialize re-login by account.

    HARD_GATE#871d-relogin-serial1:
    1) check_token (skipped when force=True)
    2) if invalid + relogin: flock by username
    3) under lock: reload state; if sohoToken changed, re-check and adopt
    4) still invalid (or force): login_from_cached_credentials

    force=True is for business APIs (getFirmAuth / listClouds) that return
    4015 while checkToken still claims valid — checkToken alone is not proof
    that control-plane calls will succeed.
    """
    response = None
    if not force:
        valid, response = check_token(state_path)
        if valid:
            return True, response
        # Gateway blip: keep existing token, do not re-login into the same 502.
        if isinstance(response, dict) and response.get("transient"):
            return False, response
        if not relogin:
            return False, response
    else:
        if not relogin:
            return False, {"code": 4015, "msg": "force re-login disabled"}
        response = {"code": 4015, "msg": "business auth expired (force re-login)"}

    args = core.argparse.Namespace(state=state_path)
    state = core.load_state(args)
    username = (
        (state or {}).get("username")
        or (state or {}).get("phone")
        or (state or {}).get("mobile")
        or (state or {}).get("account")
        or ""
    )
    if not username:
        state = auth.login_from_cached_credentials(state_path)
        return True, {
            "code": 2000,
            "msg": "re-login ok",
            "userId": state.get("userId"),
            "forced": bool(force),
        }

    before_fp = _state_token_fingerprint(state)
    with account_relogin_lock(str(username)):
        # Peer may have just written a fresh token into the shared state file.
        state2 = core.load_state(args)
        after_fp = _state_token_fingerprint(state2)
        if after_fp and after_fp != before_fp:
            valid2, response2 = check_token(state_path)
            if valid2:
                return True, {
                    "code": 2000,
                    "msg": "adopted peer re-login token",
                    "userId": (state2 or {}).get("userId"),
                    "adopted": True,
                    "forced": bool(force),
                    "prior": response,
                    "check": response2,
                }
        if not force:
            # Token unchanged or still invalid — we are the re-login owner.
            valid3, response3 = check_token(state_path)
            if valid3:
                return True, response3
            if isinstance(response3, dict) and response3.get("transient"):
                return False, response3
        # force=True always re-logs when peer did not supply a fresher token;
        # checkToken can lie (valid) while firmAuth/listClouds still return 4015.
        state = auth.login_from_cached_credentials(state_path)
        return True, {
            "code": 2000,
            "msg": "re-login ok",
            "userId": state.get("userId"),
            "adopted": False,
            "forced": bool(force),
        }
