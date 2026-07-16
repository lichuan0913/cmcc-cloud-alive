"""WebUI ASGI package (Starlette). Parent process only — no keepalive loop here."""
__all__ = ["app"]

def __getattr__(name: str):
    if name == "app":
        from cmcc_cloud_alive.webui.app import app as _app
        return _app
    raise AttributeError(name)
