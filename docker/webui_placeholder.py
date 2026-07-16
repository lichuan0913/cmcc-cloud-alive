"""Temporary WebUI until J3 `cmcc_cloud_alive.webui.app` exists.

Provides /api/health and a minimal index. No LIVE, no secrets.
"""
from __future__ import annotations

import os

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse
from starlette.routing import Route

TOKEN = os.environ.get("CMCC_WEBUI_TOKEN", "").strip()


def _auth(request: Request) -> JSONResponse | None:
    if not TOKEN:
        return None
    auth = request.headers.get("authorization", "")
    if auth == f"Bearer {TOKEN}":
        return None
    q = request.query_params.get("token", "")
    if q and q == TOKEN:
        return None
    return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)


async def health(request: Request):
    denied = _auth(request)
    # health stays open for docker HEALTHCHECK even with token
    return JSONResponse(
        {
            "ok": True,
            "service": "cmcc-cloud-alive-webui-placeholder",
            "home": os.environ.get("HOME", ""),
            "note": "J3 will replace this module with cmcc_cloud_alive.webui.app",
        }
    )


async def index(request: Request):
    denied = _auth(request)
    if denied:
        return denied
    html = """<!doctype html>
<html><head><meta charset=utf-8><title>cmcc-cloud-alive</title></head>
<body>
<h1>cmcc-cloud-alive WebUI placeholder</h1>
<p>Health: <a href="/api/health">/api/health</a></p>
<p>Waiting for J3 Starlette app + static shell.</p>
</body></html>"""
    return HTMLResponse(html)


async def ready(request: Request):
    return PlainTextResponse("ready\n")


app = Starlette(
    routes=[
        Route("/", index),
        Route("/api/health", health),
        Route("/health", health),
        Route("/ready", ready),
    ]
)
