from __future__ import annotations

import asyncio
import socket
import threading
import time

import uvicorn
import webview

from app import app

HOST = "127.0.0.1"
PORT = 8765
URL = f"http://{HOST}:{PORT}"


def run_server() -> None:
    config = uvicorn.Config(
        app,
        host=HOST,
        port=PORT,
        reload=False,
        access_log=False,
        log_level="warning",
    )
    server = uvicorn.Server(config)
    asyncio.run(server.serve())


def wait_for_server(host: str, port: int, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    last_error: Exception | None = None

    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.2)

    raise RuntimeError(f"Server non pronto su {host}:{port}") from last_error


if __name__ == "__main__":
    threading.Thread(target=run_server, daemon=True).start()
    wait_for_server(HOST, PORT)

    webview.create_window(
        "RENTRI — Gestione FIR digitali",
        URL,
        width=1500,
        height=950,
        resizable=True,
        confirm_close=True,
    )
    webview.start(debug=False)