from __future__ import annotations

import asyncio
import ctypes
import threading
import time

import uvicorn
import webview

from app import app
from qr_hub import TABLET_PORT, tablet_app

LOCAL_HOST = "127.0.0.1"
LOCAL_PORT = 8765
LOCAL_URL = f"http://{LOCAL_HOST}:{LOCAL_PORT}"


def show_error(message: str, title: str = "RENTRI BOOMER - Errore di avvio") -> None:
    try:
        ctypes.windll.user32.MessageBoxW(None, message, title, 0x10 | 0x0)
    except Exception:
        pass


def start_server(application, host: str, port: int, name: str):
    config = uvicorn.Config(
        application,
        host=host,
        port=port,
        reload=False,
        access_log=False,
        log_level="warning",
    )
    server = uvicorn.Server(config)

    def run() -> None:
        asyncio.run(server.serve())

    thread = threading.Thread(target=run, name=name, daemon=True)
    thread.start()
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if server.started:
            return server, thread
        if not thread.is_alive():
            raise RuntimeError(
                f"Il servizio {name} non è riuscito ad avviarsi sulla porta {port}. "
                "Verifica che la porta non sia già utilizzata da un'altra versione della BOOMER."
            )
        time.sleep(0.2)
    server.should_exit = True
    raise RuntimeError(f"Il servizio {name} non ha risposto entro 25 secondi (porta {port}).")


if __name__ == "__main__":
    api_server = tablet_server = None
    api_thread = tablet_thread = None
    try:
        api_server, api_thread = start_server(app, LOCAL_HOST, LOCAL_PORT, "RENTRI-API")
        # Il display è un'app separata: espone soltanto la pagina QR e solo all'IP autorizzato.
        tablet_server, tablet_thread = start_server(tablet_app, "0.0.0.0", TABLET_PORT, "RENTRI-QR-TABLET")
        webview.create_window(
            "RENTRI BOOMER - Truccolo Angelo",
            LOCAL_URL,
            width=1480,
            height=940,
            resizable=True,
            confirm_close=True,
        )
        webview.start(gui="edgechromium", debug=False)
    except Exception as exc:
        show_error(
            f"Non è stato possibile avviare RENTRI BOOMER.\n\nDettaglio: {exc}\n\n"
            "Chiudi eventuali altre finestre BOOMER e riprova. "
            "Se il problema riguarda WebView2, chiedi all'amministratore di installare Microsoft Edge WebView2 Runtime."
        )
    finally:
        for server in (tablet_server, api_server):
            if server is not None:
                server.should_exit = True
        for thread in (tablet_thread, api_thread):
            if thread is not None:
                thread.join(timeout=5)
