from __future__ import annotations

import base64
import ipaddress
import os
import re
import threading
import time
from datetime import datetime, timezone
from html import escape
from typing import Any, Dict

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

# Rete locale: il tablet è autorizzato per IP e non vede le API del gestionale.
TABLET_IP = os.getenv("RENTRI_TABLET_IP", "192.168.1.11").strip() or "192.168.1.11"
TABLET_PC_IP = os.getenv("RENTRI_TABLET_PC_IP", "192.168.1.70").strip() or "192.168.1.70"
TABLET_PORT = int(os.getenv("RENTRI_TABLET_PORT", "8766"))
TABLET_URL = f"http://{TABLET_PC_IP}:{TABLET_PORT}/"


def _parse_ip_list(raw_value: str) -> set[str]:
    """Legge IP separati da virgola, punto e virgola o ritorno a capo."""
    result: set[str] = set()
    for item in re.split(r"[,;\r\n]+", raw_value or ""):
        item = item.strip()
        if not item:
            continue
        try:
            result.add(ipaddress.ip_address(item).compressed)
        except ValueError as exc:
            raise ValueError(
                f"Indirizzo IP non valido in RENTRI_TABLET_SENDER_IPS: {item}"
            ) from exc
    return result


def _normalize_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            return address.ipv4_mapped.compressed
        return address.compressed
    except ValueError:
        return (value or "").strip()


# La lista autorizza i PC che inviano il QR al computer che ospita il servizio.
# Il PC centrale è incluso automaticamente per mantenere compatibile l'uso da un solo PC.
TABLET_SENDER_IPS = _parse_ip_list(os.getenv("RENTRI_TABLET_SENDER_IPS", ""))
TABLET_SENDER_IPS.add(_normalize_ip(TABLET_PC_IP))

_lock = threading.Lock()
_state: Dict[str, Any] = {
    "active": False,
    "version": "0",
    "numero_fir": "",
    "qr_base64": "",
    "updated_at": "",
    "last_seen": 0.0,
}


def publish_tablet_qr(numero_fir: str, png_bytes: bytes) -> None:
    if not png_bytes or not png_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("Il QR da inviare al tablet non è un'immagine PNG valida.")
    if len(png_bytes) > 3 * 1024 * 1024:
        raise ValueError("L'immagine QR è troppo grande per la visualizzazione sul tablet.")
    with _lock:
        _state.update({
            "active": True,
            "version": str(time.time_ns()),
            "numero_fir": str(numero_fir).strip()[:100],
            "qr_base64": base64.b64encode(png_bytes).decode("ascii"),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })


def clear_tablet_qr() -> None:
    with _lock:
        _state.update({
            "active": False,
            "version": str(time.time_ns()),
            "numero_fir": "",
            "qr_base64": "",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })


def get_tablet_status() -> Dict[str, Any]:
    with _lock:
        last_seen = float(_state.get("last_seen") or 0)
        return {
            "ok": True,
            "tablet_ip": TABLET_IP,
            "pc_ip": TABLET_PC_IP,
            "port": TABLET_PORT,
            "url": TABLET_URL,
            "connected": bool(last_seen and (time.time() - last_seen) <= 8),
            "active": bool(_state.get("active")),
            "numero_fir": _state.get("numero_fir", ""),
            "updated_at": _state.get("updated_at", ""),
        }


TABLET_HTML = r'''<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<meta name="theme-color" content="#102318">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>RENTRI · QR Bancone</title>
<style>
:root{color-scheme:dark;font-family:Arial,Helvetica,sans-serif;background:#102318;color:#fff}
*{box-sizing:border-box}
html,body{height:100%;width:100%;margin:0;overflow:hidden}
body{display:flex;align-items:center;justify-content:center;padding:clamp(12px,2.4vw,30px);background:radial-gradient(circle at 50% 35%,#294b36 0,#172d20 55%,#0b1710 100%)}
main{width:min(100%,1050px);height:100%;max-height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:clamp(10px,2vh,22px);text-align:center}
.brand{font-size:clamp(14px,2vw,20px);font-weight:800;letter-spacing:.16em;text-transform:uppercase;color:#b8d7bf}
.headline{font-size:clamp(24px,4vw,42px);font-weight:900;line-height:1.08;letter-spacing:.02em}
.number{font-size:clamp(18px,2.8vw,30px);font-weight:800;color:#d9f4df;letter-spacing:.05em}
.qr-frame{display:flex;align-items:center;justify-content:center;background:#fff;border-radius:20px;padding:clamp(12px,2vw,22px);box-shadow:0 20px 70px #0008;min-width:0;min-height:0;max-width:min(78vw,72vh);max-height:min(78vw,72vh);width:min(68vh,68vw);aspect-ratio:1;overflow:hidden}
#qr{display:none;width:100%;height:100%;object-fit:contain;image-rendering:auto;filter:none}
.waiting{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;color:#d8e7dc}
.waiting-icon{font-size:clamp(58px,10vw,112px);line-height:1}
.waiting-title{font-size:clamp(23px,3.8vw,38px);font-weight:900}
.waiting-text{font-size:clamp(15px,2vw,20px);color:#b4c8b9;max-width:620px;line-height:1.4}
.footer{font-size:clamp(12px,1.5vw,16px);color:#b8cdbd}
.status{position:fixed;left:12px;right:12px;bottom:10px;text-align:center;font-size:12px;color:#99b09f;opacity:.85}
.error{position:fixed;inset:0;background:#351414;display:none;align-items:center;justify-content:center;text-align:center;padding:28px;font-size:22px;font-weight:800}
@media (orientation:portrait){.qr-frame{width:min(78vw,58vh);max-width:78vw;max-height:58vh}}
</style>
</head>
<body>
<main>
  <div class="brand">TRUCCOLO ANGELO · RENTRI</div>
  <div id="waiting" class="waiting">
    <div class="waiting-icon">▦</div>
    <div class="waiting-title">IN ATTESA DEL CODICE</div>
    <div class="waiting-text">Quando l'ufficio invierà un formulario, il QR apparirà qui automaticamente.</div>
  </div>
  <div id="active" style="display:none;flex-direction:column;align-items:center;gap:clamp(8px,1.5vh,16px);min-height:0;max-height:100%;">
    <div class="headline">SCANSIONA IL CODICE</div>
    <div class="number" id="firNumber"></div>
    <div class="qr-frame"><img id="qr" alt="QR del formulario RENTRI"></div>
    <div class="footer">Inquadra il codice con la fotocamera del telefono</div>
  </div>
</main>
<div class="status" id="status">Collegamento al gestionale…</div>
<div class="error" id="error">Connessione interrotta.<br>Verifica che il Wi-Fi sia attivo.</div>
<script>
let version='';
let lastContact=Date.now();
let wakeLock=null;
const $=id=>document.getElementById(id);
function showOffline(){
  $('error').style.display='flex';
  $('active').style.display='none';
  $('waiting').style.display='none';
  $('status').textContent='Il gestionale non è raggiungibile';
}
function showOnline(){
  $('error').style.display='none';
  $('status').textContent='Collegato al gestionale · Schermo pronto per la scansione';
}
async function refreshState(){
  try{
    const response=await fetch('/state?since='+encodeURIComponent(version),{cache:'no-store'});
    if(response.status===204){lastContact=Date.now();showOnline();return;}
    if(!response.ok)throw new Error('HTTP '+response.status);
    const data=await response.json();
    version=String(data.version||version);
    lastContact=Date.now();
    showOnline();
    if(data.active&&data.qr_base64){
      $('qr').src='data:image/png;base64,'+data.qr_base64;
      $('qr').style.display='block';
      $('firNumber').textContent=data.numero_fir||'';
      $('waiting').style.display='none';
      $('active').style.display='flex';
    }else{
      $('qr').removeAttribute('src');
      $('qr').style.display='none';
      $('active').style.display='none';
      $('waiting').style.display='flex';
    }
  }catch(error){
    if(Date.now()-lastContact>4500)showOffline();
  }
}
async function keepAwake(){
  try{
    if('wakeLock' in navigator && !wakeLock){wakeLock=await navigator.wakeLock.request('screen');wakeLock.addEventListener('release',()=>{wakeLock=null;});}
  }catch(e){}
}
document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')keepAwake();});
keepAwake();
refreshState();
setInterval(refreshState,1200);
</script>
</body>
</html>'''


tablet_app = FastAPI(
    title="RENTRI BOOMER - QR Tablet",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@tablet_app.middleware("http")
async def restrict_tablet_ip(request: Request, call_next):
    remote = _normalize_ip(request.client.host if request.client else "")
    path = request.url.path

    # Il tablet può soltanto aprire la pagina e leggere lo stato del display.
    if path in {"/", "/state", "/health"}:
        if remote != _normalize_ip(TABLET_IP):
            return JSONResponse(
                status_code=403,
                content={"detail": "Questo display è riservato al tablet autorizzato."},
                headers={"Cache-Control": "no-store"},
            )
        return await call_next(request)

    # I PC autorizzati possono pubblicare/interrompere il QR e leggere lo stato.
    if path in {"/publish", "/clear", "/status"}:
        if remote not in TABLET_SENDER_IPS:
            return JSONResponse(
                status_code=403,
                content={
                    "detail": (
                        f"Il PC con IP {remote or 'sconosciuto'} non è autorizzato a inviare QR. "
                        "Aggiungi il suo IP a RENTRI_TABLET_SENDER_IPS nel file .env del PC che ospita il tablet."
                    )
                },
                headers={"Cache-Control": "no-store"},
            )
        return await call_next(request)

    return JSONResponse(status_code=404, content={"detail": "Risorsa non disponibile."})


@tablet_app.get("/", response_class=HTMLResponse)
async def tablet_home() -> HTMLResponse:
    return HTMLResponse(TABLET_HTML, headers={"Cache-Control": "no-store"})


@tablet_app.get("/state")
async def tablet_state(since: str = Query(default="")) -> Response:
    with _lock:
        _state["last_seen"] = time.time()
        version = str(_state.get("version") or "0")
        if since and since == version:
            return Response(status_code=204, headers={"Cache-Control": "no-store"})
        payload = {
            "active": bool(_state.get("active")),
            "version": version,
            "numero_fir": _state.get("numero_fir", ""),
            "qr_base64": _state.get("qr_base64", ""),
            "updated_at": _state.get("updated_at", ""),
        }
    return JSONResponse(payload, headers={"Cache-Control": "no-store"})


@tablet_app.get("/health")
async def tablet_health() -> Dict[str, Any]:
    with _lock:
        _state["last_seen"] = time.time()
    return {"ok": True, "service": "RENTRI BOOMER QR Tablet"}

@tablet_app.post("/publish")
async def tablet_publish_from_pc(request: Request, numero_fir: str = Query(..., min_length=1, max_length=100)) -> Dict[str, Any]:
    """Riceve dal PC autorizzato il PNG già estratto da RENTRI e lo mostra sul tablet."""
    content_length = request.headers.get("content-length", "")
    try:
        if content_length and int(content_length) > 3 * 1024 * 1024:
            return JSONResponse(status_code=413, content={"detail": "Immagine QR troppo grande."})
    except ValueError:
        return JSONResponse(status_code=400, content={"detail": "Intestazione Content-Length non valida."})
    png_bytes = await request.body()
    try:
        publish_tablet_qr(numero_fir, png_bytes)
    except ValueError as exc:
        return JSONResponse(status_code=422, content={"detail": str(exc)})
    return {"ok": True, "message": "QR ricevuto dal PC e pubblicato sul display.", **get_tablet_status()}


@tablet_app.post("/clear")
async def tablet_clear_from_pc() -> Dict[str, Any]:
    clear_tablet_qr()
    return {"ok": True, "message": "Display QR svuotato."}


@tablet_app.get("/status")
async def tablet_sender_status() -> Dict[str, Any]:
    return get_tablet_status()

