from __future__ import annotations

import os
import sys
import io
import base64
import logging
import json
import asyncio
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import quote

import httpx
import fitz
from PIL import Image, ImageStat
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

BASE_DIR = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent

try:
    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / ".env", override=False)
except Exception:
    pass

from rentri_client import RentriApiError, RentriClient
from usb_signer import UsbSignerError, list_windows_signing_certificates, sign_digest_with_windows_certificate
from qr_hub import TABLET_PC_IP, TABLET_PORT, TABLET_URL

app = FastAPI(title="RENTRI — Gestione FIR digitali")


def _boomer_data_dir() -> Path:
    """Cartella persistente per le preferenze locali della BOOMER, separata da RENTRI."""
    configured = os.getenv("RENTRI_BOOMER_DATA_DIR", "").strip()
    if configured:
        folder = Path(configured).expanduser()
    elif os.name == "nt":
        root = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA")
        folder = (Path(root) / "TruccoloAngelo" / "RENTRI_BOOMER") if root else (Path.home() / "AppData" / "Local" / "TruccoloAngelo" / "RENTRI_BOOMER")
    else:
        folder = Path.home() / ".local" / "share" / "TruccoloAngelo" / "RENTRI_BOOMER"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


BOOMER_DATA_DIR = _boomer_data_dir()
HIDDEN_FIRS_FILE = BOOMER_DATA_DIR / "hidden_firs.json"


def _read_hidden_firs() -> List[Dict[str, Any]]:
    if not HIDDEN_FIRS_FILE.exists():
        return []
    try:
        parsed = json.loads(HIDDEN_FIRS_FILE.read_text(encoding="utf-8"))
        items = parsed.get("items", []) if isinstance(parsed, dict) else []
        return items if isinstance(items, list) else []
    except (OSError, json.JSONDecodeError):
        logging.exception("Impossibile leggere l'archivio locale dei formulari nascosti")
        raise HTTPException(status_code=500, detail="Archivio locale dei formulari nascosti non leggibile. Avvisa l'amministratore; nessun formulario è stato modificato su RENTRI.")


def _write_hidden_firs(items: List[Dict[str, Any]]) -> None:
    temporary = HIDDEN_FIRS_FILE.with_suffix(".json.tmp")
    payload = {"version": 1, "updated_at": datetime.now(timezone.utc).isoformat(), "items": items}
    try:
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temporary, HIDDEN_FIRS_FILE)
    except OSError as exc:
        logging.exception("Impossibile salvare l'archivio locale dei formulari nascosti")
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise HTTPException(status_code=500, detail="Non è stato possibile salvare l'elenco dei formulari nascosti sul computer. Controlla i permessi della cartella o avvisa l'amministratore.") from exc

# Numero unità locale: va impostato in .env come RENTRI_NUM_ISCR_SITO (nessun valore di default
# nel codice, per non pubblicare dati specifici dell'operatore in un repository pubblico).
DEFAULT_NUM_ISCR_SITO = ""


def _resolved_p12_path() -> str:
    configured = os.getenv("RENTRI_P12_PATH", "./certificati/interoperabilita_demo.p12").strip()
    path = Path(configured).expanduser()
    if not path.is_absolute():
        path = BASE_DIR / path
    return str(path.resolve())


def _effective_num_iscr_sito() -> str:
    return os.getenv("RENTRI_NUM_ISCR_SITO", DEFAULT_NUM_ISCR_SITO).strip()


def _init_client() -> tuple[Optional[RentriClient], Optional[str]]:
    try:
        instance = RentriClient(
            env=os.getenv("RENTRI_ENV", "demo"),
            demo_base_url=os.getenv("RENTRI_DEMO_BASE_URL", "https://demoapi.rentri.gov.it"),
            prod_base_url=os.getenv("RENTRI_PROD_BASE_URL", "https://api.rentri.gov.it"),
            p12_path=_resolved_p12_path(),
            p12_password=os.getenv("RENTRI_P12_PASSWORD"),
            issuer=os.getenv("RENTRI_ISSUER", os.getenv("RENTRI_IDENTIFICATIVO", "")),
            identificativo=os.getenv("RENTRI_IDENTIFICATIVO", ""),
            num_iscr_sito=_effective_num_iscr_sito(),
            jwt_audience=os.getenv("RENTRI_JWT_AUDIENCE"),
            jwt_subject=os.getenv("RENTRI_JWT_SUBJECT"),
        )
        return instance, None
    except Exception as exc:
        return None, str(exc)


client, init_error = _init_client()


class TabletPublishPayload(BaseModel):
    numero_fir: str = Field(..., min_length=1, max_length=100)


class AccettazionePayload(BaseModel):
    """Dati inseriti dall'operatore; il backend costruisce il JSON RENTRI."""
    tipo_accettazione: Literal["A", "P", "R"]
    quantita_accettata: float = Field(..., ge=0)
    data_ora_arrivo: datetime
    reply_to: Optional[str] = None


class HashPayload(BaseModel):
    # RENTRI richiede il certificato X.509 del firmatario nel body:
    # {"certificato": "<certificato DER codificato Base64>"}.
    certificato_base64: str = Field(..., min_length=1)
    reply_to: Optional[str] = None


class FirmaPayload(BaseModel):
    token: str = Field(..., min_length=1)
    firma_base64: str = Field(..., min_length=1)
    certificato_base64: str = Field(..., min_length=1)
    identificativo_utente: str = Field(..., min_length=1)
    reply_to: Optional[str] = None


class UsbSignAcquirePayload(BaseModel):
    numero_fir: str = Field(..., min_length=1)
    thumbprint: str = Field(..., min_length=20)
    digest_to_sign: str = Field(..., min_length=1)
    token: str = Field(..., min_length=1)
    certificato_base64: str = Field(..., min_length=1)
    identificativo_utente: str = Field(..., min_length=1)
    reply_to: Optional[str] = None


class RollbackPayload(BaseModel):
    reply_to: Optional[str] = None


class CaAuthorizePayload(BaseModel):
    credentials_id: str = Field(..., min_length=1)
    digest_to_sign: str = Field(..., min_length=1)
    numero_fir: str = Field(..., min_length=1)
    auth_data: List[Dict[str, str]] = Field(default_factory=list)
    client_data: Optional[str] = None
    reply_to: Optional[str] = None


class CaConfirmationPayload(BaseModel):
    credentials_id: str = Field(..., min_length=1)
    handle: str = Field(..., min_length=1)
    otp: Optional[str] = ""
    pin: str = Field(..., min_length=1)
    allowed: bool = True
    reply_to: Optional[str] = None


class CaSignHashPayload(BaseModel):
    credentials_id: str = Field(..., min_length=1)
    sad: str = Field(..., min_length=1)
    digest_to_sign: str = Field(..., min_length=1)
    certificato_base64: str = Field(..., min_length=1)
    client_data: Optional[str] = None
    reply_to: Optional[str] = None


def _raise_api_error(exc: RentriApiError) -> None:
    payload: Dict[str, Any] = {
        "error": exc.message,
        "problem_details": exc.detail,
    }
    if exc.status_code == 403:
        payload["hint"] = (
            "RENTRI ha rifiutato l'operazione per autorizzazione/visibilità o per lo stato del FIR. "
            "Il dettaglio restituito dall'API è riportato in problem_details.response."
        )
    if exc.is_invalid_audience():
        payload["hint"] = (
            "Il gateway AgID/RENTRI ha rifiutato il claim 'aud' del JWT. "
            "Controlla RENTRI_JWT_AUDIENCE per l'ambiente selezionato."
        )
    if exc.is_issuer_banned():
        payload["hint"] = "L'issuer configurato risulta bloccato da RENTRI."
    if exc.is_maintenance():
        payload["hint"] = "Il servizio RENTRI risulta in manutenzione."
    if exc.retry_after is not None:
        payload["retry_after_seconds"] = exc.retry_after
    raise HTTPException(status_code=exc.status_code, detail=payload)


def _require_client() -> RentriClient:
    if init_error or client is None:
        raise HTTPException(status_code=500, detail={"init_error": init_error})
    return client


@app.get("/api/info")
async def api_info() -> Dict[str, Any]:
    current = client
    rollback_suffix = os.getenv("RENTRI_ROLLBACK_SUFFIX", "rollback-firma").strip() or "rollback-firma"
    if rollback_suffix == "rollback":
        rollback_suffix = "rollback-firma"
    return {
        "init_error": init_error,
        "client": current.get_certificate_info() if current else None,
        "runtime": current.get_runtime_info() if current else None,
        "num_iscr_sito": _effective_num_iscr_sito(),
        "identificativo": os.getenv("RENTRI_IDENTIFICATIVO", ""),
        # Nome dell'operatore usato come riscontro leggibile quando il riepilogo
        # RENTRI non espone il codice fiscale nel record sintetico.
        "ragione_sociale": (os.getenv("RENTRI_RAGIONE_SOCIALE", "").strip() or "TRUCCOLO ANGELO SRL"),
        "env": os.getenv("RENTRI_ENV", "demo"),
        "rollback_suffix": rollback_suffix,
        "ca_credentials_id": os.getenv("RENTRI_CA_CREDENTIALS_ID", "").strip(),
        "gestionale_user_id": os.getenv("RENTRI_GESTIONALE_USER_ID", "TRUCCOLO-PC").strip() or "TRUCCOLO-PC",
    }


@app.get("/api/formulari")
async def api_formulari(
    filtro_tipo: str = Query(default="sito", pattern="^(sito|soggetto)$"),
    stato: Optional[str] = Query(default=None),
    numero_fir: Optional[str] = Query(default=None),
    codice_blocco: Optional[str] = Query(default=None),
    codice_eer: Optional[str] = Query(default=None, max_length=8),
    num_iscr_sito: Optional[str] = Query(default=None),
    identificativo_soggetto: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=100),
) -> Dict[str, Any]:
    current = _require_client()
    try:
        statuses = [stato] if stato and stato != "TUTTI" else None
        if filtro_tipo == "sito":
            return await current.elenco_formulari(
                num_iscr_sito=(num_iscr_sito or _effective_num_iscr_sito()),
                identificativo_soggetto=None,
                numero_fir=numero_fir,
                codice_blocco=codice_blocco,
                codice_eer=codice_eer,
                stati=statuses,
                paging_page=page,
                paging_page_size=page_size,
            )
        return await current.elenco_formulari(
            num_iscr_sito=None,
            identificativo_soggetto=(identificativo_soggetto or os.getenv("RENTRI_IDENTIFICATIVO", "")),
            numero_fir=numero_fir,
            codice_blocco=codice_blocco,
            codice_eer=codice_eer,
            stati=statuses,
            paging_page=page,
            paging_page_size=page_size,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"validation_error": str(exc)})
    except RentriApiError as exc:
        _raise_api_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"unexpected_error": str(exc)})


@app.get("/api/formulari/{numero_fir}")
async def api_dettaglio(numero_fir: str) -> Dict[str, Any]:
    current = _require_client()
    try:
        return await current.dettaglio_fir(numero_fir)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"validation_error": str(exc)})
    except RentriApiError as exc:
        _raise_api_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"unexpected_error": str(exc)})




@app.get("/api/formulari/{numero_fir}/pdf")
async def api_formulario_pdf(numero_fir: str) -> Response:
    """Restituisce il PDF completo del FIR, autenticandosi verso RENTRI."""
    current = _require_client()
    pdf_url = f"{current.service_base_url.rstrip('/')}/{quote(numero_fir, safe='')}/pdf"
    try:
        headers = current._build_headers(
            extra_headers={"Accept": "application/json, application/pdf"}
        )
        async with httpx.AsyncClient(timeout=current.timeout, follow_redirects=False) as http_client:
            response = await http_client.get(pdf_url, headers=headers)

        if response.status_code == 204:
            raise HTTPException(status_code=404, detail={"validation_error": "RENTRI non ha restituito un PDF per questo formulario."})
        if response.status_code != 200:
            try:
                detail = response.json()
            except Exception:
                detail = {"raw_response": response.text[:1000]}
            raise HTTPException(status_code=response.status_code, detail=detail)

        response_body = response.content
        content_type = response.headers.get("content-type", "").lower()
        if "json" in content_type or response_body.lstrip().startswith(b"{"):
            try:
                payload = response.json()
            except ValueError as exc:
                raise HTTPException(status_code=502, detail={"pdf_error": "RENTRI ha restituito JSON non leggibile per la stampa PDF."}) from exc
            encoded_content = payload.get("content") if isinstance(payload, dict) else None
            if not encoded_content:
                raise HTTPException(status_code=404, detail={"pdf_error": "La risposta RENTRI non contiene il PDF del formulario."})
            if isinstance(encoded_content, str):
                encoded_content = encoded_content.strip()
                if encoded_content.startswith("data:") and "," in encoded_content:
                    encoded_content = encoded_content.split(",", 1)[1]
                try:
                    pdf_bytes = base64.b64decode("".join(encoded_content.split()), validate=False)
                except Exception as exc:
                    raise HTTPException(status_code=502, detail={"pdf_error": "Il contenuto PDF Base64 ricevuto da RENTRI non è valido."}) from exc
            elif isinstance(encoded_content, list):
                try:
                    pdf_bytes = bytes(encoded_content)
                except Exception as exc:
                    raise HTTPException(status_code=502, detail={"pdf_error": "Il contenuto PDF RENTRI non è convertibile in byte."}) from exc
            else:
                raise HTTPException(status_code=502, detail={"pdf_error": "Tipo del contenuto PDF RENTRI non supportato."})
        else:
            pdf_bytes = response_body

        if not pdf_bytes or b"%PDF-" not in pdf_bytes[:1024]:
            raise HTTPException(status_code=502, detail={"pdf_error": "La risposta dell'API non contiene un PDF valido."})

        safe_name = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in numero_fir)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'inline; filename="{safe_name or "FIR"}.pdf"',
                "Cache-Control": "no-store",
            },
        )
    except HTTPException:
        raise
    except RentriApiError as exc:
        _raise_api_error(exc)
    except Exception as exc:
        logging.getLogger(__name__).exception("Errore download PDF FIR %s", numero_fir)
        raise HTTPException(status_code=500, detail={"unexpected_error": f"Errore durante il recupero del PDF: {type(exc).__name__}: {exc}"}) from exc


@app.get("/api/formulari/{numero_fir}/qr")
async def api_formulario_qr(
    numero_fir: str,
    page: int = Query(default=1, ge=1),
    x: float = Query(default=479),
    y: float = Query(default=78),
    width: float = Query(default=86, gt=0),
    height: float = Query(default=86, gt=0),
    scale: Literal["thumb", "large"] = Query(default="thumb"),
) -> Response:
    """Scarica il PDF del FIR da RENTRI e restituisce il ritaglio PNG del QR.

    RENTRI documenta questa risposta come JSON con `content` Base64;
    alcuni ambienti/proxy possono però restituire direttamente i byte PDF.
    Gestiamo entrambi i formati.
    """
    current = _require_client()
    pdf_url = f"{current.service_base_url.rstrip('/')}/{quote(numero_fir, safe='')}/pdf"
    try:
        # L'endpoint RENTRI documentato restituisce application/json con:
        # {"nome_file": ..., "mime": "application/pdf", "content": "<base64>"}
        headers = current._build_headers(
            extra_headers={"Accept": "application/json, application/pdf"}
        )
        async with httpx.AsyncClient(timeout=current.timeout, follow_redirects=False) as http_client:
            response = await http_client.get(pdf_url, headers=headers)

        if response.status_code == 204:
            raise HTTPException(
                status_code=404,
                detail={"validation_error": "RENTRI non ha restituito un PDF per questo formulario."},
            )
        if response.status_code != 200:
            try:
                detail = response.json()
            except Exception:
                detail = {"raw_response": response.text[:1000]}
            raise HTTPException(status_code=response.status_code, detail=detail)

        response_body = response.content
        content_type = response.headers.get("content-type", "").lower()

        # Caso 1: risposta documentata JSON con il PDF codificato Base64.
        if "json" in content_type or response_body.lstrip().startswith(b"{"):
            try:
                payload = response.json()
            except ValueError as exc:
                raise HTTPException(
                    status_code=502,
                    detail={"qr_error": "RENTRI ha restituito JSON non leggibile per la stampa PDF."},
                ) from exc

            if not isinstance(payload, dict):
                raise HTTPException(
                    status_code=502,
                    detail={"qr_error": "Formato della risposta PDF RENTRI non riconosciuto."},
                )

            encoded_content = payload.get("content")
            if not encoded_content:
                raise HTTPException(
                    status_code=404,
                    detail={"qr_error": "La risposta RENTRI non contiene il PDF del formulario."},
                )

            if isinstance(encoded_content, str):
                encoded_content = encoded_content.strip()
                if encoded_content.startswith("data:") and "," in encoded_content:
                    encoded_content = encoded_content.split(",", 1)[1]
                try:
                    # `string<byte>` nell'OpenAPI RENTRI è una stringa Base64.
                    pdf_bytes = base64.b64decode("".join(encoded_content.split()), validate=False)
                except Exception as exc:
                    raise HTTPException(
                        status_code=502,
                        detail={"qr_error": "Il contenuto PDF Base64 ricevuto da RENTRI non è valido."},
                    ) from exc
            elif isinstance(encoded_content, list):
                try:
                    pdf_bytes = bytes(encoded_content)
                except Exception as exc:
                    raise HTTPException(
                        status_code=502,
                        detail={"qr_error": "Il contenuto PDF RENTRI non è convertibile in byte."},
                    ) from exc
            else:
                raise HTTPException(
                    status_code=502,
                    detail={"qr_error": "Tipo del contenuto PDF RENTRI non supportato."},
                )
        else:
            # Caso 2: l'endpoint/proxy restituisce direttamente application/pdf.
            pdf_bytes = response_body

        # Evita di passare a PyMuPDF una risposta JSON/HTML o un PDF vuoto.
        if not pdf_bytes or b"%PDF-" not in pdf_bytes[:1024]:
            raise HTTPException(
                status_code=502,
                detail={"qr_error": "La risposta dell'API non contiene un PDF valido (firma %PDF- assente)."},
            )

        try:
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        except Exception as exc:
            raise HTTPException(
                status_code=422,
                detail={"qr_error": f"Il PDF restituito da RENTRI non è leggibile: {type(exc).__name__}: {exc}"},
            ) from exc

        try:
            if page > len(doc):
                raise HTTPException(
                    status_code=404,
                    detail={"validation_error": f"Pagina {page} non disponibile nel PDF."},
                )

            pdf_page = doc[page - 1]
            page_rect = pdf_page.rect

            # Le coordinate fornite sono riferite all'origine in alto a sinistra.
            # Manteniamo un secondo tentativo con origine in basso a sinistra per
            # tollerare PDF che usano il sistema di coordinate PDF tradizionale.
            candidates = [
                fitz.Rect(x, y, x + width, y + height),
                fitz.Rect(
                    x,
                    page_rect.height - (y + height),
                    x + width,
                    page_rect.height - y,
                ),
            ]

            best_bytes = None
            best_score = -1.0
            zoom = 3.0 if scale == "thumb" else 8.0
            matrix = fitz.Matrix(zoom, zoom)

            for rect in candidates:
                clip = rect & page_rect
                if clip.is_empty:
                    continue
                pix = pdf_page.get_pixmap(matrix=matrix, clip=clip, alpha=False)
                if pix.width <= 0 or pix.height <= 0:
                    continue
                img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
                gray = img.convert("L")
                stat = ImageStat.Stat(gray)
                hist = gray.histogram()
                dark = sum(hist[:235]) / max(1, gray.width * gray.height)
                contrast = stat.stddev[0]
                score = (dark * 2.0) + contrast
                buf = io.BytesIO()
                img.save(buf, format="PNG")
                if score > best_score:
                    best_score = score
                    best_bytes = buf.getvalue()

            if best_bytes is None:
                raise HTTPException(
                    status_code=422,
                    detail={"validation_error": "Impossibile ritagliare il QR dalle coordinate indicate nel PDF."},
                )
            return Response(content=best_bytes, media_type="image/png", headers={"Cache-Control": "no-store"})
        finally:
            doc.close()

    except HTTPException:
        raise
    except RentriApiError as exc:
        _raise_api_error(exc)
    except Exception as exc:
        # Il dettaglio effettivo è riportato nel log Python; al client restituiamo
        # un messaggio diagnostico utile senza esporre token o intestazioni.
        logging.getLogger(__name__).exception("Errore estrazione QR FIR %s", numero_fir)
        raise HTTPException(
            status_code=500,
            detail={"unexpected_error": f"Errore durante l'estrazione del QR: {type(exc).__name__}: {exc}"},
        ) from exc


@app.post("/api/tablet/publish")
async def api_tablet_publish(body: TabletPublishPayload) -> Dict[str, Any]:
    """Estrae il QR da RENTRI e lo inoltra al PC centrale che gestisce il display."""
    numero = body.numero_fir.strip()
    if not numero:
        raise HTTPException(status_code=400, detail={"validation_error": "Seleziona prima un formulario."})
    qr_response = await api_formulario_qr(
        numero_fir=numero, page=1, x=479, y=78, width=86, height=86, scale="large"
    )
    if not isinstance(qr_response, Response) or qr_response.media_type != "image/png":
        raise HTTPException(status_code=502, detail={"tablet_error": "Non è stato possibile preparare l'immagine QR del formulario."})

    publish_url = f"{TABLET_URL.rstrip('/')}/publish"
    try:
        async with httpx.AsyncClient(timeout=20.0) as session:
            response = await session.post(
                publish_url,
                params={"numero_fir": numero},
                content=qr_response.body,
                headers={"Content-Type": "image/png", "Cache-Control": "no-store"},
            )
            response.raise_for_status()
            remote_status = response.json()
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text[:1000] or f"HTTP {exc.response.status_code}"
        raise HTTPException(
            status_code=502,
            detail={"tablet_error": f"Il PC che ospita il display ha rifiutato l'invio: {detail}"},
        ) from exc
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "tablet_error": (
                    f"Non riesco a raggiungere il PC del display ({TABLET_PC_IP}:{TABLET_PORT}). "
                    "Verifica che BOOMER sia aperto su quel PC e che la porta 8766 sia consentita nella rete privata."
                )
            },
        ) from exc
    return {
        "ok": True,
        "message": "QR inviato al PC che gestisce il display.",
        **remote_status,
    }


@app.post("/api/tablet/clear")
async def api_tablet_clear() -> Dict[str, Any]:
    clear_url = f"{TABLET_URL.rstrip('/')}/clear"
    try:
        async with httpx.AsyncClient(timeout=8.0) as session:
            response = await session.post(clear_url, headers={"Cache-Control": "no-store"})
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail={"tablet_error": f"Il PC del display ha rifiutato il comando di arresto: HTTP {exc.response.status_code}."}) from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail={"tablet_error": f"PC del display non raggiungibile ({TABLET_PC_IP}:{TABLET_PORT})."}) from exc


@app.get("/api/tablet/status")
async def api_tablet_status() -> Dict[str, Any]:
    status_url = f"{TABLET_URL.rstrip('/')}/status"
    try:
        async with httpx.AsyncClient(timeout=5.0) as session:
            response = await session.get(status_url, headers={"Cache-Control": "no-store"})
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail={"tablet_error": f"Il PC del display ha risposto con HTTP {exc.response.status_code}."}) from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail={"tablet_error": f"PC del display non raggiungibile ({TABLET_PC_IP}:{TABLET_PORT})."}) from exc


@app.post("/api/formulari/{numero_fir}/accettazione")
async def api_accettazione(numero_fir: str, body: AccettazionePayload) -> Dict[str, Any]:
    current = _require_client()
    try:
        # Converte la data/ora del modulo in ISO-8601 UTC e costruisce qui
        # il payload: l'utente non deve conoscere né scrivere JSON.
        arrival = body.data_ora_arrivo
        if arrival.tzinfo is None:
            # Il browser invia normalmente un ISO con offset; in caso contrario
            # si assume l'orario locale configurato sul PC dell'operatore.
            arrival = arrival.astimezone()
        arrival_utc = arrival.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        return await current.invia_accettazione_fir(
            numero_fir=numero_fir,
            tipo_accettazione=body.tipo_accettazione,
            quantita_accettata=body.quantita_accettata,
            data_ora_arrivo=arrival_utc,
            reply_to=body.reply_to,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"validation_error": str(exc)})
    except RentriApiError as exc:
        _raise_api_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"unexpected_error": str(exc)})


@app.post("/api/formulari/{numero_fir}/hash")
async def api_hash(numero_fir: str, body: HashPayload) -> Dict[str, Any]:
    current = _require_client()
    try:
        return await current.genera_hash_fir(
            numero_fir=numero_fir,
            certificato_base64=body.certificato_base64,
            reply_to=body.reply_to,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"validation_error": str(exc)})
    except RentriApiError as exc:
        _raise_api_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"unexpected_error": str(exc)})


@app.get("/api/transazioni/{transazione_id}/status")
async def api_transazione_status(transazione_id: str) -> Dict[str, Any]:
    current = _require_client()
    try:
        return await current.stato_transazione(transazione_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"validation_error": str(exc)})
    except RentriApiError as exc:
        _raise_api_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"unexpected_error": str(exc)})


@app.get("/api/transazioni/{transazione_id}/result")
async def api_transazione_result(transazione_id: str) -> Dict[str, Any]:
    current = _require_client()
    try:
        return await current.esito_transazione(transazione_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"validation_error": str(exc)})
    except RentriApiError as exc:
        _raise_api_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"unexpected_error": str(exc)})


@app.post("/api/formulari/{numero_fir}/acquisizione-firma")
async def api_firma(numero_fir: str, body: FirmaPayload) -> Dict[str, Any]:
    current = _require_client()
    try:
        return await current.acquisizione_firma_fir(
            numero_fir=numero_fir,
            token=body.token,
            firma_base64=body.firma_base64,
            certificato_base64=body.certificato_base64,
            identificativo_utente=body.identificativo_utente,
            reply_to=body.reply_to,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"validation_error": str(exc)})
    except RentriApiError as exc:
        _raise_api_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"unexpected_error": str(exc)})


@app.get("/api/usb-signing/certificates")
async def api_usb_signing_certificates() -> Dict[str, Any]:
    """Elenca certificati con chiave privata esposti dagli store Windows."""
    try:
        return await asyncio.to_thread(list_windows_signing_certificates)
    except UsbSignerError as exc:
        raise HTTPException(status_code=400, detail={"usb_signing_error": str(exc)})
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"usb_signing_error": str(exc)})


@app.post("/api/usb-signing/sign-acquire")
async def api_usb_signing_sign_and_acquire(body: UsbSignAcquirePayload) -> Dict[str, Any]:
    """Firma localmente con la chiave hardware Windows e invia la firma a RENTRI.

    Il PIN non viene acquisito dal backend: il middleware CSP/KSP/InfoCert gestisce
    l'eventuale richiesta tramite la propria finestra protetta.
    """
    current = _require_client()
    try:
        signed = await asyncio.to_thread(
            sign_digest_with_windows_certificate,
            body.thumbprint,
            body.digest_to_sign,
            body.certificato_base64,
        )
        acquisition = await current.acquisizione_firma_fir(
            numero_fir=body.numero_fir,
            token=body.token,
            firma_base64=signed["signature_base64"],
            certificato_base64=signed["certificate_base64"],
            identificativo_utente=body.identificativo_utente,
            reply_to=body.reply_to,
        )
        return {
            "firma_locale": {
                "generata": True,
                "firmatario": signed.get("subject"),
                "ente_certificatore": signed.get("issuer"),
                "thumbprint": signed.get("thumbprint"),
                "algoritmo": signed.get("signature_algorithm"),
                "pin_memorizzato": False,
            },
            "acquisizione": acquisition,
        }
    except UsbSignerError as exc:
        raise HTTPException(status_code=400, detail={"usb_signing_error": str(exc)})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"validation_error": str(exc)})
    except RentriApiError as exc:
        _raise_api_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"unexpected_error": str(exc)})


@app.post("/api/formulari/{numero_fir}/rollback")
async def api_rollback(numero_fir: str, body: RollbackPayload) -> Dict[str, Any]:
    current = _require_client()
    try:
        # Endpoint ufficiale: POST /{numero_fir}/rollback-firma.
        # Compatibilità con una vecchia .env che riportava semplicemente "rollback".
        suffix = os.getenv("RENTRI_ROLLBACK_SUFFIX", "rollback-firma").strip() or "rollback-firma"
        if suffix == "rollback":
            suffix = "rollback-firma"
        return await current.rollback_ultima_firma(
            numero_fir=numero_fir,
            endpoint_suffix=suffix,
            reply_to=body.reply_to,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"validation_error": str(exc)})
    except RentriApiError as exc:
        _raise_api_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"unexpected_error": str(exc)})


@app.get("/api/ca-rentri/credentials")
async def api_ca_credentials(
    identificativo_soggetto: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    current = _require_client()
    try:
        # Priorità al valore esplicito della UI, altrimenti usa RENTRI_IDENTIFICATIVO.
        subject_id = (identificativo_soggetto or current.identificativo or "").strip()
        if not subject_id:
            raise ValueError(
                "Inserisci l'identificativo del soggetto abilitato nel campo "
                "'Identificativo soggetto' oppure valorizza RENTRI_IDENTIFICATIVO nella .env."
            )
        return await current.ca_elenco_credenziali(
            identificativo_soggetto=subject_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"validation_error": str(exc)})
    except RentriApiError as exc:
        _raise_api_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"unexpected_error": str(exc)})


@app.get("/api/ca-rentri/credentials-info")
async def api_ca_credentials_info(
    credentials_id: str = Query(..., min_length=1),
) -> Dict[str, Any]:
    current = _require_client()
    try:
        return await current.ca_info_credenziali(
            credentials_id=credentials_id,
            auth_info=True,
            lang="it-IT",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"validation_error": str(exc)})
    except RentriApiError as exc:
        _raise_api_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"unexpected_error": str(exc)})


@app.post("/api/ca-rentri/authorize")
async def api_ca_authorize(body: CaAuthorizePayload) -> Dict[str, Any]:
    current = _require_client()
    try:
        return await current.ca_autorizza_credenziali(
            credentials_id=body.credentials_id,
            numero_fir=body.numero_fir,
            digest_to_sign=body.digest_to_sign,
            auth_data=body.auth_data,
            client_data=body.client_data,
            reply_to=body.reply_to,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"validation_error": str(exc)})
    except RentriApiError as exc:
        _raise_api_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"unexpected_error": str(exc)})


@app.put("/api/ca-rentri/authorize-confirmation")
async def api_ca_confirmation(body: CaConfirmationPayload) -> Dict[str, Any]:
    current = _require_client()
    try:
        return await current.ca_conferma_autorizzazione(
            credentials_id=body.credentials_id,
            handle=body.handle,
            otp=body.otp or "",
            pin=body.pin,
            allowed=body.allowed,
            reply_to=body.reply_to,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"validation_error": str(exc)})
    except RentriApiError as exc:
        _raise_api_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"unexpected_error": str(exc)})


@app.post("/api/ca-rentri/sign-hash")
async def api_ca_sign_hash(body: CaSignHashPayload) -> Dict[str, Any]:
    current = _require_client()
    try:
        return await current.ca_firma_hash(
            credentials_id=body.credentials_id,
            sad=body.sad,
            digest_to_sign=body.digest_to_sign,
            certificato_base64=body.certificato_base64,
            client_data=body.client_data,
            reply_to=body.reply_to,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"validation_error": str(exc)})
    except RentriApiError as exc:
        _raise_api_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"unexpected_error": str(exc)})


HTML_UI = r"""<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>RENTRI BOOMER · Truccolo Angelo</title>
  <style>
    :root {
      color-scheme: light;
      --bg:#edf2ee; --panel:#fff; --panel-soft:#f7faf7; --line:#d5e0d7;
      --text:#203126; --muted:#607166; --green:#237a35; --green-dark:#176128;
      --green-soft:#e9f5eb; --warn:#986416; --warn-bg:#fff6e5;
      --danger:#a12c37; --danger-bg:#fff0f1; --ok:#246f32; --ok-bg:#eaf7ec;
      --shadow:0 7px 22px rgba(32,55,39,.08);
    }
    *{box-sizing:border-box}
    html,body{width:100%;height:100%;margin:0;overflow:hidden;background:var(--bg);color:var(--text);font:15px/1.4 "Segoe UI",Arial,sans-serif}
    body{display:flex;flex-direction:column}
    header{height:66px;flex:0 0 66px;display:flex;align-items:center;justify-content:space-between;gap:14px;padding:8px 20px;background:#fff;border-bottom:1px solid var(--line);box-shadow:0 2px 8px rgba(32,55,39,.04);z-index:10}
    .brand{display:flex;align-items:center;gap:12px;min-width:0}
    .brand-mark{width:42px;height:42px;display:grid;place-items:center;flex:0 0 42px;border-radius:12px;background:var(--green);color:#fff;font-weight:900;font-size:16px;letter-spacing:-.04em}
    .brand-title{font-size:18px;font-weight:850;line-height:1.1;letter-spacing:.01em}
    .brand-subtitle{font-size:11px;color:var(--muted);font-weight:700;letter-spacing:.09em;margin-top:4px}
    .top-meta{display:flex;align-items:center;justify-content:flex-end;gap:8px;min-width:0}
    .badge{display:inline-flex;align-items:center;justify-content:center;padding:7px 11px;border-radius:999px;background:#eaf4ec;border:1px solid #c5ddca;color:#24592e;font-size:12px;font-weight:850;white-space:nowrap}
    #envBadge[style*="rgb(185, 28, 28)"],#envBadge[style*="#b91c1c"]{background:#b91c1c!important;color:white!important;border-color:#a51d27!important}
    #subtitle{font-size:11px;color:var(--muted);max-width:330px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-align:right}
    /* Gli avvisi restano nel flusso della pagina: non coprono più le istruzioni sottostanti. */
    .boomer-alert{position:static;top:auto;left:auto;transform:none;z-index:auto;width:min(1900px,calc(100% - 24px));margin:8px auto 0;padding:10px 14px;font-size:14px;font-weight:700;box-shadow:0 4px 12px rgba(20,40,25,.08);white-space:pre-wrap;max-height:104px;overflow-y:auto;flex:0 0 auto}
    .banner{border-radius:13px;border:1px solid var(--line);background:#f7faf7;color:var(--text);padding:11px 13px}
    .banner.ok{background:var(--ok-bg);border-color:#b8daba;color:#235b2b}
    .banner.warn{background:var(--warn-bg);border-color:#efd9a8;color:#6b4a13}
    .banner.err{background:var(--danger-bg);border-color:#e8b9bf;color:#842a33}
    .hidden{display:none!important}
    .boomer-main{width:100%;height:calc(100dvh - 74px);flex:1 1 0;min-height:0;max-width:1900px;margin:0 auto;padding:12px;display:grid;grid-template-columns:minmax(430px,.88fr) minmax(620px,1.32fr);gap:12px;overflow:auto;align-content:start;scrollbar-gutter:stable both-edges}
    .left-column,.right-column{display:flex;flex-direction:column;gap:12px;min-width:0;min-height:0}
    .right-column{overflow:visible;min-height:0}
    .card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:14px;box-shadow:var(--shadow);min-width:0}
    .list-panel{display:flex;flex-direction:column;flex:1;min-height:0}
    .panel-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:10px}
    .heading-main{display:flex;align-items:center;gap:10px;min-width:0}
    .step-number{width:30px;height:30px;flex:0 0 30px;border-radius:50%;display:grid;place-items:center;background:var(--green);color:#fff;font-weight:900;font-size:15px}
    h1,h2,h3,p{margin:0}
    h2{font-size:18px;line-height:1.2;font-weight:850}
    h3{font-size:15px;font-weight:850}
    .intro{font-size:12px;color:var(--muted);margin:3px 0 0;line-height:1.35}
    .toolbar{display:flex;gap:8px;align-items:center;min-width:0}
    .filterbar{display:grid;grid-template-columns:minmax(120px,1fr) minmax(150px,1.1fr) auto;gap:8px;margin:5px 0 8px}
    input,select{width:100%;min-width:0;height:44px;background:var(--panel-soft);border:1px solid #cbd9ce;border-radius:10px;padding:9px 11px;color:var(--text);font:inherit;font-size:14px}
    input:focus,select:focus{outline:3px solid rgba(35,122,53,.18);border-color:var(--green)}
    input::placeholder{color:#829087}
    button{min-height:42px;border:1px solid transparent;border-radius:10px;padding:10px 14px;background:var(--green-dark);color:#fff;font:inherit;font-size:14px;font-weight:850;cursor:pointer;transition:background .12s,transform .12s}
    button:hover{background:var(--green);color:#fff}
    button:active{transform:translateY(1px)}
    button:disabled{opacity:.45;cursor:not-allowed;transform:none}
    button.primary{background:linear-gradient(180deg,#2c913f,#217331);color:#fff;min-height:50px;padding:13px 18px;font-size:16px;box-shadow:0 5px 13px rgba(35,122,53,.18)}
    button.primary:hover{background:#176128}
    button.secondary{background:#eff6f0;border-color:#c8dccb;color:#24552d}
    button.secondary:hover{background:#e2f0e4;color:#184b22}
    button.danger{background:#a8323c;color:#fff}
    .search-button{white-space:nowrap;min-width:132px}
    details{border:1px solid var(--line);border-radius:11px;background:#fbfdfb;padding:8px 10px}
    details>summary{cursor:pointer;list-style:none;display:flex;align-items:center;justify-content:space-between;gap:10px;font-weight:800;color:#35503c}
    details>summary::-webkit-details-marker{display:none}
    details>summary::after{content:"Mostra";font-size:11px;color:var(--green);font-weight:850}
    details[open]>summary::after{content:"Nascondi"}
    .more-filters{margin-bottom:8px;font-size:12px}
    .more-filters-content{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:9px}
    .filter-help{grid-column:1/-1;font-size:11px;color:var(--muted);margin:0}
    #toggleHiddenFirBtn{min-height:34px;padding:6px 10px;font-size:11px;white-space:nowrap}
    .technical-settings{grid-column:1/-1}
    .technical-settings .settings-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px}
    .table-wrap{flex:1;min-height:0;overflow:auto;border:1px solid var(--line);border-radius:12px;background:#fff}
    table{width:100%;min-width:0;border-collapse:collapse;table-layout:fixed;font-size:13px}
    th,td{padding:10px 9px;border-bottom:1px solid #e6ede7;text-align:left;vertical-align:middle;overflow-wrap:anywhere}
    th{position:sticky;top:0;background:#edf5ee;color:#36533c;font-size:11px;text-transform:uppercase;letter-spacing:.04em;z-index:1}
    th:nth-child(3),td:nth-child(3),th:nth-child(5),td:nth-child(5),th:nth-child(6),td:nth-child(6){display:none}
    th:nth-child(1){width:27%} th:nth-child(2){width:29%} th:nth-child(4){width:28%} th:nth-child(7){width:16%}
    tbody tr{cursor:pointer;transition:background .1s}
    tbody tr:hover{background:#f2f8f3}
    tbody tr.selected{background:#e3f2e5;box-shadow:inset 4px 0 var(--green);font-weight:700}
    tbody tr:last-child td{border-bottom:0}
    tbody td:first-child{font-weight:850;color:#234a2b}
    .pager{display:flex;align-items:center;justify-content:space-between;gap:8px;padding-top:9px}
    .pager button{min-height:38px;padding:8px 12px;font-size:13px}
    #pagingInfo{font-size:12px;color:var(--muted);font-weight:750}
    .detail-panel{flex:0 0 auto;padding:13px}
    #detailBanner{margin:7px 0 9px;background:#f4f8f4;font-size:13px}
    .summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px}
    .summary .box{min-width:0;padding:8px 10px;border:1px solid #dfebe0;border-radius:10px;background:#f6faf6}
    .summary .tiny,.detail-grid .tiny{font-size:10px;color:var(--muted);font-weight:750;text-transform:uppercase;letter-spacing:.04em}
    .summary .value{margin-top:3px;font-size:13px;font-weight:800;color:#294a30;overflow-wrap:anywhere;line-height:1.25}
    .extra-detail{margin-top:8px;font-size:12px}
    .extra-detail .detail-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:7px;margin-top:8px}
    .detail-grid .box{padding:8px 9px;background:#f6faf6;border:1px solid #dfebe0;border-radius:9px;min-width:0}
    .detail-grid .value{font-size:12px;font-weight:700;margin-top:3px;overflow-wrap:anywhere}
    .detail-pre{white-space:pre-wrap;margin:8px 0 0;font:inherit;font-size:12px;max-height:180px;overflow:auto}
    #reloadDetailBtn{min-height:34px;padding:6px 10px;font-size:11px}
    #rollbackBtn{min-height:34px;padding:6px 10px;font-size:11px;white-space:nowrap}
    .panel-heading .toolbar{flex-wrap:wrap;justify-content:flex-end}
    button.danger:hover{background:#8e2630;color:#fff}
    .qr-dock{display:grid;grid-template-columns:64px minmax(0,1fr);grid-template-areas:'thumb copy' 'actions actions' 'status status';gap:8px 10px;align-items:start;margin-top:9px;padding:8px 10px;border:1px solid #dfe9e1;border-radius:11px;background:#fbfdfb;width:100%;min-width:0}
    .qr-dock.hidden{display:none!important}
    .qr-label{font-size:11px;color:var(--muted);font-weight:850;text-transform:uppercase;letter-spacing:.05em}
    .qr-thumb-wrap{grid-area:thumb;display:flex;align-items:center;justify-content:center;cursor:pointer;flex:0 0 auto}
    .qr-thumb{width:62px;height:62px;object-fit:contain;border-radius:7px;border:1px solid #dfe8e1;background:#fff}
    .qr-copy{grid-area:copy;min-width:0}
    .qr-copy .small-note{font-size:11px;color:var(--muted)}
    .qr-actions{grid-area:actions;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
    .qr-pdf-button{min-height:38px;padding:8px 12px;font-size:12px;white-space:nowrap;flex:1 1 190px}
    .tablet-connection{grid-area:status;font-size:11px;color:var(--muted)}
    #sendQrTabletBtn{border-color:#b9d8c0;color:#245b31;font-weight:800}
    #sendQrTabletBtn.danger{background:#a8323c;border-color:#922934;color:#fff}
    #sendQrTabletBtn.danger:hover{background:#8e2630;color:#fff}
    #sendQrTabletBtn:disabled{opacity:.5}
    .action-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;align-items:stretch}
    .action-grid:has(#acceptanceCard.hidden){grid-template-columns:1fr}
    #acceptanceCard,#signCard,#closedFirCard{min-width:0;padding:13px}
    #closedFirCard{background:var(--ok-bg);border-color:#b8daba}
    #closedFirCard .step-number{background:var(--ok)}
    #closedFirCard .intro{font-size:13px;color:#315d38}
    #recipientWaitingCard{background:#fffaf0;border-color:#ecd8a8}
    #recipientWaitingCard .step-number{background:#b7791f}
    #recipientWaitingCard .intro{font-size:13px;color:#76551f}
    #acceptanceCard h2,#signCard h2,#recipientWaitingCard h2{font-size:17px}
    .action-lead{font-size:12px;color:var(--muted);margin:4px 0 9px;line-height:1.35}
    .acceptance-fields{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px}
    .field{display:grid;gap:5px;min-width:0}
    .field label{font-size:12px;font-weight:800;color:#43594a}
    .field input,.field select{height:42px}
    .acceptance-actions{display:flex;margin-top:9px}
    .acceptance-actions button{width:100%;min-height:48px}
    #acceptanceStateHint{font-size:12px;margin:8px 0}
    .pill{display:inline-flex;align-items:center;justify-content:center;gap:5px;padding:5px 9px;border-radius:999px;background:#eaf5eb;border:1px solid #c6dfca;color:#285d31;font-size:10px;font-weight:850;letter-spacing:.04em;text-transform:uppercase;white-space:nowrap}
    .sign-steps{display:grid;grid-template-columns:1fr;gap:4px;margin:7px 0 9px;font-size:12px;color:#42574a}
    .sign-step{display:flex;align-items:flex-start;gap:7px}
    .mini-check{width:18px;height:18px;flex:0 0 18px;border-radius:50%;display:grid;place-items:center;background:#e7f2e9;color:#28723a;font-size:11px;font-weight:900}
    .cert-actions{display:grid;grid-template-columns:auto minmax(0,1fr);gap:7px;align-items:center}
    #scanUsbCertsBtn{min-height:40px;padding:8px 11px;font-size:12px;white-space:nowrap}
    #usbCertSelect{height:40px;font-size:12px}
    #usbMemoryNote,#roleHint,.small-note{font-size:11px;color:var(--muted);margin-top:6px;line-height:1.3}
    #usbCertSummary{padding:8px 10px;font-size:12px;margin-top:6px}
    #usbSignBtn{width:100%;margin-top:10px;min-height:48px;font-size:15px}
    #signBanner{margin-top:8px;font-size:13px}
    .debug-tools{padding:9px 11px;font-size:12px;background:#f8faf8}
    .debug-tools h2{font-size:13px;margin:0}
    .debug-tools>summary::after{content:"Apri solo se richiesto"}
    .debug-tools[open]>summary::after{content:"Chiudi"}
    #debugLog{white-space:pre-wrap;word-break:break-word;max-height:230px;overflow:auto;margin:8px 0 0;padding:10px;background:#f1f5f1;border-radius:8px;font:11px/1.4 Consolas,monospace}
    .qr-modal,.pdf-modal{position:fixed;inset:0;z-index:100;display:flex;align-items:center;justify-content:center;background:rgba(13,25,16,.72);padding:18px}
    .qr-modal.hidden,.pdf-modal.hidden{display:none!important}
    .qr-modal-inner{max-width:min(92vw,850px);max-height:92vh;background:#fff;border-radius:16px;padding:14px;display:flex;flex-direction:column;gap:10px;box-shadow:0 18px 48px rgba(0,0,0,.32)}
    .qr-modal img{max-width:min(84vw,780px);max-height:78vh;object-fit:contain;border-radius:10px}
    .pdf-modal-inner{width:min(96vw,1200px);height:min(94vh,900px);background:#fff;border-radius:16px;padding:12px;display:flex;flex-direction:column;gap:9px}
    .pdf-modal iframe{width:100%;flex:1;min-height:0;border:1px solid var(--line);border-radius:9px}
    .muted{color:var(--muted)}

@media (max-width:1650px), (max-height:920px){
  header{height:58px;flex:0 0 58px;padding:6px 14px}
  .brand-mark{width:36px;height:36px;flex-basis:36px;font-size:14px}
  .brand-title{font-size:16px}
  .brand-subtitle{display:none}
  .boomer-main{height:calc(100dvh - 58px);padding:10px;grid-template-columns:1fr;gap:10px}
  .card{padding:12px;border-radius:14px}
  .list-panel,.detail-panel{padding:12px}
  .panel-heading{margin-bottom:8px}
  h2{font-size:17px}
  .intro{font-size:11px}
  .filterbar{grid-template-columns:minmax(0,1fr) minmax(0,1fr) auto}
  .more-filters-content{grid-template-columns:1fr 1fr}
  .action-grid{grid-template-columns:1fr}
  .summary{grid-template-columns:repeat(3,minmax(0,1fr))}
  .extra-detail .detail-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
  .qr-dock{grid-template-columns:1fr;grid-template-areas:'thumb' 'copy' 'actions' 'status'}
  .qr-thumb-wrap{justify-content:flex-start}
  .qr-actions{flex-direction:column;align-items:stretch}
  .qr-pdf-button{flex:1 1 auto;width:100%}
  .acceptance-fields{grid-template-columns:1fr}
  .cert-actions{grid-template-columns:1fr}
  #usbSignBtn{min-height:46px;font-size:15px}
  .acceptance-actions button{min-height:44px}
  #rollbackBtn,#reloadDetailBtn{min-height:38px}
}
    @media (max-width:1250px){.summary{grid-template-columns:repeat(2,minmax(0,1fr))}.extra-detail .detail-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
    @media (max-width:1000px){html,body{height:auto;min-height:100%;overflow:auto}.boomer-main{height:auto;min-height:calc(100vh - 66px);grid-template-columns:1fr;overflow:visible}.left-column{min-height:520px}.right-column{overflow:visible}.table-wrap{min-height:360px}.summary{grid-template-columns:repeat(3,minmax(0,1fr))}}
    @media (max-width:650px){header{padding:8px 10px}.brand-title{font-size:15px}.brand-mark{width:36px;height:36px;flex-basis:36px}#subtitle{display:none}.boomer-main{padding:8px}.filterbar{grid-template-columns:1fr 1fr}.search-button{grid-column:1/-1}.action-grid{grid-template-columns:1fr!important}.summary{grid-template-columns:repeat(2,minmax(0,1fr))}.acceptance-fields{grid-template-columns:1fr 1fr}.qr-dock{flex-wrap:wrap}.qr-pdf-button{flex:1}}
  </style>
</head>
<body>
<header>
  <div class="brand">
    <div class="brand-mark">TA</div>
    <div>
      <div class="brand-title">Truccolo Angelo · Gestione FIR</div>
      <div class="brand-subtitle">MODALITÀ SEMPLICE · PROCEDURA GUIDATA</div>
    </div>
  </div>
  <div class="top-meta">
    <span class="badge" id="envBadge">AMBIENTE</span>
    <span class="badge" id="sitePill">Configurazione</span>
    <span id="subtitle">Connessione al servizio RENTRI…</span>
  </div>
</header>
<div id="signBanner" class="banner hidden boomer-alert" role="status" aria-live="polite"></div>

<main class="boomer-main">
  <section class="left-column">
    <div class="card list-panel">
      <div class="panel-heading">
        <div class="heading-main">
          <span class="step-number">1</span>
          <div>
            <h2>Scegli il formulario</h2>
            <p class="intro">Seleziona una riga dall’elenco per visualizzare i dati e le operazioni disponibili.</p>
          </div>
        </div>
      </div>

      <div class="filterbar">
        <input id="searchNumeroFir" placeholder="Cerca numero FIR" aria-label="Cerca per numero FIR" />
        <select id="searchVista" aria-label="Tipo di formulari da visualizzare">
          <option value="ACCETTAZIONE">Da accettare</option>
          <option value="FIRMA" selected>Da firmare</option>
          <option value="TUTTI">Tutti i formulari</option>
          <option value="ACCETTATI">Già accettati</option>
          <option value="PARZIALI">Accettati parzialmente</option>
        </select>
        <button id="searchBtn" class="primary search-button" onclick="loadList(1)">AGGIORNA ELENCO</button>
      </div>

      <details class="more-filters">
        <summary>Altri filtri (facoltativi) e impostazioni</summary>
        <div class="more-filters-content">
          <input id="searchEer" placeholder="Codice EER" maxlength="8" aria-label="Codice EER" />
          <select id="searchVisibility" aria-label="Visualizzazione formulari">
            <option value="VISIBILI" selected>Formulari normali</option>
            <option value="NASCOSTI">Formulari nascosti (archivio)</option>
          </select>
          <select id="pageSizeSelect" aria-label="Numero di formulari per pagina">
            <option value="5">5 formulari</option><option value="10">10 formulari</option>
            <option value="20">20 formulari</option><option value="50">50 formulari</option>
            <option value="100">100 formulari</option>
          </select>
          <p class="filter-help">I formulari nascosti restano salvati su questo computer e non vengono cancellati da RENTRI. Nell’archivio trovi tutti i FIR nascosti, indipendentemente dallo stato.</p>
          <details class="technical-settings">
            <summary>Impostazioni tecniche (non modificare)</summary>
            <div class="small-note">Questi valori sono normalmente caricati dalla configurazione del programma. Modificarli solo su indicazione dell'amministratore.</div>
            <div class="settings-grid">
              <input id="numIscrSito" placeholder="Numero iscrizione unità locale" aria-label="Numero iscrizione unità locale" />
              <input id="identificativoSoggetto" placeholder="Identificativo soggetto" aria-label="Identificativo soggetto" />
            </div>
          </details>
        </div>
      </details>

      <div class="table-wrap">
        <table>
          <thead><tr><th>Numero FIR</th><th>Produttore</th><th>Trasportatore</th><th>Destinatario</th><th>EER</th><th>Quantità</th><th>Stato</th></tr></thead>
          <tbody id="tbody"><tr><td colspan="7" class="muted">Caricamento formulari…</td></tr></tbody>
        </table>
      </div>
      <div class="pager">
        <button class="secondary" id="prevBtn" onclick="changePage(-1)" disabled>← Precedenti</button>
        <span id="pagingInfo">Pagina 1</span>
        <button class="secondary" id="nextBtn" onclick="changePage(1)" disabled>Successivi →</button>
      </div>
    </div>
  </section>

  <section class="right-column">
    <div class="card detail-panel">
      <div class="panel-heading">
        <div class="heading-main">
          <span class="step-number">2</span>
          <div>
            <h2>Controlla il formulario</h2>
            <p class="intro">Verifica soprattutto numero, destinatario e stato prima di procedere.</p>
          </div>
        </div>
        <div class="toolbar" style="flex-wrap:wrap;justify-content:flex-end">
          <button class="secondary" id="toggleHiddenFirBtn" type="button" onclick="toggleHiddenSelectedFir()" disabled>Nascondi formulario</button>
          <button class="danger" id="rollbackBtn" onclick="rollbackSignature()" disabled>ANNULLA ULTIMA FIRMA</button>
          <button class="secondary" id="reloadDetailBtn" onclick="reloadDetail()" disabled>Aggiorna dati</button>
        </div>
      </div>
      <div class="banner" id="detailBanner">Seleziona un formulario dall’elenco a sinistra.</div>
      <div id="detailData" class="hidden">
        <div class="summary">
          <div class="box"><div class="tiny muted">Numero FIR</div><div class="value" id="detailNum">—</div></div>
          <div class="box"><div class="tiny muted">Stato</div><div class="value" id="detailStatus">—</div></div>
          <div class="box"><div class="tiny muted">Produttore</div><div class="value" id="detailProd">—</div></div>
          <div class="box"><div class="tiny muted">Trasportatore</div><div class="value" id="detailTransport">—</div></div>
          <div class="box"><div class="tiny muted">Destinatario</div><div class="value" id="detailDest">—</div></div>
          <div class="box"><div class="tiny muted">Quantità presunta</div><div class="value" id="detailQty">—</div></div>
          <div class="box"><div class="tiny muted">Codice EER</div><div class="value" id="detailEer">—</div></div>
        </div>
        <details class="extra-detail">
          <summary>Altri dati del formulario (facoltativi)</summary>
          <div class="detail-grid">
            <div class="box"><div class="tiny muted">Data emissione</div><div class="value" id="detailEmissione">—</div></div>
            <div class="box"><div class="tiny muted">Data creazione</div><div class="value" id="detailCreazione">—</div></div>
            <div class="box"><div class="tiny muted">Inizio trasporto</div><div class="value" id="detailTrasportoInizio">—</div></div>
            <div class="box"><div class="tiny muted">Accettazione</div><div class="value" id="detailAccettazione">—</div></div>
            <div class="box"><div class="tiny muted">Targa motrice</div><div class="value" id="detailTargaMotrice">—</div></div>
            <div class="box"><div class="tiny muted">Targa rimorchio</div><div class="value" id="detailTargaRimorchio">—</div></div>
            <div class="box"><div class="tiny muted">Intermediario</div><div class="value" id="detailIntermediario">—</div></div>
            <div class="box"><div class="tiny muted">Attività / operazione</div><div class="value" id="detailAttivita">—</div></div>
            <div class="box"><div class="tiny muted">Visibilità acquisita</div><div class="value" id="detailVisibilita">—</div></div>
            <div class="box"><div class="tiny muted">Trasformato in cartaceo</div><div class="value" id="detailCartaceo">—</div></div>
            <div class="box"><div class="tiny muted">Versione</div><div class="value" id="detailVersione">—</div></div>
            <div class="box"><div class="tiny muted">Blocco</div><div class="value" id="detailBlocco">—</div></div>
            <div class="box"><div class="tiny muted">Produttore</div><div class="value" id="detailProdFull">—</div></div>
            <div class="box"><div class="tiny muted">Trasportatori</div><div class="value" id="detailTransportersFull">—</div></div>
            <div class="box"><div class="tiny muted">Destinatari</div><div class="value" id="detailRecipientsFull">—</div></div>
            <div class="box"><div class="tiny muted">Intermediari</div><div class="value" id="detailIntermediariesFull">—</div></div>
          </div>
          <details class="spaced" id="detailNarrativePanel">
            <summary>Visualizza scheda completa</summary>
            <pre class="detail-pre" id="detailNarrative"></pre>
          </details>
        </details>
      </div>
      <div class="qr-dock hidden" id="qrDock" title="Anteprima QR del formulario">
        <div class="qr-thumb-wrap" onclick="openQrModal()"><img id="qrThumb" class="qr-thumb" alt="Anteprima QR del formulario" /></div>
        <div class="qr-copy"><div class="qr-label">QR del formulario</div><div class="small-note">Clicca sul codice per ingrandirlo.</div></div>
        <div class="qr-actions">
          <button class="secondary qr-pdf-button" id="sendQrTabletBtn" type="button" onclick="sendQrToTablet()" disabled>Mostra sul tablet</button>
          <button class="secondary qr-pdf-button" id="openPdfBtn" type="button" onclick="openPdfModal()">Apri PDF completo</button>
        </div>
        <div class="tablet-connection" id="tabletQrStatus" aria-live="polite">Tablet: verifica collegamento…</div>
      </div>
    </div>

    <div class="action-grid">
      <div class="card hidden" id="acceptanceCard">
        <div class="panel-heading">
          <div class="heading-main"><span class="step-number">3</span><div><h2>Registra l’accettazione</h2><p class="intro">Compila i dati dell’arrivo. Controllali prima di confermare.</p></div></div>
          <span class="pill">Da completare</span>
        </div>
        <div class="banner acceptance-hint" id="acceptanceStateHint">La scheda comparirà solo se l’accettazione compete a Truccolo Angelo.</div>
        <div class="acceptance-fields">
          <div class="field"><label for="acceptanceType">Esito</label><select id="acceptanceType"><option value="A">Accettato integralmente</option><option value="P">Accettato parzialmente</option><option value="R">Respinto totalmente</option></select></div>
          <div class="field"><label for="acceptedQuantity">Quantità accettata</label><input id="acceptedQuantity" type="number" min="0" step="0.001" placeholder="Inserisci il peso" /></div>
          <div class="field"><label for="arrivalDate">Data di arrivo</label><input id="arrivalDate" type="date" autocomplete="off" aria-label="Data di arrivo" /></div>
          <div class="field"><label for="arrivalTime">Ora di arrivo</label><input id="arrivalTime" type="time" autocomplete="off" aria-label="Ora di arrivo" /></div>
        </div>
        <div class="acceptance-actions"><button class="primary" id="acceptanceBtn" onclick="sendAcceptance()">CONFERMA ACCETTAZIONE</button></div>
      </div>

      <div class="card closed-state-card hidden" id="closedFirCard" role="status" aria-live="polite">
        <div class="panel-heading">
          <div class="heading-main">
            <span class="step-number">✓</span>
            <div>
              <h2 id="closedFirTitle">Formulario già accettato</h2>
              <p class="intro" id="closedFirText">L'accettazione risulta già registrata. Non occorre apporre un'altra firma da questa schermata.</p>
            </div>
          </div>
          <span class="pill">Operazione conclusa</span>
        </div>
      </div>

      <div class="card recipient-waiting-card hidden" id="recipientWaitingCard" role="status" aria-live="polite">
        <div class="panel-heading">
          <div class="heading-main">
            <span class="step-number">!</span>
            <div>
              <h2>In attesa del destinatario</h2>
              <p class="intro" id="recipientWaitingText">L'accettazione e la firma di questo passaggio spettano al destinatario indicato nel formulario.</p>
            </div>
          </div>
          <span class="pill">Nessuna azione richiesta</span>
        </div>
        <div class="small-note">Non inserire dati di accettazione e non apporre firme da questa schermata. Se ritieni che il destinatario sia errato, avvisa l'amministratore.</div>
      </div>

      <div class="card" id="signCard">
        <div class="panel-heading">
          <div class="heading-main"><span class="step-number" id="signStepNumber">3</span><div><h2>Firma il formulario</h2><p class="intro">Inserisci la chiavetta USB e controlla il nominativo del certificato.</p></div></div>
          <span class="pill" id="modePill">AMBIENTE</span>
        </div>
        <div class="sign-steps">
          <div class="sign-step"><span class="mini-check">1</span><span>Collega la chiavetta USB al computer.</span></div>
          <div class="sign-step"><span class="mini-check">2</span><span>Rileva e seleziona il certificato corretto.</span></div>
          <div class="sign-step"><span class="mini-check">3</span><span>Premi il pulsante verde per firmare.</span></div>
        </div>
        <div class="cert-actions">
          <button class="secondary" id="scanUsbCertsBtn" onclick="loadUsbCertificates()" type="button">RILEVA CHIAVETTA</button>
          <select id="usbCertSelect" aria-label="Certificato di firma"><option value="">Collega la chiavetta e rilevala</option></select>
        </div>
        <div id="usbMemoryNote">Nessuna chiavetta selezionata.</div>
        <div id="usbCertSummary" class="banner hidden"></div>
        <div class="small-note" id="roleHint">Seleziona un formulario per verificare se è pronto per la firma.</div>
        <button class="primary" id="usbSignBtn" onclick="signWithUsb()" disabled>FIRMA IL FORMULARIO</button>
      </div>
    </div>

    <details class="debug-tools">
      <summary><h2>Assistenza tecnica</h2></summary>
      <p class="small-note">Aprire questo riquadro solo se richiesto dall’amministratore. Contiene i messaggi tecnici utili per risolvere eventuali problemi.</p>
      <pre id="debugLog">Nessun dato tecnico ancora registrato.</pre>
    </details>
  </section>
</main>

<div class="qr-modal hidden" id="qrModal" role="dialog" aria-modal="true" aria-label="QR del formulario" onclick="closeQrModal(event)">
  <div class="qr-modal-inner" onclick="event.stopPropagation()">
    <div class="toolbar" style="justify-content:space-between"><strong>QR del formulario</strong><button class="secondary" type="button" onclick="closeQrModal()">Chiudi</button></div>
    <img id="qrModalImg" alt="QR ingrandito del formulario" />
  </div>
</div>
<div class="pdf-modal hidden" id="pdfModal" role="dialog" aria-modal="true" aria-label="PDF completo del formulario" onclick="closePdfModal(event)">
  <div class="pdf-modal-inner" onclick="event.stopPropagation()">
    <div class="toolbar" style="justify-content:space-between"><strong id="pdfModalTitle">PDF completo del formulario</strong><button class="secondary" type="button" onclick="closePdfModal()">Chiudi PDF</button></div>
    <iframe id="pdfFrame" title="PDF completo del formulario" src="about:blank"></iframe>
  </div>
</div>

<script>
  const state = {
    selectedNum: null,
    selectedRow: null,
    selectedDetail: null,
    selectedStatusRaw: '',
    selectedStatusLabel: '',
    currentPage: 1,
    pageSize: 5,
    rows: [],
    usbCertificates: [],
    usbSelected: null,
    usbSigningInProgress: false,
    usbHashTransactionId: null,
    usbHashToken: '',
    usbDigestToSign: '',
    usbHashCertThumb: '',
    usbHashCertBase64: '',
    acceptanceVisible: false,
    acceptanceSubmittedForFir: '',
    selectedSuggestedQuantity: '',
    runtimeInfo: null,
    hiddenFirEntries: [],
    hiddenFirConfigLoaded: false,
    tabletStatus: null,
    tabletQrActive: false,
    tabletQrFir: '',
  };

  const STORAGE = {
    usbThumbprint: 'rentri_usb_thumbprint',
    usbSubject: 'rentri_usb_subject',
    numIscrSito: 'rentri_num_iscr_sito',
    identificativoSoggetto: 'rentri_identificativo_soggetto',
    pageSize: 'rentri_page_size',
  };

  const QR_CROP = { page: 1, x: 479, y: 78, width: 86, height: 86 };

  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
  const pretty = value => JSON.stringify(value, null, 2);

  function readStorage(key, fallback='') {
    try { return localStorage.getItem(key) ?? fallback; } catch { return fallback; }
  }
  function writeStorage(key, value) {
    try {
      if (value === null || value === undefined || value === '') localStorage.removeItem(key);
      else localStorage.setItem(key, String(value));
    } catch {}
  }

  function shortCertName(subject) {
    const s = String(subject || '');
    const m = s.match(/(?:^|,\s*)CN=([^,]+)/i);
    if (m && m[1]) return m[1].trim();
    const serial = s.match(/(?:^|,\s*)SN=([^,]+)/i);
    if (serial && serial[1]) return serial[1].trim();
    return s || 'Certificato';
  }

  function friendlyStatus(raw) {
    const s = String(raw || '').trim();
    const map = {
      InserimentoAccettazione: 'Da accettare',
      FirmaAccettazione: 'In firma di accettazione',
      FirmaProduttore: 'In attesa di firma produttore',
      FirmaTrasportatore: 'In attesa di firma trasportatore',
      FirmaDestinatario: 'In attesa di firma destinatario',
      FirmaAccettazioneSuccessiva: 'Accettazione firmata',
      Accettato: 'Accettato',
      RespintoAccettatoParzialmente: 'Accettato parzialmente',
    };
    return map[s] || s || '—';
  }

  // Stati che rappresentano un esito di accettazione già registrato e concluso.
  // Non includiamo "FirmaAccettazioneSuccessiva": può essere ancora uno stato di passaggio.
  function isFinalizedAcceptanceStatus(raw) {
    const token = String(raw || '').trim().toLowerCase().replace(/[\s_-]/g, '');
    return [
      'accettato',
      'accettatointegralmente',
      'accettatoparzialmente',
      'respintoaccettatoparzialmente'
    ].includes(token);
  }

  function canShowAcceptance(raw) {
    const s = String(raw || '').trim();
    return ['InserimentoAccettazione', 'FirmaAccettazione', 'FirmaAccettazioneSuccessiva'].includes(s);
  }

  function setBanner(el, text, kind='') {
    const layoutClass = el?.id === 'signBanner' ? ' boomer-alert' : '';
    el.className = 'banner' + (kind ? ` ${kind}` : '') + layoutClass;
    el.textContent = text;
    el.classList.remove('hidden');
  }

  function hideBanner(el) {
    const layoutClass = el?.id === 'signBanner' ? ' boomer-alert' : '';
    el.className = 'banner hidden' + layoutClass;
    el.textContent = '';
  }


  function qrPreviewUrl(numeroFir, scale = 'thumb') {
    if (!numeroFir) return '';
    const params = new URLSearchParams({
      page: String(QR_CROP.page),
      x: String(QR_CROP.x),
      y: String(QR_CROP.y),
      width: String(QR_CROP.width),
      height: String(QR_CROP.height),
      scale,
    });
    return `/api/formulari/${encodeURIComponent(numeroFir)}/qr?${params.toString()}`;
  }

  function updateTabletSendButton() {
    const button = $('sendQrTabletBtn');
    if (!button) return;
    const active = Boolean(state.tabletQrActive);
    button.textContent = active ? 'Smetti di inviare' : 'Mostra sul tablet';
    button.classList.toggle('danger', active);
    button.classList.toggle('secondary', !active);
    button.setAttribute('aria-pressed', active ? 'true' : 'false');
    button.disabled = !state.selectedNum;
  }

  async function sendQrToTablet() {
    const numero = String(state.selectedNum || '').trim();
    const button = $('sendQrTabletBtn');
    if (!numero || !button) return;

    // Lo stesso pulsante interrompe la visualizzazione già avviata.
    if (state.tabletQrActive) {
      button.disabled = true;
      button.textContent = 'INTERROMPO…';
      try {
        await requestJson('/api/tablet/clear', {method: 'POST'});
        state.tabletQrActive = false;
        state.tabletQrFir = '';
        await updateTabletStatus();
        showFriendlyMainMessage('Visualizzazione del QR interrotta sul tablet del bancone.', 'ok');
        debugAppend('Invio QR interrotto sul tablet', {numero_fir: numero});
      } catch (err) {
        showFriendlyMainMessage(friendlyErrorMessage(err), 'err');
        debugAppend('Errore interruzione QR sul tablet', err.raw || err.message);
      } finally {
        updateTabletSendButton();
      }
      return;
    }

    button.disabled = true;
    button.textContent = 'PREPARO IL QR…';
    try {
      const result = await requestJson('/api/tablet/publish', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({numero_fir: numero}),
      });
      state.tabletQrActive = true;
      state.tabletQrFir = numero;
      await updateTabletStatus();
      // La pubblicazione sul servizio LAN è riuscita: lo stato di connessione
      // può aggiornarsi con qualche secondo di ritardo, quindi non mostriamo
      // un falso errore basato sul solo heartbeat del tablet.
      showFriendlyMainMessage(`QR del formulario ${numero} inviato al display del bancone.`, 'ok');
      debugAppend('QR inviato al tablet', {numero_fir: numero, tablet_url: result.url, tablet_ip: result.tablet_ip, tablet_connected: result.tablet_connected});
    } catch (err) {
      showFriendlyMainMessage(friendlyErrorMessage(err), 'err');
      debugAppend('Errore invio QR al tablet', err.raw || err.message);
    } finally {
      updateTabletSendButton();
    }
  }

  async function clearTabletQrSilently() {
    // La selezione del formulario cambia: il display viene svuotato e il
    // pulsante torna allo stato iniziale anche se la richiesta non risponde.
    state.tabletQrActive = false;
    state.tabletQrFir = '';
    updateTabletSendButton();
    try {
      await fetch('/api/tablet/clear', {method: 'POST', cache: 'no-store'});
      await updateTabletStatus();
    } catch {}
  }

  async function updateTabletStatus() {
    const label = $('tabletQrStatus');
    if (!label) return;
    try {
      const info = await requestJson('/api/tablet/status');
      state.tabletStatus = info;
      label.textContent = info.connected
        ? `Tablet collegato · ${info.tablet_ip}`
        : `Tablet non collegato · ${info.tablet_ip} · apri Fully Kiosk`;
      label.style.color = info.connected ? '#28723a' : '#9a6b22';
      label.title = `Pagina tablet: ${info.url}`;
    } catch {
      label.textContent = 'Servizio tablet non disponibile';
      label.style.color = '#a33';
    }
  }

  function refreshQrPreview() {
    const dock = $('qrDock');
    const img = $('qrThumb');
    if (!dock || !img) return;
    if (!state.selectedNum) {
      dock.classList.add('hidden');
      img.removeAttribute('src');
      img.style.display = 'none';
      return;
    }
    dock.classList.remove('hidden');
    img.style.display = 'block';
    img.src = qrPreviewUrl(state.selectedNum, 'thumb');
  }

  function openQrModal() {
    if (!state.selectedNum) return;
    const modal = $('qrModal');
    const img = $('qrModalImg');
    if (!modal || !img) return;
    img.src = qrPreviewUrl(state.selectedNum, 'large');
    modal.classList.remove('hidden');
  }

  function closeQrModal(event) {
    if (event && event.target !== event.currentTarget) return;
    const modal = $('qrModal');
    if (!modal) return;
    modal.classList.add('hidden');
  }

  function openPdfModal() {
    if (!state.selectedNum) return;
    const modal = $('pdfModal');
    const frame = $('pdfFrame');
    if (!modal || !frame) return;
    $('pdfModalTitle').textContent = `PDF completo · ${state.selectedNum}`;
    frame.src = `/api/formulari/${encodeURIComponent(state.selectedNum)}/pdf#toolbar=1&navpanes=0`;
    modal.classList.remove('hidden');
  }

  function closePdfModal(event) {
    if (event && event.target !== event.currentTarget) return;
    const modal = $('pdfModal');
    const frame = $('pdfFrame');
    if (!modal) return;
    modal.classList.add('hidden');
    if (frame) frame.src = 'about:blank';
  }

  function debugAppend(title, payload) {
    const pre = $('debugLog');
    const chunk = `\n\n[${new Date().toLocaleString('it-IT')}] ${title}\n${typeof payload === 'string' ? payload : pretty(payload)}`;
    if (pre.textContent === 'Nessun dato tecnico ancora registrato.') {
      pre.textContent = '';
    }
    pre.textContent += chunk;
    pre.scrollTop = pre.scrollHeight;
  }

  async function requestJson(url, options = {}) {
    const response = await fetch(url, options);
    const raw = await response.text();
    let data = null;
    if (raw) {
      try { data = JSON.parse(raw); }
      catch { data = { raw_response: raw }; }
    }
    if (!response.ok) {
      const detail = data?.detail ?? data ?? { title: 'Errore generico' };
      const title = detail?.problem_details?.response?.title || detail?.title || `Richiesta non riuscita (${response.status})`;
      const err = new Error(title);
      err.raw = { http_status: response.status, detail };
      throw err;
    }
    return data;
  }


  function deepFind(root, wantedKeys, depth = 0) {
    if (root === null || root === undefined || depth > 6) return null;
    if (Array.isArray(root)) {
      for (const item of root) {
        const found = deepFind(item, wantedKeys, depth + 1);
        if (found !== null && found !== undefined && found !== '') return found;
      }
      return null;
    }
    if (typeof root === 'object') {
      for (const key of wantedKeys) {
        if (Object.prototype.hasOwnProperty.call(root, key) && root[key] !== null && root[key] !== undefined && root[key] !== '') {
          return root[key];
        }
      }
      for (const value of Object.values(root)) {
        const found = deepFind(value, wantedKeys, depth + 1);
        if (found !== null && found !== undefined && found !== '') return found;
      }
    }
    return null;
  }


  function unwrapRecord(value) {
    return value?.visibilita_sito_acquisita ?? value?.data ?? value?.result ?? value?.risultato ?? value;
  }

  function normalizeParty(value, depth = 0) {
    if (value === null || value === undefined || value === '' || depth > 6) return '';
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      return String(value).trim();
    }
    if (Array.isArray(value)) {
      return value.map(item => normalizeParty(item, depth + 1)).filter(Boolean).join(' · ');
    }
    if (typeof value === 'object') {
      const preferredKeys = [
        'denominazione', 'ragione_sociale', 'ragioneSociale', 'nome', 'nominativo',
        'descrizione', 'codice_fiscale', 'codiceFiscale', 'partita_iva', 'partitaIVA',
        'partitaIva', 'cf', 'piva', 'serialNumber', 'id', 'value', 'label', 'text', 'subject', 'name', 'raison_sociale'
      ];
      for (const key of preferredKeys) {
        const candidate = value[key];
        if (candidate !== null && candidate !== undefined && candidate !== '') {
          const normalized = normalizeParty(candidate, depth + 1);
          if (normalized) return normalized;
        }
      }
      for (const nested of Object.values(value)) {
        const normalized = normalizeParty(nested, depth + 1);
        if (normalized) return normalized;
      }
    }
    return '';
  }

  function extractParty(root, aliases) {
    return normalizeParty(deepFind(unwrapRecord(root), aliases));
  }

  function extractPartyList(root, aliases) {
    const value = deepFind(unwrapRecord(root), aliases);
    if (value === null || value === undefined || value === '') return '';
    if (Array.isArray(value)) {
      return value.map(item => normalizeParty(item)).filter(Boolean).join(' · ');
    }
    return normalizeParty(value);
  }

  function fmtDate(value) {
    if (!value) return '—';
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return String(value);
    return d.toLocaleString('it-IT');
  }

  function fmtBool(value) {
    if (value === true) return 'Sì';
    if (value === false) return 'No';
    return '—';
  }

  function fmtValue(value) {
    if (value === null || value === undefined || value === '') return '—';
    if (Array.isArray(value)) return value.map(v => fmtValue(v)).filter(v => v && v !== '—').join(' · ') || '—';
    if (typeof value === 'object') return normalizeParty(value) || JSON.stringify(value);
    return String(value);
  }

  // Le quantita' di RENTRI arrivano come oggetto {valore, unita_misura} (es. {"valore":10,"unita_misura":"kg"}),
  // non come numero semplice: senza questa funzione finivano mostrate come "[object Object]".
  function formatQuantity(raw, defaultUnit = '') {
    if (raw === null || raw === undefined || raw === '') return '';
    if (typeof raw === 'object') {
      const value = raw.valore ?? raw.value ?? raw.quantita ?? null;
      if (value === null || value === undefined || value === '') return '';
      const unit = raw.unita_misura ?? raw.unitaMisura ?? raw.unit ?? defaultUnit;
      return unit ? `${value} ${unit}` : String(value);
    }
    return defaultUnit ? `${raw} ${defaultUnit}` : String(raw);
  }

  function pad2(value) {
    return String(value).padStart(2, '0');
  }

  function setArrivalDefaults() {
    const now = new Date();
    const dateInput = $('arrivalDate');
    const timeInput = $('arrivalTime');
    // I controlli nativi HTML date/time usano i formati ISO richiesti dal browser.
    if (dateInput && !dateInput.value) {
      dateInput.value = `${now.getFullYear()}-${pad2(now.getMonth() + 1)}-${pad2(now.getDate())}`;
    }
    if (timeInput && !timeInput.value) {
      timeInput.value = `${pad2(now.getHours())}:${pad2(now.getMinutes())}`;
    }
  }

  function resetAcceptanceForm() {
    if ($('acceptanceType')) $('acceptanceType').value = 'A';
    if ($('acceptedQuantity')) {
      $('acceptedQuantity').value = '';
      delete $('acceptedQuantity').dataset.manual;
    }
    if ($('arrivalDate')) {
      $('arrivalDate').value = '';
      delete $('arrivalDate').dataset.manual;
    }
    if ($('arrivalTime')) {
      $('arrivalTime').value = '';
      delete $('arrivalTime').dataset.manual;
    }
  }

  function formatDigitMask(rawValue, groups, separators) {
    const digits = String(rawValue || '').replace(/\D/g, '').slice(0, groups.reduce((a, b) => a + b, 0));
    let output = '';
    let offset = 0;
    for (let i = 0; i < groups.length && offset < digits.length; i++) {
      if (i > 0) output += separators[i - 1];
      output += digits.slice(offset, offset + groups[i]);
      offset += groups[i];
    }
    return output;
  }

  function bindDigitMask(input, groups, separators) {
    if (!input) return;
    input.addEventListener('input', () => {
      const original = input.value;
      const caret = input.selectionStart ?? original.length;
      const digitsBeforeCaret = original.slice(0, caret).replace(/\D/g, '').length;
      const formatted = formatDigitMask(original, groups, separators);
      input.value = formatted;
      let newCaret = 0;
      let counted = 0;
      while (newCaret < formatted.length && counted < digitsBeforeCaret) {
        if (/\d/.test(formatted[newCaret])) counted++;
        newCaret++;
      }
      input.setSelectionRange(newCaret, newCaret);
      input.dataset.manual = '1';
    });
  }

  function getArrivalIsoLocal() {
    const dateText = String($('arrivalDate')?.value || '').trim();
    const timeText = String($('arrivalTime')?.value || '').trim();
    // type="date" restituisce YYYY-MM-DD. Manteniamo il supporto DD/MM/YYYY
    // per eventuali browser/vecchi moduli che conservino il formato precedente.
    let year, month, day;
    const isoDate = dateText.match(/^(\d{4})-(\d{2})-(\d{2})$/);
    const itDate = dateText.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
    if (isoDate) {
      year = Number(isoDate[1]); month = Number(isoDate[2]); day = Number(isoDate[3]);
    } else if (itDate) {
      day = Number(itDate[1]); month = Number(itDate[2]); year = Number(itDate[3]);
    } else {
      return null;
    }
    const timeMatch = timeText.match(/^(\d{2}):(\d{2})$/);
    if (!timeMatch) return null;
    const hour = Number(timeMatch[1]);
    const minute = Number(timeMatch[2]);
    if (year < 2000 || month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59) return null;
    const check = new Date(year, month - 1, day, hour, minute, 0, 0);
    if (check.getFullYear() !== year || check.getMonth() !== month - 1 || check.getDate() !== day) return null;
    return `${year}-${pad2(month)}-${pad2(day)}T${pad2(hour)}:${pad2(minute)}`;
  }

  function syncAcceptanceSection() {
    // La scheda è disponibile solo se il FIR è in stato di accettazione e il
    // destinatario identificato nel dettaglio coincide con il soggetto configurato.
    // In assenza di un identificativo verificabile, la scheda resta nascosta.
    const statusAllowsAcceptance = canShowAcceptance(state.selectedStatusRaw);
    const recipientIsCurrentCompany = detailRecipientMatchesMyProfile(state.selectedDetail);
    const visible = statusAllowsAcceptance && recipientIsCurrentCompany;
    state.acceptanceVisible = visible;
    const card = $('acceptanceCard');
    const signStepNumber = $('signStepNumber');
    if (signStepNumber) signStepNumber.textContent = visible ? '4' : '3';
    const quantityInput = $('acceptedQuantity');
    if (!card) return;
    card.classList.toggle('hidden', !visible);
    if (visible) {
      const alreadySubmitted = state.acceptanceSubmittedForFir === state.selectedNum;
      if (!alreadySubmitted) {
        setArrivalDefaults();
        const suggested = state.selectedSuggestedQuantity;
        if (quantityInput) {
          const existing = String(quantityInput.value || '').trim();
          const hasManual = quantityInput.dataset.manual === '1';
          if ((!existing || !hasManual) && suggested !== null && suggested !== undefined && suggested !== '') {
            quantityInput.value = String(suggested);
          }
          quantityInput.placeholder = suggested !== null && suggested !== undefined && suggested !== ''
            ? `Peso presunto: ${suggested}`
            : 'Peso presunto';
        }
        $('acceptanceStateHint').textContent = 'Questo FIR è in attesa di accettazione. Inserisci quantità, data e ora, poi invia.';
      } else {
        $('acceptanceStateHint').textContent = 'Accettazione registrata. I campi sono stati puliti: puoi procedere con la firma nel riquadro “Firma FIR”.';
      }
    } else {
      $('acceptanceStateHint').textContent = 'La sezione compare solo quando il FIR è in attesa di accettazione.';
    }
  }

  function clearUsbHashCache() {
    state.usbHashTransactionId = null;
    state.usbHashToken = '';
    state.usbDigestToSign = '';
    state.usbHashCertThumb = '';
    state.usbHashCertBase64 = '';
  }

  async function wait(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  function getSelectedInputValue(id) {
    const el = $(id);
    return el ? el.value.trim() : '';
  }

  function searchStateToBackend(value) {
    switch (value) {
      case 'ACCETTAZIONE': return 'InserimentoAccettazione';
      case 'FIRMA': return 'TUTTI';
      case 'ACCETTATI': return 'Accettato';
      case 'PARZIALI': return 'RespintoAccettatoParzialmente';
      default: return '';
    }
  }

  function normalizeDetail(detail) {
    const d = unwrapRecord(detail) ?? {};
    const pf = d.dati_partenza ?? d.datiPartenza ?? d.partenza ?? {};
    const producerObj = pf.produttore ?? d.produttore ?? d.producer ?? {};
    const recipientObj = pf.destinatario ?? d.destinatario ?? d.recipient ?? {};
    const transportersArr = pf.trasportatori ?? d.trasportatori ?? d.transporters ?? [];
    const recipientsArr = pf.destinatari ?? d.destinatari ?? d.recipients ?? [];
    const intermediariesArr = pf.intermediari ?? d.intermediari ?? d.intermediaries ?? [];
    const intermediario = pf.intermediario ?? d.intermediario ?? intermediariesArr;
    const rifiuto = pf.rifiuto ?? d.rifiuto ?? {};
    // L'accettazione vera arriva in "dati_accettazione" (non "accettazione"): senza questo alias
    // la sezione risultava sempre vuota anche a FIR accettato.
    const acceptance = d.dati_accettazione ?? d.datiAccettazione ?? d.accettazione ?? d.acceptance ?? pf.accettazione ?? pf.acceptance ?? null;
    // I dati del trasporto (targa, inizio trasporto) sono dentro l'array "dati_trasporto", un
    // elemento per tratta: qui prendiamo l'ultima tratta (la piu' recente, es. dopo un trasbordo).
    const trasportiArr = Array.isArray(d.dati_trasporto) ? d.dati_trasporto : (Array.isArray(pf.dati_trasporto) ? pf.dati_trasporto : []);
    const trasportoCorrente = trasportiArr.length ? trasportiArr[trasportiArr.length - 1] : (d.dati_trasporto ?? pf.dati_trasporto ?? {});

    const status = d.stato_formulario ?? d.statoFormulario ?? d.stato ?? d.status ?? d.state ?? d.status_label ?? '';
    const producer = extractParty(producerObj, ['denominazione', 'ragione_sociale', 'ragioneSociale', 'nome', 'nominativo', 'codice_fiscale', 'codiceFiscale']);
    const transport = extractPartyList(transportersArr, ['denominazione', 'ragione_sociale', 'ragioneSociale', 'nome', 'nominativo', 'codice_fiscale', 'codiceFiscale']) || extractParty(d, ['trasportatore']);
    const recipient = extractPartyList(recipientObj, ['denominazione', 'ragione_sociale', 'ragioneSociale', 'nome', 'nominativo', 'codice_fiscale', 'codiceFiscale']) || extractParty(d, ['destinatario']);
    const transporters = Array.isArray(transportersArr)
      ? transportersArr.map(item => normalizeParty(item)).filter(Boolean).join(' · ')
      : normalizeParty(transportersArr);
    const recipients = Array.isArray(recipientsArr)
      ? recipientsArr.map(item => normalizeParty(item)).filter(Boolean).join(' · ')
      : normalizeParty(recipientsArr);
    const intermediaries = Array.isArray(intermediariesArr)
      ? intermediariesArr.map(item => normalizeParty(item)).filter(Boolean).join(' · ')
      : normalizeParty(intermediariesArr);
    const quantityRaw = d.quantita ?? d.quantita_totale ?? d.quantita_restituita ?? d.quantita_accettata ?? rifiuto.quantita ?? pf.quantita ?? '';
    const quantity = formatQuantity(quantityRaw);
    const eer = d.codice_eer ?? d.eer ?? d.codiceCER ?? rifiuto.codice_eer ?? pf.codice_eer ?? '';
    const acceptanceQtyRaw = acceptance?.quantita_accettata ?? acceptance?.quantitaAccettata ?? d.quantita_accettata ?? '';
    const acceptanceQty = formatQuantity(acceptanceQtyRaw, 'kg');
    const acceptanceArrival = acceptance?.data_ora_arrivo ?? acceptance?.dataOraArrivo ?? d.data_ora_arrivo ?? '';
    const acceptanceType = acceptance?.tipo_accettazione ?? acceptance?.tipoAccettazione ?? d.tipo_accettazione ?? '';
    const dataEmissione = d.data_emissione ?? d.dataEmissione ?? pf.data_emissione ?? '';
    const dataCreazione = d.data_creazione ?? d.dataCreazione ?? pf.data_creazione ?? '';
    const trasportoInizio = trasportoCorrente.data_ora_inizio_trasporto ?? trasportoCorrente.data_inizio_trasporto ?? d.data_inizio_trasporto ?? d.dataInizioTrasporto ?? d.data_ora_inizio_trasporto ?? d.inizio_trasporto ?? pf.data_inizio_trasporto ?? pf.data_ora_inizio_trasporto ?? '';
    const targaMotrice = trasportoCorrente.targa_automezzo ?? trasportoCorrente.targa_motrice ?? trasportoCorrente.targaAutomezzo ?? d.targa_motrice ?? d.targaMotrice ?? d.targa_mezzo ?? d.targa ?? pf.targa_motrice ?? pf.targa ?? '';
    const targaRimorchio = trasportoCorrente.targa_rimorchio ?? trasportoCorrente.targaRimorchio ?? d.targa_rimorchio ?? d.targaRimorchio ?? d.targa2 ?? pf.targa_rimorchio ?? '';
    const attivita = d.attivita ?? d.operazione ?? d.operazione_destinazione ?? pf.attivita ?? recipientObj.attivita ?? '';
    const visibilita = d.visibilita_sito_acquisita ?? d.visibilitaSitoAcquisita ?? '';
    const trasformatoCartaceo = d.trasformato_in_cartaceo ?? d.trasformatoInCartaceo ?? '';
    const versione = d.versione ?? d.version ?? '';
    const codiceBlocco = d.codice_blocco ?? d.codiceBlocco ?? '';
    const isUpload = d.is_upload ?? d.isUpload ?? '';
    const numeroFirOrigine = deepFind(d, ['trasbordo_parziale_origine', 'numero_fir_origine', 'numeroFirOrigine']) || '';
    return {
      raw: d,
      status,
      producer,
      transport,
      recipient,
      transporters,
      recipients,
      intermediaries,
      intermediario,
      quantity,
      eer,
      acceptanceQty,
      acceptanceArrival,
      acceptanceType,
      acceptance,
      dataEmissione,
      dataCreazione,
      trasportoInizio,
      targaMotrice,
      targaRimorchio,
      attivita,
      visibilita,
      trasformatoCartaceo,
      versione,
      codiceBlocco,
      isUpload,
      numeroFirOrigine,
      dati_partenza: pf,
      rifiuto,
    };
  }

  function setDetailCardValue(id, value) {
    const element = $(id);
    if (!element) return '';
    const text = String(value ?? '').trim();
    const empty = !text || text === '—' || text === '-';
    element.textContent = empty ? '' : text;
    const card = element.closest('.box');
    if (card) card.classList.toggle('hidden', empty);
    return empty ? '' : text;
  }

  function renderSelectedDetail(detail) {
    const norm = normalizeDetail(detail);
    const detailData = $('detailData');
    if (detailData) detailData.classList.remove('hidden');
    const statusLabel = friendlyStatus(norm.status);
    const hasAcceptanceData = norm.acceptance && Object.keys(norm.acceptance).length > 0;

    setDetailCardValue('detailNum', state.selectedNum || norm.raw?.numero_fir || norm.dati_partenza?.numero_fir || '');
    setDetailCardValue('detailStatus', statusLabel);
    setDetailCardValue('detailProd', norm.producer);
    setDetailCardValue('detailTransport', norm.transport);
    setDetailCardValue('detailDest', norm.recipient);
    setDetailCardValue('detailQty', norm.quantity);
    setDetailCardValue('detailEer', norm.eer);
    setDetailCardValue('detailEmissione', norm.dataEmissione ? fmtDate(norm.dataEmissione) : '');
    setDetailCardValue('detailCreazione', norm.dataCreazione ? fmtDate(norm.dataCreazione) : '');
    setDetailCardValue('detailTrasportoInizio', norm.trasportoInizio ? fmtDate(norm.trasportoInizio) : '');
    setDetailCardValue('detailAccettazione', hasAcceptanceData
      ? [norm.acceptanceType, norm.acceptanceQty, norm.acceptanceArrival ? fmtDate(norm.acceptanceArrival) : ''].filter(Boolean).join(' · ')
      : (norm.status === 'InserimentoAccettazione' ? 'Da inserire' : ''));
    setDetailCardValue('detailTargaMotrice', fmtValue(norm.targaMotrice));
    setDetailCardValue('detailTargaRimorchio', fmtValue(norm.targaRimorchio));
    setDetailCardValue('detailIntermediario', fmtValue(norm.intermediario));
    setDetailCardValue('detailAttivita', fmtValue(norm.attivita));
    setDetailCardValue('detailVisibilita', fmtBool(norm.visibilita));
    setDetailCardValue('detailCartaceo', fmtBool(norm.trasformatoCartaceo));
    setDetailCardValue('detailVersione', fmtValue(norm.versione));
    setDetailCardValue('detailBlocco', fmtValue(norm.codiceBlocco));
    setDetailCardValue('detailProdFull', norm.producer);
    setDetailCardValue('detailTransportersFull', norm.transporters);
    setDetailCardValue('detailRecipientsFull', norm.recipients);
    setDetailCardValue('detailIntermediariesFull', norm.intermediaries);

    const narrativeRows = [
      ['Numero FIR', state.selectedNum || norm.raw?.numero_fir || norm.dati_partenza?.numero_fir],
      ['Stato', statusLabel],
      ['Produttore', norm.producer],
      ['Trasportatore', norm.transport],
      ['Destinatario', norm.recipient],
      ['Intermediario', norm.intermediario],
      ['Codice EER', norm.eer],
      ['Quantità', norm.quantity],
      ['Data emissione', norm.dataEmissione ? fmtDate(norm.dataEmissione) : ''],
      ['Data creazione', norm.dataCreazione ? fmtDate(norm.dataCreazione) : ''],
      ['Inizio trasporto', norm.trasportoInizio ? fmtDate(norm.trasportoInizio) : ''],
      ['Targa motrice', fmtValue(norm.targaMotrice)],
      ['Targa rimorchio', fmtValue(norm.targaRimorchio)],
      ['Accettazione', hasAcceptanceData ? [norm.acceptanceType, norm.acceptanceQty, norm.acceptanceArrival ? fmtDate(norm.acceptanceArrival) : ''].filter(Boolean).join(' · ') : ''],
    ].filter(([, value]) => value !== null && value !== undefined && String(value).trim() !== '' && String(value).trim() !== '—' && String(value).trim() !== '-');
    const textArea = $('detailNarrative');
    if (textArea) textArea.textContent = narrativeRows.map(([label, value]) => `${label}: ${value}`).join('\n');

    $('detailBanner').textContent = state.selectedNum
      ? `FIR selezionato: ${state.selectedNum} · Stato: ${statusLabel}`
      : "Seleziona un FIR dall'elenco.";
    state.selectedStatusRaw = String(norm.status || '');
    state.selectedStatusLabel = statusLabel;
    state.selectedDetail = norm.raw;
    state.selectedSuggestedQuantity = norm.quantity;
    const roleHint = $('roleHint');
    if (roleHint) {
      const recipientStage = isRecipientActionStage(state.selectedStatusRaw);
      const currentCompanyIsRecipient = detailRecipientMatchesMyProfile(norm.raw);
      roleHint.textContent = !state.selectedNum
        ? 'Seleziona un formulario per iniziare.'
        : (recipientStage && !currentCompanyIsRecipient)
          ? 'Questo passaggio spetta al destinatario indicato nel formulario. Non devi inserire dati né firmare.'
          : (state.selectedStatusRaw === 'InserimentoAccettazione' && state.acceptanceSubmittedForFir !== state.selectedNum)
            ? 'Prima completa l’accettazione nella scheda a sinistra. Il pulsante di firma si attiverà dopo.'
            : 'Controlla il nominativo del certificato: la firma verrà applicata al ruolo previsto dal formulario.';
    }
    const acceptanceBanner = $('acceptanceStateHint');
    if (acceptanceBanner && canShowAcceptance(norm.status)) {
      acceptanceBanner.textContent = `Accettazione disponibile per questo FIR. Peso presunto proposto: ${norm.quantity !== '' && norm.quantity !== null && norm.quantity !== undefined ? norm.quantity : 'n/d'}.`;
    }
    syncAcceptanceSection();
    refreshQrPreview();
    updateActionButtons();
  }


  function showFriendlyMainMessage(text, kind='') {
    setBanner($('signBanner'), text, kind);
  }

  function clearFriendlyMainMessage() {
    hideBanner($('signBanner'));
  }

  function friendlyErrorMessage(err) {
    const raw = err?.raw || {};
    const detail = raw?.detail || {};
    const status = Number(raw?.http_status || 0);
    const detailText = JSON.stringify(detail || {}).toLowerCase();
    const backendText = detail?.validation_error || detail?.error || detail?.hint
      || detail?.problem_details?.response?.detail || detail?.problem_details?.response?.title || '';
    const title = String(backendText || err?.message || 'Operazione non riuscita').trim();

    if (/failed to fetch|networkerror|load failed|fetch failed/i.test(String(err?.message || ''))) {
      return 'Non riesco a collegarmi al servizio. Controlla che il computer sia connesso a Internet e riprova. Se il problema continua, avvisa l’amministratore.';
    }
    if (detailText.includes('chiavetta') || detailText.includes('certificato') || detailText.includes('pkcs') || detailText.includes('loadinfo is not defined')) {
      return 'Non riesco a leggere il certificato di firma. Controlla che la chiavetta USB sia inserita, premi “RILEVA CHIAVETTA” e seleziona il nominativo corretto. Se non compare, prova un’altra porta USB e avvisa l’amministratore.';
    }
    if (detailText.includes('non risulta firmato') || detailText.includes('not signed')) {
      return 'Non è possibile annullare la firma: il formulario non risulta firmato oppure la firma è già stata annullata. Non occorre ripetere l’operazione.';
    }
    if (detail?.problem_details?.response?.model_state) {
      return 'RENTRI ha rifiutato alcuni dati del formulario. Non ripetere subito l’operazione: controlla i dati inseriti e chiedi all’amministratore di verificare i dettagli tecnici.';
    }
    if (status === 400) {
      return `RENTRI non ha accettato la richiesta perché alcuni dati non sono validi. ${title} Controlla il formulario e, se non capisci quale dato manca, chiedi all’amministratore.`;
    }
    if (status === 401) {
      return 'La sessione di collegamento a RENTRI non è stata autorizzata. Non è un errore da correggere inserendo di nuovo i dati del formulario: avvisa l’amministratore.';
    }
    if (status === 403) {
      return 'RENTRI non autorizza questa operazione per il formulario selezionato. Potrebbe non essere di competenza della nostra azienda oppure lo stato del FIR potrebbe non permetterla. Non ripetere l’operazione; chiedi una verifica.';
    }
    if (status === 404) {
      return 'Il formulario o il documento richiesto non è disponibile su RENTRI. Aggiorna l’elenco e verifica di aver selezionato il FIR corretto.';
    }
    if (status === 409 || status === 423) {
      return 'Il formulario è momentaneamente bloccato oppure è già in lavorazione. Aggiorna i dati e verifica lo stato prima di riprovare.';
    }
    if (status === 429) {
      return 'RENTRI sta ricevendo troppe richieste. Attendi qualche minuto, poi aggiorna l’elenco. Evita di premere più volte lo stesso pulsante.';
    }
    if (status === 503 || status === 502 || status === 504) {
      return 'Il servizio RENTRI non è momentaneamente disponibile. Attendi qualche minuto e riprova. L’operazione potrebbe non essere stata completata: controlla lo stato del FIR prima di inviarla di nuovo.';
    }
    if (status >= 500) {
      return 'Si è verificato un problema tecnico durante il collegamento a RENTRI. Non ripetere subito un’accettazione o una firma: aggiorna prima il FIR e verifica se l’operazione è già stata registrata. Se il problema continua, avvisa l’amministratore.';
    }
    if (title && title !== 'Operazione non riuscita') {
      return `${title}. Se non sai come procedere, non ripetere l’operazione e avvisa l’amministratore.`;
    }
    return 'L’operazione non è riuscita. Non ripeterla più volte: aggiorna prima il formulario e verifica che non sia già stata completata. Se il problema continua, avvisa l’amministratore.';
  }


  function refreshStoredConfig() {
    const num = readStorage(STORAGE.numIscrSito, '');
    const ident = readStorage(STORAGE.identificativoSoggetto, '');
    if (!$('numIscrSito').dataset.edited) $('numIscrSito').value = num;
    if (!$('identificativoSoggetto').dataset.edited) $('identificativoSoggetto').value = ident;
  }

  function saveConfigInputs() {
    writeStorage(STORAGE.numIscrSito, $('numIscrSito').value.trim());
    writeStorage(STORAGE.identificativoSoggetto, $('identificativoSoggetto').value.trim());
  }

  async function loadInfo() {
    try {
      const info = await requestJson('/api/info');
      const env = String(info.env || 'demo').toUpperCase();
      const isProd = env === 'PROD';
      if ($('envBadge')) {
        $('envBadge').textContent = env;
        $('envBadge').style.background = isProd ? '#b91c1c' : '';
        $('envBadge').style.color = isProd ? '#fff' : '';
      }
      if ($('modePill')) {
        $('modePill').textContent = env;
        $('modePill').style.background = isProd ? '#b91c1c' : '';
        $('modePill').style.color = isProd ? '#fff' : '';
      }
      if ($('subtitle')) {
        // Mai piu' "Versione DEMO" fisso: deve riflettere l'ambiente reale, altrimenti si rischia
        // di firmare un FIR vero credendo di essere ancora in prova.
        const parts = [isProd ? 'PRODUZIONE — i FIR hanno valore legale' : 'Versione DEMO', 'firma USB'];
        if (info.num_iscr_sito) parts.push(info.num_iscr_sito);
        $('subtitle').textContent = parts.join(' · ');
      }
      if ($('sitePill')) {
        $('sitePill').textContent = info.num_iscr_sito ? `UL ${info.num_iscr_sito}` : 'Configurazione attiva';
      }
      if (info.init_error) {
        showFriendlyMainMessage('Attenzione: una parte della configurazione iniziale non è pronta. Apri Debug tecnico per i dettagli.', 'warn');
      }
      state.runtimeInfo = info;
      debugAppend('Configurazione caricata', {
        env: info.env,
        num_iscr_sito: info.num_iscr_sito,
        identificativo: info.identificativo,
        gestionale_user_id: info.gestionale_user_id,
        rollback_suffix: info.rollback_suffix,
      });
    } catch (err) {
      debugAppend('Errore caricamento configurazione', err.raw || err.message);
      showFriendlyMainMessage('Configurazione non disponibile al momento. Controlla il debug tecnico.', 'warn');
    }
  }

  function updateUsbMemoryNote(cert = null) {
    const subject = cert?.subject || readStorage(STORAGE.usbSubject, '');
    $('usbMemoryNote').textContent = subject ? `Ultima chiavetta usata: ${shortCertName(subject)}` : 'Ultima chiavetta usata: nessuna.';
  }

  function updateActionButtons() {
    $('reloadDetailBtn').disabled = !state.selectedNum;
    $('rollbackBtn').disabled = !(state.selectedNum && state.selectedDetail);
    $('rollbackBtn').title = state.selectedDetail
      ? 'RENTRI verifica se questa è la tua ultima firma e se sussistono ancora le condizioni per annullarla.'
      : 'Seleziona un formulario e attendi il caricamento dei suoi dati.';
    updateTabletSendButton();

    const hiddenToggle = $('toggleHiddenFirBtn');
    if (hiddenToggle) {
      const isHidden = state.hiddenFirEntries.some(item => item.numero_fir === state.selectedNum);
      hiddenToggle.disabled = !state.selectedNum;
      hiddenToggle.textContent = isHidden ? 'Ripristina formulario' : 'Nascondi formulario';
      hiddenToggle.title = isHidden
        ? 'Rende di nuovo visibile questo formulario nelle liste normali.'
        : 'Nasconde questo formulario solo in questo programma; non modifica RENTRI.';
    }

    const detailReady = Boolean(state.selectedNum && state.selectedDetail);
    const finalizedAcceptance = detailReady && isFinalizedAcceptanceStatus(state.selectedStatusRaw);
    const recipientStage = detailReady && isRecipientActionStage(state.selectedStatusRaw);
    const recipientIsCurrentCompany = detailReady && detailRecipientMatchesMyProfile(state.selectedDetail);
    // Se il passaggio appartiene al destinatario e non abbiamo verificato che
    // Truccolo Angelo sia quel destinatario, blocchiamo sia accettazione sia firma.
    const waitingForRecipient = Boolean(recipientStage && !recipientIsCurrentCompany && !finalizedAcceptance);
    const signCard = $('signCard');
    const closedCard = $('closedFirCard');
    const waitingCard = $('recipientWaitingCard');

    if (signCard) signCard.classList.toggle('hidden', !detailReady || finalizedAcceptance || waitingForRecipient);
    if (waitingCard) waitingCard.classList.toggle('hidden', !waitingForRecipient);
    if (waitingForRecipient) {
      const norm = normalizeDetail(state.selectedDetail);
      const recipientName = norm.recipient || 'il destinatario riportato nel formulario';
      $('recipientWaitingText').textContent = `Il destinatario indicato è ${recipientName}. L'accettazione e la firma di questo passaggio competono a quel destinatario, non a Truccolo Angelo.`;
    }

    if (closedCard) {
      closedCard.classList.toggle('hidden', !finalizedAcceptance);
      if (finalizedAcceptance) {
        const partial = String(state.selectedStatusRaw || '').toLowerCase().includes('parzial');
        $('closedFirTitle').textContent = partial ? 'Accettazione parziale già registrata' : 'Formulario già accettato';
        $('closedFirText').textContent = partial
          ? 'L’esito di accettazione parziale risulta già registrato su RENTRI. Non occorre ripetere l’operazione né apporre un’altra firma da questa schermata.'
          : 'L’accettazione risulta già registrata su RENTRI. Il formulario è concluso: non occorre apporre un’altra firma da questa schermata.';
      }
    }

    const acceptanceStillRequired = state.selectedStatusRaw === 'InserimentoAccettazione'
      && state.acceptanceSubmittedForFir !== state.selectedNum;
    $('usbSignBtn').disabled = !(detailReady && !finalizedAcceptance && !waitingForRecipient && state.usbSelected && state.usbSelected.suitable_for_signature && !state.usbSigningInProgress && !acceptanceStillRequired);
    $('usbSignBtn').title = finalizedAcceptance
      ? 'Questo formulario risulta già accettato e concluso.'
      : waitingForRecipient
        ? 'L’accettazione e la firma spettano al destinatario indicato nel formulario.'
        : acceptanceStillRequired
          ? 'Prima registra l’accettazione nella scheda dedicata.'
          : 'Firma il formulario selezionato.';
    const acceptanceBtn = $('acceptanceBtn');
    if (acceptanceBtn) {
      acceptanceBtn.disabled = !(state.selectedNum && state.acceptanceVisible && !waitingForRecipient);
    }
  }

  function acceptanceRecipientMatchesMyProfile(item) {
    // Regola di sicurezza: nel filtro "Da accettare" mostriamo soltanto i FIR
    // per i quali l'identificativo del destinatario coincide con il soggetto/UL
    // configurato. Non cercare "identificativo_soggetto" in tutto il FIR:
    // potrebbe appartenere al produttore o al trasportatore.
    return detailRecipientMatchesMyProfile(item);
  }

  function normalizeIdentityToken(value) {
    let token = String(value ?? '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (token.startsWith('IT') && token.length > 11) token = token.slice(2);
    return token;
  }

  function collectRecipientIdentityValues(root, results = [], depth = 0) {
    if (root === null || root === undefined || depth > 8) return results;
    if (Array.isArray(root)) {
      for (const item of root) collectRecipientIdentityValues(item, results, depth + 1);
      return results;
    }
    if (typeof root !== 'object') return results;

    const identityKeys = new Set([
      'codice_fiscale', 'codicefiscale', 'codice_fiscale_soggetto', 'codicefiscalesoggetto',
      'codice_fiscale_destinatario', 'codicefiscaledestinatario', 'cf',
      'partita_iva', 'partitaiva', 'piva',
      'partita_iva_destinatario', 'partitaivadestinatario', 'piva_destinatario', 'pivadestinatario',
      'identificativo_soggetto', 'identificativosoggetto', 'identificativo',
      'identificativo_soggetto_destinatario', 'identificativosoggettodestinatario',
      'num_iscr_sito', 'numiscrsito', 'num_iscr_sito_destinatario', 'numiscrsitodestinatario',
      'numero_iscrizione', 'numeroiscrizione'
    ]);
    for (const [key, value] of Object.entries(root)) {
      if (identityKeys.has(key.toLowerCase())) {
        if (Array.isArray(value)) {
          for (const item of value) if (item !== null && item !== undefined) results.push(item);
        } else if (value !== null && value !== undefined && typeof value !== 'object') {
          results.push(value);
        }
      }
      if (value && typeof value === 'object') collectRecipientIdentityValues(value, results, depth + 1);
    }
    return results;
  }

  function isRecipientActionStage(raw) {
    const token = String(raw || '').trim().toLowerCase().replace(/[\s_-]/g, '');
    // In questi stati l'azione è del destinatario: non basta essere un altro
    // soggetto coinvolto nel FIR (ad esempio il produttore o il trasportatore).
    return [
      'inserimentoaccettazione',
      'firmaaccettazione',
      'firmaaccettazionesuccessiva',
      'firmadestinatario'
    ].includes(token);
  }

  function getCurrentCompanyIdentityTokens() {
    const info = state.runtimeInfo || {};
    const rawValues = [
      info.identificativo,
      info.issuer,
      info.num_iscr_sito,
      readStorage(STORAGE.identificativoSoggetto, ''),
      readStorage(STORAGE.numIscrSito, ''),
      $('identificativoSoggetto')?.value?.trim?.() || '',
      $('numIscrSito')?.value?.trim?.() || '',
    ];
    return new Set(rawValues.map(normalizeIdentityToken).filter(Boolean));
  }

  function normalizeCompanyName(value) {
    return String(value ?? '')
      .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
      .toUpperCase()
      .replace(/[^A-Z0-9]/g, '');
  }

  function getCurrentCompanyNameTokens() {
    const info = state.runtimeInfo || {};
    const client = info.client || {};
    const values = [
      info.ragione_sociale,
      info.denominazione,
      info.company_name,
    ];

    // Il certificato P12 può riportare la denominazione in CN oppure O.
    // Non confrontiamo il DN intero: estraiamo soltanto i valori leggibili.
    for (const dn of [client.subject, client.issuer_cert]) {
      const source = String(dn || '');
      const re = /(?:^|,\s*)(CN|O|OU)=((?:\\.|[^,])*)/gi;
      let match;
      while ((match = re.exec(source)) !== null) {
        values.push(match[2].replace(/\\,/g, ',').trim());
      }
    }

    return new Set(values.map(normalizeCompanyName).filter(value => value.length >= 5));
  }

  function collectPartyMatchValues(root, identities = [], names = [], depth = 0) {
    if (root === null || root === undefined || depth > 10) return { identities, names };
    if (Array.isArray(root)) {
      for (const item of root) collectPartyMatchValues(item, identities, names, depth + 1);
      return { identities, names };
    }
    if (typeof root === 'string' || typeof root === 'number') {
      const value = String(root).trim();
      if (value) names.push(value);
      return { identities, names };
    }
    if (typeof root !== 'object') return { identities, names };

    const identityKeys = new Set([
      'codicefiscale', 'codicefiscalesoggetto', 'codicefiscaleoperatore', 'cf',
      'partitaiva', 'piva', 'identificativo', 'identificativosoggetto',
      'identificativooperatore', 'numiscrsito', 'numeroiscrizione', 'idsoggetto',
      'idoperatore', 'codicefiscaleproduttore', 'codicefiscaletrasportatore',
      'partitaivaproduttore', 'partitaivatrasportatore'
    ]);
    const nameKeys = new Set([
      'denominazione', 'denominazionesoggetto', 'denominazioneoperatore',
      'ragionesociale', 'nominativo', 'nomeazienda', 'companyname'
    ]);

    for (const [key, value] of Object.entries(root)) {
      const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (identityKeys.has(normalizedKey) && value !== null && value !== undefined && typeof value !== 'object') {
        identities.push(value);
      }
      if (nameKeys.has(normalizedKey) && value !== null && value !== undefined && typeof value !== 'object') {
        names.push(value);
      }
      if (value && typeof value === 'object') {
        collectPartyMatchValues(value, identities, names, depth + 1);
      }
    }
    return { identities, names };
  }

  function deepFindAllValues(root, wantedKeys, results = [], depth = 0) {
    if (root === null || root === undefined || depth > 10) return results;
    if (Array.isArray(root)) {
      for (const item of root) deepFindAllValues(item, wantedKeys, results, depth + 1);
      return results;
    }
    if (typeof root !== 'object') return results;
    for (const [key, value] of Object.entries(root)) {
      if (wantedKeys.includes(key) && value !== null && value !== undefined && value !== '') {
        results.push(value);
      }
      if (value && typeof value === 'object') {
        deepFindAllValues(value, wantedKeys, results, depth + 1);
      }
    }
    return results;
  }

  function itemMatchesCurrentCompany(item, aliases) {
    const expectedIds = getCurrentCompanyIdentityTokens();
    const expectedNames = getCurrentCompanyNameTokens();
    if ((!expectedIds.size && !expectedNames.size) || !item) return false;

    const containers = aliases.flatMap(alias => deepFindAllValues(item, alias));
    const foundIds = [];
    const foundNames = [];
    for (const container of containers) {
      collectPartyMatchValues(container, foundIds, foundNames);
      // Alcuni riepiloghi API espongono il ruolo come semplice stringa.
      if (typeof container === 'string') foundNames.push(container);
    }

    const idMatch = foundIds.some(value => expectedIds.has(normalizeIdentityToken(value)));
    if (idMatch) return true;

    const nameMatch = foundNames.some(value => expectedNames.has(normalizeCompanyName(value)));
    return nameMatch;
  }

  function detailRecipientMatchesMyProfile(item) {
    return itemMatchesCurrentCompany(item, [
      ['destinatario'], ['destinatari'], ['recipient'], ['recipients'],
      ['destinatario_denominazione'], ['denominazione_destinatario'],
      ['ragione_sociale_destinatario'], ['codice_fiscale_destinatario'],
      ['codice_fiscale_soggetto_destinatario'], ['partita_iva_destinatario'],
      ['identificativo_soggetto_destinatario'], ['num_iscr_sito_destinatario']
    ]);
  }

  function getFirStatus(item) {
    const value = deepFind(item, [
      'stato_formulario', 'statoFormulario', 'stato', 'status', 'state'
    ]);
    if (value && typeof value === 'object') {
      return String(value.codice ?? value.value ?? value.stato ?? value.descrizione ?? '');
    }
    return String(value ?? '').trim();
  }

  function isSigningStatusCandidate(raw) {
    const token = String(raw || '').trim().toLowerCase().replace(/[\s_-]/g, '');
    // Escludiamo intenzionalmente InserimentoAccettazione: significa "da accettare",
    // non "da firmare". Sono ammessi solo stati che richiedono un atto di firma.
    return [
      'firmaproduttoretrasportatoreiniziale',
      'firmaproduttoreiniziale',
      'firmatrasportatoreiniziale',
      'firmaproduttore',
      'firmatrasportatore',
      'firmatrasportatoresuccessivo',
      'firmadestinatario',
      'firmadestinatariosuccessivo',
      'firmaaccettazione',
      'firmaaccettazionesuccessiva'
    ].includes(token);
  }

  function shouldShowSigningRow(item) {
    const token = getFirStatus(item).toLowerCase().replace(/[\s_-]/g, '');
    if (!isSigningStatusCandidate(token)) return false;

    const recipientStage = [
      'firmaaccettazione', 'firmaaccettazionesuccessiva',
      'firmadestinatario', 'firmadestinatariosuccessivo'
    ].includes(token);
    if (recipientStage) return detailRecipientMatchesMyProfile(item);

    // Nel nome combinato "FirmaProduttoreTrasportatoreIniziale" la seconda
    // parola è "Trasportatore", non "FirmaTrasportatore": cercare la sequenza
    // "firmatrasportatore" escludeva erroneamente proprio questo stato.
    const producerStage = token.includes('produttore');
    const transportStage = token.includes('trasportatore');

    const producerMatch = producerStage && itemMatchesCurrentCompany(item, [
      ['produttore'], ['produttori'], ['producer'],
      ['produttore_denominazione'], ['denominazione_produttore'],
      ['ragione_sociale_produttore'], ['codice_fiscale_produttore'],
      ['codice_fiscale_soggetto_produttore'], ['partita_iva_produttore'],
      ['identificativo_soggetto_produttore']
    ]);
    const transportMatch = transportStage && itemMatchesCurrentCompany(item, [
      ['trasportatore'], ['trasportatori'], ['transporters'], ['transporter'],
      ['trasportatore_denominazione'], ['denominazione_trasportatore'],
      ['ragione_sociale_trasportatore'], ['codice_fiscale_trasportatore'],
      ['partita_iva_trasportatore'], ['identificativo_soggetto_trasportatore']
    ]);

    // Nello stato combinato è sufficiente che Truccolo sia uno dei due firmatari.
    return Boolean(producerMatch || transportMatch);
  }

  async function filterSigningRowsWithDetails(rows) {
    const candidates = rows.filter(item => isSigningStatusCandidate(getFirStatus(item)));
    if (!candidates.length) return [];

    const matched = [];
    let detailErrors = 0;
    const concurrency = 4;
    for (let offset = 0; offset < candidates.length; offset += concurrency) {
      const batch = candidates.slice(offset, offset + concurrency);
      const results = await Promise.all(batch.map(async summary => {
        const numero = String(
          deepFind(summary, ['numero_fir', 'numeroFir', 'numero']) || ''
        ).trim();
        if (!numero) return null;
        try {
          const detail = await requestJson(`/api/formulari/${encodeURIComponent(numero)}`);
          const detailRecord = (detail && typeof detail === 'object')
            ? (detail.data ?? detail.result ?? detail.risultato ?? detail)
            : detail;
          const merged = {
            ...summary,
            ...(detailRecord && typeof detailRecord === 'object' && !Array.isArray(detailRecord) ? detailRecord : {}),
            dettaglio_completo: detail,
          };
          return shouldShowSigningRow(merged) ? summary : null;
        } catch (error) {
          detailErrors += 1;
          debugAppend(`Dettaglio non disponibile per il filtro firma (${numero})`, error.raw || error.message);
          // Fail closed: se non riusciamo a verificare il ruolo, non mostriamo il FIR
          // come firmabile per errore.
          return null;
        }
      }));
      for (const result of results) if (result) matched.push(result);
    }
    debugAppend('Verifica filtro Da firmare', {
      righe_ricevute: rows.length,
      stati_di_firma: candidates.length,
      firma_di_competenza_truccolo: matched.length,
      errori_dettaglio: detailErrors,
    });
    return matched;
  }

  function shouldShowRowForCurrentView(item) {
    const view = $('searchVista').value;
    if (view === 'ACCETTAZIONE') return acceptanceRecipientMatchesMyProfile(item);
    if (view === 'FIRMA') return shouldShowSigningRow(item);
    return true;
  }

  function updatePageControls(rowsCount, paging = {}) {
    const page = Number(paging['Paging-Page'] || paging.page || state.currentPage || 1);
    const pageSize = Number(paging['Paging-PageSize'] || paging.page_size || state.pageSize || 5);
    const prevBtn = $('prevBtn');
    const nextBtn = $('nextBtn');
    const pagingInfo = $('pagingInfo');

    if (pagingInfo) {
      pagingInfo.textContent = `Pagina ${page}`;
    }
    if (prevBtn) {
      prevBtn.disabled = page <= 1;
    }
    if (nextBtn) {
      nextBtn.disabled = rowsCount < pageSize;
    }
  }

  function hiddenFirSet() {
    return new Set(state.hiddenFirEntries.map(item => String(item.numero_fir || '').trim()).filter(Boolean));
  }

  function makeHiddenFirSnapshot(item) {
    const numero = String(item?.numero_fir ?? item?.numeroFir ?? state.selectedNum ?? '').trim();
    return {
      numero_fir: numero,
      produttore_display: extractParty(item, ['produttore', 'produttore_denominazione', 'denominazione_produttore', 'ragione_sociale_produttore']) || '-',
      trasportatore_display: extractPartyList(item, ['trasportatore', 'trasportatore_denominazione', 'denominazione_trasportatore', 'ragione_sociale_trasportatore', 'trasportatori']) || '-',
      destinatario_display: extractPartyList(item, ['destinatario', 'destinatario_denominazione', 'denominazione_destinatario', 'ragione_sociale_destinatario', 'destinatari']) || '-',
      codice_eer: String(item?.codice_eer ?? item?.eer ?? item?.codiceCER ?? ''),
      quantita_display: formatQuantity(item?.quantita, item?.unita_misura) || '-',
      stato: String(item?.stato ?? item?.status ?? item?.state ?? ''),
      nascosto_il: new Date().toISOString(),
    };
  }

  function renderFirRows(rows) {
    const tbody = $('tbody');
    if (!rows.length) {
      const isHiddenView = $('searchVisibility')?.value === 'NASCOSTI';
      const emptyMessage = isHiddenView
        ? 'Non hai ancora nascosto formulari. Per archiviarne uno, selezionalo e premi “Nascondi formulario”.'
        : $('searchVista').value === 'ACCETTAZIONE'
          ? 'Nessun formulario in attesa di accettazione intestato a Truccolo Angelo. I formulari con altri destinatari vengono esclusi.'
          : $('searchVista').value === 'FIRMA'
            ? 'Nessun formulario che richiede la tua firma.'
            : 'Nessun formulario trovato con questi filtri.';
      tbody.innerHTML = `<tr><td colspan="7" class="muted">${esc(emptyMessage)}</td></tr>`;
      return;
    }

    tbody.innerHTML = rows.map((item, index) => {
      const producer = item.produttore_display || extractParty(item, ['produttore', 'produttore_denominazione', 'denominazione_produttore', 'ragione_sociale_produttore']) || '-';
      const transport = item.trasportatore_display || extractPartyList(item, ['trasportatore', 'trasportatore_denominazione', 'denominazione_trasportatore', 'ragione_sociale_trasportatore', 'trasportatori']) || '-';
      const recipient = item.destinatario_display || extractPartyList(item, ['destinatario', 'destinatario_denominazione', 'denominazione_destinatario', 'ragione_sociale_destinatario', 'destinatari']) || '-';
      const qty = item.quantita_display || formatQuantity(item.quantita, item.unita_misura) || '-';
      const status = friendlyStatus(item.stato || item.status || item.state);
      const number = String(item.numero_fir || item.numeroFir || '').trim();
      return `<tr data-index="${index}" class="${number === state.selectedNum ? 'selected' : ''}">
        <td><b>${esc(number || '-')}</b></td>
        <td>${esc(producer)}</td>
        <td>${esc(transport)}</td>
        <td>${esc(recipient)}</td>
        <td>${esc(item.codice_eer || item.eer || item.codiceCER || '-')}</td>
        <td>${esc(qty)}</td>
        <td>${esc(status)}</td>
      </tr>`;
    }).join('');
    tbody.querySelectorAll('tr[data-index]').forEach(row => {
      row.addEventListener('click', () => selectFir(state.rows[Number(row.dataset.index)].numero_fir));
    });
  }

  async function loadHiddenFirConfig() {
    const config = await requestJson('/api/ui/hidden-firs');
    state.hiddenFirEntries = Array.isArray(config?.items) ? config.items : [];
    state.hiddenFirConfigLoaded = true;
    updateActionButtons();
  }

  async function saveHiddenFirConfig(items) {
    const result = await requestJson('/api/ui/hidden-firs', {
      method: 'PUT',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({items}),
    });
    state.hiddenFirEntries = Array.isArray(result?.items) ? result.items : items;
    state.hiddenFirConfigLoaded = true;
    updateActionButtons();
  }

  function clearSelectedFirView(message = 'Formulario archiviato in locale. Per ritrovarlo apri “Altri filtri” e scegli “Formulari nascosti (archivio)”.') {
    clearTabletQrSilently();
    state.selectedNum = null;
    state.selectedRow = null;
    state.selectedDetail = null;
    state.selectedStatusRaw = '';
    state.selectedStatusLabel = '';
    state.acceptanceSubmittedForFir = '';
    $('detailData')?.classList.add('hidden');
    if ($('detailBanner')) $('detailBanner').textContent = message;
    $('qrDock')?.classList.add('hidden');
    $('qrThumb')?.removeAttribute('src');
    resetAcceptanceForm();
    clearUsbHashCache();
    syncAcceptanceSection();
    updateActionButtons();
  }

  async function toggleHiddenSelectedFir() {
    const numero = String(state.selectedNum || '').trim();
    if (!numero) return;
    const current = state.hiddenFirEntries;
    const alreadyHidden = current.some(item => item.numero_fir === numero);
    let nextItems;

    if (alreadyHidden) {
      nextItems = current.filter(item => item.numero_fir !== numero);
    } else {
      const source = state.selectedRow || state.selectedDetail || {numero_fir: numero};
      const snapshot = makeHiddenFirSnapshot(source);
      snapshot.numero_fir = numero;
      nextItems = [snapshot, ...current.filter(item => item.numero_fir !== numero)];
    }

    const action = alreadyHidden ? 'ripristinare' : 'nascondere';
    if (!confirm(`Vuoi ${action} il formulario ${numero}?\n\nQuesta scelta riguarda solo la visualizzazione di questo programma. Non modifica né cancella il formulario su RENTRI.`)) return;

    const previousItems = current;
    try {
      await saveHiddenFirConfig(nextItems);
      clearSelectedFirView(alreadyHidden
        ? 'Formulario ripristinato. Tornerà visibile nelle liste normali.'
        : 'Formulario nascosto in locale. Puoi ritrovarlo in “Altri filtri” → “Formulari nascosti (archivio)”.');
      await loadList(1);
      showFriendlyMainMessage(alreadyHidden
        ? `Formulario ${numero} ripristinato nelle liste normali.`
        : `Formulario ${numero} nascosto. È stato salvato sul computer e potrai ripristinarlo quando vuoi.`, 'ok');
    } catch (err) {
      state.hiddenFirEntries = previousItems;
      updateActionButtons();
      showFriendlyMainMessage(friendlyErrorMessage(err), 'err');
      debugAppend('Errore salvataggio archivio formulari nascosti', err.raw || err.message);
    }
  }

  async function loadList(page = 1) {
    $('searchBtn').disabled = true;
    try {
      if (!state.hiddenFirConfigLoaded) {
        await loadHiddenFirConfig();
      }
      saveConfigInputs();
      const pageSize = Number($('pageSizeSelect').value || state.pageSize || 5);
      state.pageSize = pageSize;
      const number = $('searchNumeroFir').value.trim().toUpperCase();
      const eer = $('searchEer').value.trim().toUpperCase();
      const hiddenView = $('searchVisibility')?.value === 'NASCOSTI';
      $('searchVista').disabled = hiddenView;

      if (hiddenView) {
        let archived = [...state.hiddenFirEntries];
        if (number) archived = archived.filter(item => String(item.numero_fir || '').toUpperCase().includes(number));
        if (eer) archived = archived.filter(item => String(item.codice_eer || '').toUpperCase().includes(eer));
        state.currentPage = 1;
        state.rows = archived;
        renderFirRows(state.rows);
        $('pagingInfo').textContent = `Archivio locale · ${archived.length} formulari`;
        $('prevBtn').disabled = true;
        $('nextBtn').disabled = true;
        debugAppend('Archivio locale formulari nascosti caricato', {count: archived.length});
        return;
      }

      $('searchVista').disabled = false;
      const params = new URLSearchParams({
        filtro_tipo: 'sito',
        stato: searchStateToBackend($('searchVista').value) || 'TUTTI',
        page: String(page),
        page_size: String(pageSize)
      });
      const site = $('numIscrSito').value.trim();
      const subject = $('identificativoSoggetto').value.trim();
      const apiNumber = $('searchNumeroFir').value.trim();
      const apiEer = $('searchEer').value.trim();
      if (site) params.set('num_iscr_sito', site);
      if (subject) params.set('identificativo_soggetto', subject);
      if (apiNumber) params.set('numero_fir', apiNumber);
      if (apiEer) params.set('codice_eer', apiEer);

      const result = await requestJson('/api/formulari?' + params.toString());
      const rows = Array.isArray(result.data) ? result.data : [];
      const normalizedRows = rows.map(item => unwrapRecord(item) || {});
      const hiddenNumbers = hiddenFirSet();
      const currentView = $('searchVista').value;
      let visibleRows = normalizedRows.filter(item => !hiddenNumbers.has(String(item.numero_fir || item.numeroFir || '').trim()));
      if (currentView === 'ACCETTAZIONE') {
        visibleRows = visibleRows.filter(item => acceptanceRecipientMatchesMyProfile(item));
      } else if (currentView === 'FIRMA') {
        // Il riepilogo elenco non sempre contiene gli identificativi completi dei soggetti.
        // Per ogni FIR in uno stato di firma recuperiamo il dettaglio ufficiale e verifichiamo
        // produttore/trasportatore/destinatario sui dati completi.
        visibleRows = await filterSigningRowsWithDetails(visibleRows);
      }
      state.currentPage = page;
      state.rows = visibleRows;
      renderFirRows(state.rows);
      updatePageControls(rows.length, result.paging || {});
      debugAppend('Lista FIR caricata', {page, count: rows.length, visible: visibleRows.length, hiddenExcluded: rows.length - visibleRows.length});
    } catch (err) {
      showFriendlyMainMessage(friendlyErrorMessage(err), 'err');
      debugAppend('Errore elenco FIR', err.raw || err.message);
    } finally {
      $('searchBtn').disabled = false;
    }
  }

  function changePage(delta) {
    const next = Math.max(1, (state.currentPage || 1) + delta);
    loadList(next);
  }

  async function selectFir(numero) {
    if (state.selectedNum !== numero) {
      // Evita che l'autista successivo possa scansionare il QR del FIR precedente.
      await clearTabletQrSilently();
      state.acceptanceSubmittedForFir = '';
      resetAcceptanceForm();
    }
    state.selectedNum = numero;
    state.selectedRow = state.rows.find(r => r.numero_fir === numero) || null;
    // Nasconde subito la scheda del FIR precedente mentre viene caricato il nuovo dettaglio.
    state.selectedDetail = null;
    state.selectedStatusRaw = '';
    syncAcceptanceSection();
    updateActionButtons();
    clearUsbHashCache();
    Array.from($('tbody').querySelectorAll('tr[data-index]')).forEach(row => {
      row.classList.toggle('selected', state.rows[Number(row.dataset.index)]?.numero_fir === numero);
    });
    $('reloadDetailBtn').disabled = false;
    clearFriendlyMainMessage();
    await reloadDetail();
    syncAcceptanceSection();
    refreshQrPreview();
    updateActionButtons();
  }

  async function reloadDetail() {
    if (!state.selectedNum) return;
    try {
      const detail = await requestJson('/api/formulari/' + encodeURIComponent(state.selectedNum));
      debugAppend('Dettaglio FIR', detail);
      renderSelectedDetail(detail);
    } catch (err) {
      if (state.selectedRow) {
        renderSelectedDetail(state.selectedRow);
        debugAppend('Dettaglio FIR parziale', state.selectedRow);
        showFriendlyMainMessage('Dettaglio completo non disponibile: mostro i dati già presenti nella lista.', 'warn');
        return;
      }
      showFriendlyMainMessage(friendlyErrorMessage(err), 'err');
      debugAppend('Errore dettaglio FIR', err.raw || err.message);
    }
  }

  async function sendAcceptance() {
    if (!state.selectedNum) return;
    const tipo = $('acceptanceType').value;
    const quantityText = String($('acceptedQuantity').value || '').trim();
    const quantity = quantityText === '' ? NaN : Number(quantityText);
    const arrivalIsoLocal = getArrivalIsoLocal();
    if (!arrivalIsoLocal) {
      showFriendlyMainMessage('Inserisci una data valida nel formato GG/MM/AAAA e un’ora valida nel formato HH:MM.', 'warn');
      return;
    }
    if (!Number.isFinite(quantity) || quantity < 0) {
      showFriendlyMainMessage('Inserisci una quantità valida.', 'warn');
      return;
    }
    if (tipo !== 'R' && quantity <= 0) {
      showFriendlyMainMessage('La quantità accettata deve essere maggiore di zero.', 'warn');
      return;
    }
    if (tipo === 'R' && quantity !== 0) {
      showFriendlyMainMessage('Per il respingimento totale la quantità deve essere zero.', 'warn');
      return;
    }
    const labels = {A:'Accettato integralmente', P:'Accettato parzialmente', R:'Respinto totalmente'};
    const weightHint = state.selectedSuggestedQuantity !== null && state.selectedSuggestedQuantity !== undefined && state.selectedSuggestedQuantity !== ''
      ? `Peso presunto proposto: ${state.selectedSuggestedQuantity}`
      : '';
    const arrivalDisplay = `${$('arrivalDate').value} ${$('arrivalTime').value}`;
    const summary = `FIR ${state.selectedNum}\nEsito: ${labels[tipo]}\nQuantità accettata: ${quantity}\nArrivo: ${arrivalDisplay}${weightHint ? `\n${weightHint}` : ''}`;
    if (!confirm(`Confermi l'accettazione del formulario?\n\n${summary}`)) return;
    const submitButton = $('acceptanceBtn');
    if (submitButton) submitButton.disabled = true;
    try {
      const result = await requestJson(`/api/formulari/${encodeURIComponent(state.selectedNum)}/accettazione`, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({
          tipo_accettazione: tipo,
          quantita_accettata: quantity,
          data_ora_arrivo: arrivalIsoLocal,
        })
      });
      state.acceptanceSubmittedForFir = state.selectedNum;
      resetAcceptanceForm();
      showFriendlyMainMessage('Accettazione completata con successo.', 'ok');
      debugAppend('Accettazione inviata', result);
      await reloadDetail();
      await loadList(state.currentPage || 1);
    } catch (err) {
      showFriendlyMainMessage(friendlyErrorMessage(err), 'err');
      debugAppend('Errore invio accettazione', err.raw || err.message);
    } finally {
      if (submitButton) submitButton.disabled = false;
    }
  }

  function certLabel(cert) {
    const name = shortCertName(cert.subject || '');
    const date = cert.valid_to ? new Date(cert.valid_to).toLocaleDateString('it-IT') : 'n/d';
    return `${name} · scade ${date}`;
  }

  async function loadUsbCertificates() {
    const btn = $('scanUsbCertsBtn');
    btn.disabled = true;
    btn.textContent = 'Ricerca…';
    try {
      const result = await requestJson('/api/usb-signing/certificates');
      const rows = Array.isArray(result.certificates) ? result.certificates : [];
      state.usbCertificates = rows;
      const sel = $('usbCertSelect');
      sel.innerHTML = '<option value="">Seleziona il certificato di firma</option>';
      rows.forEach(cert => {
        const opt = document.createElement('option');
        opt.value = cert.thumbprint;
        opt.textContent = certLabel(cert);
        sel.appendChild(opt);
      });
      const remembered = readStorage(STORAGE.usbThumbprint, '');
      if (remembered && rows.some(c => c.thumbprint === remembered)) {
        sel.value = remembered;
      }
      if (sel.value) selectUsbCertificate();
      else {
        state.usbSelected = null;
        $('usbCertSummary').classList.add('hidden');
        $('usbCertSummary').textContent = '';
        updateUsbMemoryNote();
      }
      debugAppend('Certificati Windows rilevati', {count: rows.length, windows_user: result.windows_user || '', provider: result.provider || ''});
      if (!rows.length) {
        showFriendlyMainMessage('Chiavetta non inserita o certificato di firma non disponibile.', 'warn');
      } else {
        showFriendlyMainMessage(`${rows.length} certificato/i trovato/i. Seleziona la chiavetta giusta e firma.`, 'ok');
      }
    } catch (err) {
      showFriendlyMainMessage(friendlyErrorMessage(err), 'err');
      debugAppend('Errore ricerca certificati', err.raw || err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = 'RILEVA CHIAVETTA';
    }
  }

  function selectUsbCertificate() {
    const thumb = $('usbCertSelect').value;
    const rows = state.usbCertificates || [];
    const cert = rows.find(c => c.thumbprint === thumb) || null;
    state.usbSelected = cert;
    clearUsbHashCache();
    if (!cert) {
      $('usbCertSummary').classList.add('hidden');
      $('usbCertSummary').textContent = '';
      writeStorage(STORAGE.usbThumbprint, '');
      writeStorage(STORAGE.usbSubject, '');
      updateUsbMemoryNote();
      updateActionButtons();
      return;
    }
    writeStorage(STORAGE.usbThumbprint, cert.thumbprint || '');
    writeStorage(STORAGE.usbSubject, cert.subject || '');
    $('usbCertSummary').classList.remove('hidden');
    $('usbCertSummary').className = 'banner';
    $('usbCertSummary').textContent = `Chiavetta pronta: ${shortCertName(cert.subject)}`;
    updateUsbMemoryNote(cert);
    debugAppend('Certificato selezionato', cert);
    updateActionButtons();
  }

  async function prepareUsbHash() {
    if (!state.selectedNum || !state.usbSelected) {
      throw new Error('Chiavetta non inserita o non selezionata.');
    }
    const cert = state.usbSelected;
    if (state.usbHashTransactionId && state.usbHashCertThumb === cert.thumbprint && state.usbHashToken && state.usbDigestToSign) {
      return {
        token: state.usbHashToken,
        digest_to_sign: state.usbDigestToSign,
        certificate_base64: state.usbHashCertBase64
      };
    }

    clearUsbHashCache();
    state.usbHashCertThumb = cert.thumbprint || '';
    state.usbHashCertBase64 = cert.certificate_base64 || '';
    showFriendlyMainMessage('Preparo la firma con RENTRI…', 'warn');
    const hashResponse = await requestJson(`/api/formulari/${encodeURIComponent(state.selectedNum)}/hash`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ certificato_base64: cert.certificate_base64 })
    });
    debugAppend('Richiesta hash', hashResponse);

    let transactionId = deepFind(hashResponse, ['transazione_id', 'transaction_id', 'id']);
    let token = deepFind(hashResponse, ['token']);
    let digest = deepFind(hashResponse, ['digest_to_sign', 'digestToSign']);
    if (token && digest) {
      state.usbHashTransactionId = transactionId || '';
      state.usbHashToken = String(token);
      state.usbDigestToSign = String(digest);
      return {
        token: state.usbHashToken,
        digest_to_sign: state.usbDigestToSign,
        certificate_base64: cert.certificate_base64
      };
    }

    if (!transactionId) {
      throw new Error('RENTRI ha preso in carico la richiesta ma non ha restituito l’ID della transazione.');
    }

    for (let attempt = 1; attempt <= 30; attempt++) {
      await wait(2000);
      try {
        await requestJson(`/api/transazioni/${encodeURIComponent(transactionId)}/status`);
      } catch (err) {
        debugAppend('Stato transazione hash', err.raw || err.message);
      }
      try {
        const result = await requestJson(`/api/transazioni/${encodeURIComponent(transactionId)}/result`);
        debugAppend('Esito transazione hash', result);
        token = deepFind(result, ['token']);
        digest = deepFind(result, ['digest_to_sign', 'digestToSign']);
        if (token && digest) {
          state.usbHashTransactionId = transactionId;
          state.usbHashToken = String(token);
          state.usbDigestToSign = String(digest);
          return {
            token: state.usbHashToken,
            digest_to_sign: state.usbDigestToSign,
            certificate_base64: cert.certificate_base64
          };
        }
      } catch (err) {
        const status = err?.raw?.http_status;
        if (![202, 404, 409, 425].includes(Number(status))) {
          throw err;
        }
      }
    }
    throw new Error('RENTRI non ha ancora restituito il digest da firmare. Riprova più tardi usando lo stesso FIR e lo stesso certificato.');
  }

  async function signWithUsb() {
    if (!state.selectedNum) {
      showFriendlyMainMessage('Seleziona prima un FIR.', 'warn');
      return;
    }
    if (!state.usbSelected || !state.usbSelected.suitable_for_signature) {
      showFriendlyMainMessage('Chiavetta non inserita o certificato non selezionato.', 'warn');
      return;
    }

    const confirmText = `Stai per firmare il FIR ${state.selectedNum} con la chiavetta collegata.\n\nChiavetta: ${shortCertName(state.usbSelected.subject)}\n\nProcedere?`;
    if (!confirm(confirmText)) return;

    state.usbSigningInProgress = true;
    updateActionButtons();
    $('usbSignBtn').textContent = 'Firma in corso…';
    showFriendlyMainMessage('Firma in corso…', 'warn');
    try {
      const hashData = await prepareUsbHash();
      const result = await requestJson('/api/usb-signing/sign-acquire', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({
          numero_fir: state.selectedNum,
          thumbprint: state.usbSelected.thumbprint,
          digest_to_sign: hashData.digest_to_sign,
          token: hashData.token,
          certificato_base64: hashData.certificate_base64,
          identificativo_utente: readStorage('rentri_signature_user_id', 'TRUCCOLO-PC'),
          reply_to: null
        })
      });
      debugAppend('Firma completa', result);
      $('usbCertSummary').classList.remove('hidden');
      $('usbCertSummary').className = 'banner ok';
      $('usbCertSummary').textContent = 'Firma apposta con successo.';
      showFriendlyMainMessage('Firma apposta con successo. Il formulario è stato aggiornato: puoi selezionare il successivo.', 'ok');
      await reloadDetail();
      await loadList(state.currentPage || 1);
    } catch (err) {
      showFriendlyMainMessage(friendlyErrorMessage(err), 'err');
      debugAppend('Errore firma USB', err.raw || err.message);
    } finally {
      state.usbSigningInProgress = false;
      $('usbSignBtn').textContent = 'FIRMA IL FORMULARIO';
      updateActionButtons();
    }
  }

  async function rollbackSignature() {
    if (!state.selectedNum) return;
    const warning = `ATTENZIONE: stai richiedendo a RENTRI l'annullamento dell'ultima firma del FIR ${state.selectedNum}.\n\nIl rollback è possibile soltanto per una tua ultima firma e se RENTRI conferma che sussistono ancora le condizioni previste (ad esempio il limite temporale e l'assenza di eventi successivi). L'operazione non elimina il FIR.\n\nVuoi continuare?`;
    if (!confirm(warning)) return;
    try {
      const result = await requestJson(`/api/formulari/${encodeURIComponent(state.selectedNum)}/rollback`, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({})
      });
      showFriendlyMainMessage('Ultima firma annullata con successo.', 'ok');
      debugAppend('Annulla ultima firma', result);
      await reloadDetail();
      await loadList(state.currentPage || 1);
    } catch (err) {
      const message = friendlyErrorMessage(err);
      showFriendlyMainMessage(message, 'err');
      debugAppend('Errore annulla ultima firma', err.raw || err.message);
    }
  }

  async function init() {
    try {
      const savedPageSize = Number(readStorage(STORAGE.pageSize, '5')) || 5;
      state.pageSize = [5, 10, 20, 50, 100].includes(savedPageSize) ? savedPageSize : 5;
      if ($('pageSizeSelect')) $('pageSizeSelect').value = String(state.pageSize);
      refreshStoredConfig();
      await loadInfo();
      await loadHiddenFirConfig();
      await loadList(1);
      await updateTabletStatus();
      window.setInterval(updateTabletStatus, 3000);
      const rememberedThumb = readStorage(STORAGE.usbThumbprint, '');
      if (rememberedThumb) {
        await loadUsbCertificates();
      } else {
        updateUsbMemoryNote();
      }
      updateActionButtons();
    } catch (err) {
      showFriendlyMainMessage(friendlyErrorMessage(err), 'err');
      debugAppend('Errore avvio', err.raw || err.message);
    }
  }

  // All'avvio mostra subito i FIR che richiedono la firma di Truccolo Angelo.
  const startupView = $('searchVista');
  if (startupView) startupView.value = 'FIRMA';

  $('usbCertSelect').addEventListener('change', selectUsbCertificate);
  const acceptedQuantityInput = $('acceptedQuantity');
  if (acceptedQuantityInput) {
    acceptedQuantityInput.addEventListener('input', () => {
      acceptedQuantityInput.dataset.manual = '1';
    });
  }
  $('searchVisibility').addEventListener('change', () => {
    if ($('searchVisibility').value === 'NASCOSTI') {
      $('searchBtn').textContent = 'MOSTRA ARCHIVIO';
    } else {
      $('searchBtn').textContent = 'AGGIORNA ELENCO';
    }
    loadList(1);
  });
  $('pageSizeSelect').addEventListener('change', () => {
    state.pageSize = Number($('pageSizeSelect').value || 5);
    writeStorage(STORAGE.pageSize, String(state.pageSize));
    loadList(1);
  });
  $('numIscrSito').addEventListener('input', () => {
    $('numIscrSito').dataset.edited = '1';
    writeStorage(STORAGE.numIscrSito, $('numIscrSito').value.trim());
  });
  $('identificativoSoggetto').addEventListener('input', () => {
    $('identificativoSoggetto').dataset.edited = '1';
    writeStorage(STORAGE.identificativoSoggetto, $('identificativoSoggetto').value.trim());
  });

  init();
</script>
</body>
</html>
"""

@app.get("/api/ui/hidden-firs")
async def get_hidden_firs() -> Dict[str, Any]:
    """Restituisce l'archivio locale: non legge né modifica dati su RENTRI."""
    return {"items": _read_hidden_firs()}


@app.put("/api/ui/hidden-firs")
async def put_hidden_firs(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Salva l'archivio locale dei FIR nascosti in modo atomico."""
    raw_items = payload.get("items", [])
    if not isinstance(raw_items, list):
        raise HTTPException(status_code=400, detail="Formato archivio non valido: l'elenco deve essere una lista.")
    if len(raw_items) > 5000:
        raise HTTPException(status_code=400, detail="L'archivio contiene troppi elementi.")

    sanitized: List[Dict[str, Any]] = []
    seen = set()
    allowed_text_fields = (
        "produttore_display", "trasportatore_display", "destinatario_display",
        "codice_eer", "quantita_display", "stato", "nascosto_il"
    )
    for raw_item in raw_items:
        if not isinstance(raw_item, dict):
            continue
        numero = str(raw_item.get("numero_fir", "") or "").strip()
        if not numero or numero in seen:
            continue
        seen.add(numero)
        entry: Dict[str, Any] = {"numero_fir": numero[:100]}
        for field in allowed_text_fields:
            value = raw_item.get(field, "")
            entry[field] = str(value or "")[:500]
        sanitized.append(entry)

    _write_hidden_firs(sanitized)
    return {"ok": True, "count": len(sanitized), "items": sanitized}


@app.get("/", response_class=HTMLResponse)
async def home() -> str:
    return HTML_UI


if __name__ == "__main__":
    import threading
    import uvicorn
    from qr_hub import tablet_app

    tablet_config = uvicorn.Config(tablet_app, host="0.0.0.0", port=8766, reload=False, access_log=False, log_level="warning")
    tablet_server = uvicorn.Server(tablet_config)
    threading.Thread(target=lambda: asyncio.run(tablet_server.serve()), name="RENTRI-QR-TABLET", daemon=True).start()
    uvicorn.run("app:app", host="127.0.0.1", port=8765, reload=False)
