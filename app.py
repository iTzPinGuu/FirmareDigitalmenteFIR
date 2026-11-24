from __future__ import annotations

import os
import asyncio
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent

try:
    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / ".env", override=False)
except Exception:
    pass

from rentri_client import RentriApiError, RentriClient
from usb_signer import UsbSignerError, list_windows_signing_certificates, sign_digest_with_windows_certificate

app = FastAPI(title="RENTRI — Gestione FIR digitali")

# Numero unità locale confermato dall'utente. La .env, se valorizzata, prevale.
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
  <title>RENTRI · Firma FIR</title>
  <style>
    :root{
      color-scheme: light;
      --bg:#f5f7f6;
      --panel:#ffffff;
      --panel2:#f8fbf8;
      --line:#d6e2d9;
      --text:#1c2a1f;
      --muted:#5f6f63;
      --accent:#388E3C;
      --accent2:#2E7D32;
      --ok:#2e7d32;
      --warn:#c48d38;
      --danger:#bf4d56;
      --soft:#eef6ef;
    }
    *{box-sizing:border-box}
    html,body{margin:0; min-height:100%; background:var(--bg); color:var(--text); font:14px/1.45 "Segoe UI",Arial,sans-serif}
    header{
      position:sticky; top:0; z-index:20;
      display:flex; align-items:center; justify-content:space-between; gap:14px;
      padding:14px 18px; background:rgba(255,255,255,.94); border-bottom:1px solid var(--line);
      backdrop-filter: blur(10px);
    }
    header .title{font-size:18px; font-weight:800; letter-spacing:.2px; color:#1f3c22}
    header .subtitle{color:var(--muted); font-size:12px; margin-top:3px}
    .badge{padding:7px 11px; border-radius:999px; border:1px solid #bdd5c1; background:#ecf5ed; color:#225327; font-size:12px; white-space:nowrap}
    main{max-width:1600px; margin:0 auto; padding:18px}
    .grid{display:grid; grid-template-columns:minmax(0, 1.68fr) minmax(360px, .92fr); gap:22px; align-items:start}
    .stack{display:flex; flex-direction:column; gap:16px; min-width:0}
    .right-panel{position:sticky; top:86px; align-self:start}
    .detail-grid{display:grid; grid-template-columns:repeat(4, minmax(0,1fr)); gap:12px}
    .detail-grid .box{background:var(--soft); border:1px solid #d9e9db; border-radius:14px; padding:12px}
    .detail-grid .value{font-size:15px; font-weight:750; margin-top:4px; color:#234026; word-break:break-word}
    @media (max-width: 1300px){ .right-panel{position:static} }
    @media (max-width: 1150px){ .grid{grid-template-columns:1fr} }
    @media (max-width: 900px){ .summary,.detail-grid{grid-template-columns:repeat(2, minmax(0,1fr))} }
    @media (max-width: 640px){ .summary,.detail-grid{grid-template-columns:1fr} }
    .card{
      background:linear-gradient(180deg, rgba(255,255,255,.98), rgba(248,251,248,.98));
      border:1px solid var(--line); border-radius:16px; padding:16px;
      box-shadow:0 10px 28px rgba(35,58,40,.08);
    }
    h2{margin:0 0 10px; font-size:18px}
    h3{margin:0 0 8px; font-size:15px}
    p{margin:8px 0}
    .muted{color:var(--muted)}
    .tiny{font-size:12px}
    .row{display:flex; gap:10px; flex-wrap:wrap; align-items:center}
    .field{display:grid; gap:7px; margin-bottom:10px}
    .field label{font-weight:650; font-size:13px}
    input,select,textarea{
      width:100%; min-width:0;
      background:var(--panel2); color:var(--text);
      border:1px solid #cfdccf; border-radius:11px; padding:10px 11px; font:inherit;
    }
    input:focus,select:focus,textarea:focus{outline:2px solid rgba(56,142,60,.35); outline-offset:2px; border-color:var(--accent)}
    button{
      border:1px solid transparent; border-radius:11px; background:var(--accent2); color:white;
      font-weight:750; padding:10px 14px; cursor:pointer; font-size:13px;
    }
    button:hover{background:var(--accent); color:white}
    button:disabled{opacity:.45; cursor:not-allowed}
    button.secondary{background:#edf5ee; border-color:#c4dac7; color:#234726}
    button.secondary:hover{background:#ddefdf; color:#17331a}
    button.primary{
      background:linear-gradient(180deg, #4caf50, #388e3c); color:white;
      font-size:15px; padding:12px 16px; box-shadow:0 10px 22px rgba(56,142,60,.18)
    }
    button.primary:hover{background:linear-gradient(180deg, #5cc860, #43a047); color:white}
    button.danger{background:#c64e57; border-color:#b53f49}
    button.danger:hover{background:#d66169; color:white}
    .toolbar{display:flex; gap:10px; flex-wrap:wrap; align-items:center}
    .toolbar > *{flex:1 1 140px}
    .table-wrap{overflow:auto; border:1px solid var(--line); border-radius:12px; margin-top:10px}
    table{width:100%; border-collapse:collapse; min-width:980px; font-size:12.5px}
    th,td{padding:10px 9px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top}
    th{position:sticky; top:0; background:#edf5ee; color:#355339; font-weight:700}
    tbody tr{cursor:pointer}
    tbody tr:hover{background:#f1f7f2}
    tbody tr.selected{background:#e1f0e2; box-shadow:inset 3px 0 var(--accent)}
    .pager{display:flex; justify-content:space-between; align-items:center; gap:10px; margin-top:10px; flex-wrap:wrap}
    .banner{
      border-radius:14px; padding:12px 14px; border:1px solid var(--line);
      background:#f5faf5; color:var(--text)
    }
    .banner.ok{border-color:#b7dbbc; background:#ebf8ec}
    .banner.err{border-color:#efc3c8; background:#fff2f3}
    .banner.warn{border-color:#eed7b0; background:#fff8ea}
    .summary{
      display:grid; grid-template-columns:repeat(3, minmax(0,1fr)); gap:12px
    }
    .summary .box{
      background:var(--soft); border:1px solid #d9e9db; border-radius:14px; padding:12px
    }
    .summary .value{font-size:16px; font-weight:750; margin-top:4px; color:#234026}
    .pill{display:inline-flex; align-items:center; gap:6px; padding:5px 10px; border-radius:999px; background:#e8f5e9; border:1px solid #c4e1c7; color:#2c5e30; font-size:11px; font-weight:800; letter-spacing:.04em; text-transform:uppercase; white-space:nowrap}
    .pill.ok{background:#e2f3e3; border-color:#a9d8af; color:#2e7d32}
    .pill.warn{background:#fff3d6; border-color:#ebd09a; color:#8d632e}
    .pill.err{background:#fdebee; border-color:#efb9c0; color:#94434b}
    .spaced{margin-top:12px}
    .hidden{display:none !important}
    details.debug{border:1px solid var(--line); border-radius:14px; background:#fbfdfb; padding:10px 12px}
    details.debug summary{cursor:pointer; font-weight:700}
    details.debug pre{
      white-space:pre-wrap; word-break:break-word; margin:10px 0 0;
      max-height:320px; overflow:auto; background:#f6faf6; border:1px solid #dbe8dd;
      padding:12px; border-radius:10px; color:#314234; font-size:12px;
    }
    .small-note{font-size:12px; color:var(--muted); margin-top:6px}
    .checkbox{display:flex; gap:8px; align-items:center; margin-top:4px}
    .checkbox input{width:auto}
    .certline{font-size:13px; color:#355339}
    .right-panel{position:static; border-left:1px solid rgba(214,226,217,.65); padding-left:8px}
    @media (max-width: 1100px){ .grid{grid-template-columns:1fr} .summary{grid-template-columns:1fr} .right-panel{position:static; border-left:none; padding-left:0} }
  
    .detail-pre{white-space:pre-wrap; margin:0; font:inherit; color:inherit; line-height:1.45;}
</style>
</head>
<body>
<header>
  <div>
    <div class="title">Truccolo Angelo · FIR RENTRI</div>
    <div class="subtitle" id="subtitle">Versione DEMO · firma USB</div>
  </div>
  <span class="badge" id="envBadge">DEMO</span>
</header>

<main class="grid">
  <section class="stack">
    <div class="card">
      <div class="row" style="justify-content:space-between; align-items:flex-start">
        <div>
          <h2>Trova il FIR</h2>
          <p class="muted tiny">Cerca un formulario e aprilo per vedere se è già pronto per l'accettazione oppure per la firma con chiavetta.</p>
        </div>
        <span class="pill" id="sitePill">Configurazione attiva</span>
      </div>

      <div class="toolbar spaced">
        <input id="searchNumeroFir" placeholder="Numero FIR" />
        <input id="searchEer" placeholder="Codice EER" maxlength="8" />
      </div>
      <div class="toolbar">
        <select id="searchVista">
          <option value="TUTTI">Tutti i FIR</option>
          <option value="ACCETTAZIONE">Solo da accettare</option>
          <option value="FIRMA">In firma</option>
          <option value="ACCETTATI">Già accettati</option>
          <option value="PARZIALI">Accettati parzialmente</option>
        </select>
        <select id="pageSizeSelect" aria-label="Righe per pagina">
          <option value="5">5 righe</option>
          <option value="10">10 righe</option>
          <option value="20">20 righe</option>
          <option value="50">50 righe</option>
          <option value="100">100 righe</option>
        </select>
        <button id="searchBtn" class="primary" onclick="loadList(1)">Cerca</button>
      </div>

      <details class="debug spaced">
        <summary>Impostazioni tecniche</summary>
        <div class="small-note">Qui trovi i parametri usati dal gestionale. Non servono per l'uso quotidiano.</div>
        <div class="toolbar spaced">
          <input id="numIscrSito" placeholder="NumIscrSito" />
          <input id="identificativoSoggetto" placeholder="Identificativo soggetto" />
        </div>
        <div class="small-note">Se lasci vuoti questi campi, il programma usa i valori della configurazione salvata.</div>
      </details>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Numero FIR</th>
              <th>Produttore</th>
              <th>Trasportatore</th>
              <th>Destinatario</th>
              <th>EER</th>
              <th>Quantità</th>
              <th>Stato</th>
            </tr>
          </thead>
          <tbody id="tbody">
            <tr><td colspan="7" class="muted">Caricamento…</td></tr>
          </tbody>
        </table>
      </div>

      <div class="pager">
        <button class="secondary" id="prevBtn" onclick="changePage(-1)" disabled>← Precedente</button>
        <span class="tiny muted" id="pagingInfo">Pagina 1</span>
        <button class="secondary" id="nextBtn" onclick="changePage(1)" disabled>Successiva →</button>
      </div>
    </div>

    <div class="card">
      <h2>Dettaglio FIR</h2>
      <div class="banner" id="detailBanner">Seleziona un FIR dall'elenco.</div>
      <div class="summary spaced">
        <div class="box">
          <div class="tiny muted">Numero FIR</div>
          <div class="value" id="detailNum">—</div>
        </div>
        <div class="box">
          <div class="tiny muted">Stato</div>
          <div class="value" id="detailStatus">—</div>
        </div>
        <div class="box">
          <div class="tiny muted">Produttore</div>
          <div class="value" id="detailProd">—</div>
        </div>
        <div class="box">
          <div class="tiny muted">Trasportatore</div>
          <div class="value" id="detailTransport">—</div>
        </div>
        <div class="box">
          <div class="tiny muted">Destinatario</div>
          <div class="value" id="detailDest">—</div>
        </div>
        <div class="box">
          <div class="tiny muted">Quantità presunta</div>
          <div class="value" id="detailQty">—</div>
        </div>
        <div class="box">
          <div class="tiny muted">EER</div>
          <div class="value" id="detailEer">—</div>
        </div>
      </div>

      <div class="detail-grid spaced">
        <div class="box">
          <div class="tiny muted">Data emissione</div>
          <div class="value" id="detailEmissione">—</div>
        </div>
        <div class="box">
          <div class="tiny muted">Data creazione</div>
          <div class="value" id="detailCreazione">—</div>
        </div>
        <div class="box">
          <div class="tiny muted">Inizio trasporto</div>
          <div class="value" id="detailTrasportoInizio">—</div>
        </div>
        <div class="box">
          <div class="tiny muted">Accettazione</div>
          <div class="value" id="detailAccettazione">—</div>
        </div>

        <div class="box">
          <div class="tiny muted">Targa motrice</div>
          <div class="value" id="detailTargaMotrice">—</div>
        </div>
        <div class="box">
          <div class="tiny muted">Targa rimorchio</div>
          <div class="value" id="detailTargaRimorchio">—</div>
        </div>
        <div class="box">
          <div class="tiny muted">Intermediario</div>
          <div class="value" id="detailIntermediario">—</div>
        </div>
        <div class="box">
          <div class="tiny muted">Attività / operazione</div>
          <div class="value" id="detailAttivita">—</div>
        </div>

        <div class="box">
          <div class="tiny muted">Visibilità acquisita</div>
          <div class="value" id="detailVisibilita">—</div>
        </div>
        <div class="box">
          <div class="tiny muted">Trasformato in cartaceo</div>
          <div class="value" id="detailCartaceo">—</div>
        </div>
        <div class="box">
          <div class="tiny muted">Versione</div>
          <div class="value" id="detailVersione">—</div>
        </div>
        <div class="box">
          <div class="tiny muted">Blocco</div>
          <div class="value" id="detailBlocco">—</div>
        </div>
      </div>

      <div class="detail-grid spaced">
        <div class="box">
          <div class="tiny muted">Produttore</div>
          <div class="value" id="detailProdFull">—</div>
        </div>
        <div class="box">
          <div class="tiny muted">Trasportatori</div>
          <div class="value" id="detailTransportersFull">—</div>
        </div>
        <div class="box">
          <div class="tiny muted">Destinatari</div>
          <div class="value" id="detailRecipientsFull">—</div>
        </div>
        <div class="box">
          <div class="tiny muted">Intermediari</div>
          <div class="value" id="detailIntermediariesFull">—</div>
        </div>
      </div>

      <div class="box spaced" style="grid-column:1/-1">
          <div class="tiny muted">Scheda formulario</div>
          <pre class="detail-pre" id="detailNarrative">Seleziona un FIR dall'elenco.</pre>
        </div>

      <div class="row spaced">
        <button class="secondary" id="reloadDetailBtn" onclick="reloadDetail()" disabled>Aggiorna dettaglio</button>
      </div>
    </div>

    <div class="card hidden" id="acceptanceCard">
      <div class="row" style="justify-content:space-between; align-items:flex-start">
        <div>
          <h2>Accettazione FIR</h2>
          <p class="muted tiny">Inserisci quantità accettata e orario. Il peso presunto viene proposto come valore di partenza.</p>
        </div>
        <span class="pill">Solo se richiesta</span>
      </div>

      <div class="banner spaced" id="acceptanceStateHint">La sezione compare solo quando il FIR è in attesa di accettazione.</div>

      <div class="toolbar spaced">
        <select id="acceptanceType">
          <option value="A">Accettato integralmente</option>
          <option value="P">Accettato parzialmente</option>
          <option value="R">Respinto totalmente</option>
        </select>
        <input id="acceptedQuantity" type="number" min="0" step="0.001" placeholder="Peso presunto" />
      </div>
      <div class="toolbar">
        <input id="arrivalDateTime" type="datetime-local" />
        <button class="primary" id="acceptanceBtn" onclick="sendAcceptance()">Conferma accettazione</button>
      </div>
    </div>

  </section>

  <section class="stack right-panel">
    <div class="card">
      <div class="row" style="justify-content:space-between; align-items:flex-start">
        <div>
          <h2>Firma FIR</h2>
          <p class="muted tiny">Seleziona la chiavetta e premi Firma FIR. Il programma usa il ruolo corretto del formulario in modo automatico.</p>
        </div>
        <span class="pill" id="modePill">DEMO</span>
      </div>

      <div class="field">
        <label for="usbCertSelect">Chiavetta / certificato</label>
        <div class="row">
          <button class="secondary" id="scanUsbCertsBtn" onclick="loadUsbCertificates()" type="button">Rileva chiavetta</button>
          <select id="usbCertSelect" style="min-width:220px" aria-label="Certificato di firma su chiavetta">
            <option value="">Prima rileva la chiavetta collegata</option>
          </select>
        </div>
        <div id="usbMemoryNote" class="small-note">Ultima chiavetta usata: nessuna.</div>
        <div id="usbCertSummary" class="banner hidden"></div>
        <div class="small-note" id="roleHint">La firma si adatta automaticamente al ruolo previsto dal FIR.</div>
      </div>

      <div class="row">
        <button class="primary" id="usbSignBtn" onclick="signWithUsb()" disabled>Firma FIR</button>
        <button class="secondary" id="rollbackBtn" onclick="rollbackSignature()" disabled>Annulla ultima firma</button>
      </div>

      <div id="signBanner" class="banner hidden spaced"></div>
    </div>

    <div class="card">
      <h2>Debug tecnico</h2>
      <p class="muted tiny">Area riservata ai dettagli tecnici, ai JSON completi e agli errori del servizio. Qui trovi tutto ciò che serve solo in caso di problema.</p>
      <details class="debug" open>
        <summary>Apri / chiudi log tecnico</summary>
        <pre id="debugLog">Nessun dato tecnico ancora registrato.</pre>
      </details>
    </div>
  </section>
</main>

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
    selectedSuggestedQuantity: '',
  };

  const STORAGE = {
    usbThumbprint: 'rentri_usb_thumbprint',
    usbSubject: 'rentri_usb_subject',
    numIscrSito: 'rentri_num_iscr_sito',
    identificativoSoggetto: 'rentri_identificativo_soggetto',
    pageSize: 'rentri_page_size',
  };

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

  function canShowAcceptance(raw) {
    const s = String(raw || '').trim();
    return ['InserimentoAccettazione', 'FirmaAccettazione', 'FirmaAccettazioneSuccessiva'].includes(s);
  }

  function setBanner(el, text, kind='') {
    el.className = 'banner' + (kind ? ` ${kind}` : '');
    el.textContent = text;
    el.classList.remove('hidden');
  }

  function hideBanner(el) {
    el.className = 'banner hidden';
    el.textContent = '';
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

  function setDatetimeLocalValue(el, date = new Date()) {
    if (!el) return;
    const pad = (n) => String(n).padStart(2, '0');
    const local = new Date(date);
    const value = `${local.getFullYear()}-${pad(local.getMonth() + 1)}-${pad(local.getDate())}T${pad(local.getHours())}:${pad(local.getMinutes())}`;
    el.value = value;
  }

  function syncAcceptanceSection() {
    const visible = canShowAcceptance(state.selectedStatusRaw);
    state.acceptanceVisible = visible;
    const card = $('acceptanceCard');
    const quantityInput = $('acceptedQuantity');
    if (!card) return;
    card.classList.toggle('hidden', !visible);
    if (visible) {
      if (!$('arrivalDateTime').value) {
        setDatetimeLocalValue($('arrivalDateTime'));
      }
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
      $('acceptanceStateHint').textContent = 'Questo FIR è in attesa di accettazione. Inserisci quantità e orario, poi invia.';
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
      case 'FIRMA': return 'FirmaAccettazione';
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

  function renderSelectedDetail(detail) {
    const norm = normalizeDetail(detail);
    const statusLabel = friendlyStatus(norm.status);
    const hasAcceptanceData = norm.acceptance && Object.keys(norm.acceptance).length > 0;

    $('detailNum').textContent = state.selectedNum || norm.raw?.numero_fir || norm.dati_partenza?.numero_fir || '—';
    $('detailStatus').textContent = statusLabel;
    $('detailProd').textContent = norm.producer || '—';
    $('detailTransport').textContent = norm.transport || '—';
    $('detailDest').textContent = norm.recipient || '—';
    $('detailQty').textContent = norm.quantity === '' || norm.quantity === null || norm.quantity === undefined ? '—' : String(norm.quantity);
    $('detailEer').textContent = norm.eer || '—';
    $('detailEmissione').textContent = fmtDate(norm.dataEmissione);
    $('detailCreazione').textContent = fmtDate(norm.dataCreazione);
    $('detailTrasportoInizio').textContent = fmtDate(norm.trasportoInizio);
    $('detailAccettazione').textContent = hasAcceptanceData
      ? `${norm.acceptanceType || '—'} · ${norm.acceptanceQty || '—'} · ${fmtDate(norm.acceptanceArrival)}`
      : (norm.status === 'InserimentoAccettazione' ? 'Da inserire' : '—');
    $('detailTargaMotrice').textContent = fmtValue(norm.targaMotrice);
    $('detailTargaRimorchio').textContent = fmtValue(norm.targaRimorchio);
    $('detailIntermediario').textContent = fmtValue(norm.intermediario);
    $('detailAttivita').textContent = fmtValue(norm.attivita);
    $('detailVisibilita').textContent = fmtBool(norm.visibilita);
    $('detailCartaceo').textContent = fmtBool(norm.trasformatoCartaceo);
    $('detailVersione').textContent = fmtValue(norm.versione);
    $('detailBlocco').textContent = fmtValue(norm.codiceBlocco);
    $('detailProdFull').textContent = norm.producer || '—';
    $('detailTransportersFull').textContent = norm.transporters || '—';
    $('detailRecipientsFull').textContent = norm.recipients || '—';
    $('detailIntermediariesFull').textContent = norm.intermediaries || '—';

    const partiesText = [
      `Produttore: ${norm.producer || '—'}`,
      `Trasportatore: ${norm.transport || '—'}`,
      `Destinatario: ${norm.recipient || '—'}`,
      `Intermediario: ${norm.intermediario || '—'}`,
      `Rifiuto: ${norm.eer || '—'}${norm.quantity !== '' && norm.quantity !== null && norm.quantity !== undefined ? ` · ${norm.quantity}` : ''}`,
      `Trasporto inizio: ${fmtDate(norm.trasportoInizio)}`,
      `Targa motrice: ${fmtValue(norm.targaMotrice)}`,
      `Targa rimorchio: ${fmtValue(norm.targaRimorchio)}`,
      `Accettazione: ${hasAcceptanceData ? `${norm.acceptanceType || '—'} · ${norm.acceptanceQty || '—'} · ${fmtDate(norm.acceptanceArrival)}` : '—'}`,
      `Stato: ${statusLabel}`,
    ].join(' • ');

    const textArea = $('detailNarrative');
    if (textArea) {
      textArea.textContent = [
        `Numero FIR: ${state.selectedNum || norm.raw?.numero_fir || '—'}`,
        `Stato: ${statusLabel}`,
        `Produttore: ${norm.producer || '—'}`,
        `Trasportatore: ${norm.transport || '—'}`,
        `Destinatario: ${norm.recipient || '—'}`,
        `Intermediario: ${norm.intermediario || '—'}`,
        `Codice EER: ${norm.eer || '—'}`,
        `Quantità: ${norm.quantity === '' || norm.quantity === null || norm.quantity === undefined ? '—' : norm.quantity}`,
        `Data emissione: ${fmtDate(norm.dataEmissione)}`,
        `Data creazione: ${fmtDate(norm.dataCreazione)}`,
        `Inizio trasporto: ${fmtDate(norm.trasportoInizio)}`,
        `Targa motrice: ${fmtValue(norm.targaMotrice)}`,
        `Targa rimorchio: ${fmtValue(norm.targaRimorchio)}`,
        `Accettazione: ${hasAcceptanceData ? `${norm.acceptanceType || '—'} · ${norm.acceptanceQty || '—'} · ${fmtDate(norm.acceptanceArrival)}` : '—'}`,
      ].join('\n');
    }

    $('detailBanner').textContent = state.selectedNum
      ? `FIR selezionato: ${state.selectedNum} · Stato: ${statusLabel}`
      : "Seleziona un FIR dall'elenco.";
    state.selectedStatusRaw = String(norm.status || '');
    state.selectedStatusLabel = statusLabel;
    state.selectedDetail = norm.raw;
    state.selectedSuggestedQuantity = norm.quantity;
    const roleHint = $('roleHint');
    if (roleHint) {
      roleHint.textContent = state.selectedNum
        ? 'La firma si adatta automaticamente al ruolo previsto dal FIR.'
        : 'Seleziona un FIR per firmare.';
    }
    const acceptanceBanner = $('acceptanceStateHint');
    if (acceptanceBanner && canShowAcceptance(norm.status)) {
      acceptanceBanner.textContent = `Accettazione disponibile per questo FIR. Peso presunto proposto: ${norm.quantity !== '' && norm.quantity !== null && norm.quantity !== undefined ? norm.quantity : 'n/d'}.`;
    }
    syncAcceptanceSection();
    updateActionButtons();
  }


  function showFriendlyMainMessage(text, kind='') {
    setBanner($('signBanner'), text, kind);
  }

  function clearFriendlyMainMessage() {
    hideBanner($('signBanner'));
  }

  function friendlyErrorMessage(err) {
    const raw = err?.raw;
    const title = err?.message || 'Operazione non riuscita';
    const serverText = JSON.stringify(raw?.detail || {}).toLowerCase();
    if (serverText.includes('chiavetta') || serverText.includes('certificato') || serverText.includes('loadinfo is not defined')) {
      return 'Chiavetta non inserita o certificato non disponibile.';
    }
    if (serverText.includes('non risulta firmato') || serverText.includes('not signed')) {
      return 'Non è possibile annullare: il FIR non risulta firmato oppure la firma è già stata annullata.';
    }
    if (raw?.detail?.problem_details?.response?.model_state) {
      return `${title}. Apri Debug tecnico per vedere i campi rifiutati.`;
    }
    return title;
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
      if ($('envBadge')) $('envBadge').textContent = env;
      if ($('modePill')) $('modePill').textContent = env;
      if ($('subtitle')) {
        const parts = ['Versione DEMO', 'firma USB'];
        if (info.num_iscr_sito) parts.push(info.num_iscr_sito);
        $('subtitle').textContent = parts.join(' · ');
      }
      if ($('sitePill')) {
        $('sitePill').textContent = info.num_iscr_sito ? `UL ${info.num_iscr_sito}` : 'Configurazione attiva';
      }
      if (info.init_error) {
        showFriendlyMainMessage('Attenzione: una parte della configurazione iniziale non è pronta. Apri Debug tecnico per i dettagli.', 'warn');
      }
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
    $('rollbackBtn').disabled = !state.selectedNum;
    $('usbSignBtn').disabled = !(state.selectedNum && state.usbSelected && state.usbSelected.suitable_for_signature && !state.usbSigningInProgress);
    const acceptanceBtn = $('acceptanceBtn');
    if (acceptanceBtn) {
      acceptanceBtn.disabled = !(state.selectedNum && state.acceptanceVisible);
    }
  }

  function updatePageControls(rowsCount, paging) {
    const pageSize = Number($('pageSizeSelect')?.value || state.pageSize || 5);
    const hasPrev = Number(state.currentPage) > 1;
    const hasNext = rowsCount >= pageSize;
    $('prevBtn').disabled = !hasPrev;
    $('nextBtn').disabled = !hasNext;
    $('pagingInfo').textContent = `Pagina ${state.currentPage} · ${rowsCount} risultati · ${pageSize} per pagina`;
  }

  async function loadList(page = 1) {
    $('searchBtn').disabled = true;
    try {
      saveConfigInputs();
      const pageSize = Number($('pageSizeSelect').value || state.pageSize || 5);
      state.pageSize = pageSize;
      const params = new URLSearchParams({
        filtro_tipo: 'sito',
        stato: searchStateToBackend($('searchVista').value) || 'TUTTI',
        page: String(page),
        page_size: String(pageSize)
      });
      const site = $('numIscrSito').value.trim();
      const subject = $('identificativoSoggetto').value.trim();
      const number = $('searchNumeroFir').value.trim();
      const eer = $('searchEer').value.trim();
      if (site) params.set('num_iscr_sito', site);
      if (subject) params.set('identificativo_soggetto', subject);
      if (number) params.set('numero_fir', number);
      if (eer) params.set('codice_eer', eer);

      const result = await requestJson('/api/formulari?' + params.toString());
      const rows = Array.isArray(result.data) ? result.data : [];
      state.currentPage = page;
      state.rows = rows.map(item => unwrapRecord(item) || {});
      const tbody = $('tbody');
      if (!state.rows.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="muted">Nessun formulario trovato.</td></tr>';
      } else {
        tbody.innerHTML = state.rows.map((item, index) => {
          const producer = extractParty(item, ['produttore', 'produttore_denominazione', 'denominazione_produttore', 'ragione_sociale_produttore']) || '-';
          const transport = extractPartyList(item, ['trasportatore', 'trasportatore_denominazione', 'denominazione_trasportatore', 'ragione_sociale_trasportatore', 'trasportatori']) || '-';
          const recipient = extractPartyList(item, ['destinatario', 'destinatario_denominazione', 'denominazione_destinatario', 'ragione_sociale_destinatario', 'destinatari']) || '-';
          const qty = formatQuantity(item.quantita, item.unita_misura) || '-';
          const status = friendlyStatus(item.stato || item.status || item.state);
          return `<tr data-index="${index}" class="${item.numero_fir === state.selectedNum ? 'selected' : ''}">
            <td><b>${esc(item.numero_fir || '-')}</b></td>
            <td>${esc(producer)}</td>
            <td>${esc(transport)}</td>
            <td>${esc(recipient)}</td>
            <td>${esc(item.codice_eer || '-')}</td>
            <td>${esc(qty)}</td>
            <td>${esc(status)}</td>
          </tr>`;
        }).join('');
        tbody.querySelectorAll('tr[data-index]').forEach(row => {
          row.addEventListener('click', () => selectFir(state.rows[Number(row.dataset.index)].numero_fir));
        });
      }
      updatePageControls(rows.length, result.paging || {});
      debugAppend('Lista FIR caricata', {page, count: rows.length});
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
    state.selectedNum = numero;
    state.selectedRow = state.rows.find(r => r.numero_fir === numero) || null;
    clearUsbHashCache();
    Array.from($('tbody').querySelectorAll('tr[data-index]')).forEach(row => {
      row.classList.toggle('selected', state.rows[Number(row.dataset.index)]?.numero_fir === numero);
    });
    $('reloadDetailBtn').disabled = false;
    clearFriendlyMainMessage();
    await reloadDetail();
    syncAcceptanceSection();
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
    const quantity = Number($('acceptedQuantity').value);
    const arrival = $('arrivalDateTime').value ? new Date($('arrivalDateTime').value) : null;
    if (!arrival || Number.isNaN(arrival.getTime())) {
      showFriendlyMainMessage('Inserisci una data e un’ora di arrivo valide.', 'warn');
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
    const summary = `FIR ${state.selectedNum}\nEsito: ${labels[tipo]}\nQuantità accettata: ${quantity}\nArrivo: ${$('arrivalDateTime').value}${weightHint ? `\n${weightHint}` : ''}`;
    if (!confirm(`Confermi l'accettazione del formulario?\n\n${summary}`)) return;
    try {
      const result = await requestJson(`/api/formulari/${encodeURIComponent(state.selectedNum)}/accettazione`, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({
          tipo_accettazione: tipo,
          quantita_accettata: quantity,
          data_ora_arrivo: $('arrivalDateTime').value,
        })
      });
      showFriendlyMainMessage('Accettazione completata con successo.', 'ok');
      debugAppend('Accettazione inviata', result);
      await reloadDetail();
      await loadList(state.currentPage || 1);
    } catch (err) {
      showFriendlyMainMessage(friendlyErrorMessage(err), 'err');
      debugAppend('Errore invio accettazione', err.raw || err.message);
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
      btn.textContent = 'Rileva chiavetta';
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
      showFriendlyMainMessage('Firma apposta con successo.', 'ok');
      await reloadDetail();
      await loadList(state.currentPage || 1);
    } catch (err) {
      showFriendlyMainMessage(friendlyErrorMessage(err), 'err');
      debugAppend('Errore firma USB', err.raw || err.message);
    } finally {
      state.usbSigningInProgress = false;
      $('usbSignBtn').textContent = 'Firma FIR';
      updateActionButtons();
    }
  }

  async function rollbackSignature() {
    if (!state.selectedNum) return;
    if (!confirm(`Annullare l'ultima firma del FIR ${state.selectedNum}?`)) return;
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
      await loadList(1);
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

  $('usbCertSelect').addEventListener('change', selectUsbCertificate);
  const acceptedQuantityInput = $('acceptedQuantity');
  if (acceptedQuantityInput) {
    acceptedQuantityInput.addEventListener('input', () => {
      acceptedQuantityInput.dataset.manual = '1';
    });
  }
  const arrivalInput = $('arrivalDateTime');
  if (arrivalInput) {
    arrivalInput.addEventListener('input', () => {
      arrivalInput.dataset.manual = '1';
    });
  }
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


@app.get("/", response_class=HTMLResponse)
async def home() -> str:
    return HTML_UI


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=8765, reload=False)
