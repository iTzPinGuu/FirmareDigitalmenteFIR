from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

logger = logging.getLogger("rentri_client")


class RentriApiError(Exception):
    """Errore HTTP RENTRI con risposta originale disponibile per la UI."""

    def __init__(
        self,
        status_code: int,
        message: str,
        detail: Any = None,
        retry_after: Optional[int] = None,
    ) -> None:
        super().__init__(f"[{status_code}] {message}")
        self.status_code = status_code
        self.message = message
        self.detail = detail
        self.retry_after = retry_after

    def _generic_codes(self) -> List[str]:
        if not isinstance(self.detail, dict):
            return []
        response = self.detail.get("response", self.detail)
        if not isinstance(response, dict):
            return []
        model_state = response.get("model_state")
        if not isinstance(model_state, dict):
            return []
        generic = model_state.get("generic")
        if not isinstance(generic, list):
            return []
        return [str(x) for x in generic if x is not None]

    def is_invalid_audience(self) -> bool:
        return "agIDInterop.invalidAudience" in self._generic_codes()

    def is_issuer_banned(self) -> bool:
        return "sys.issuerIsBanned" in self._generic_codes()

    def is_maintenance(self) -> bool:
        return "sys.maintenance" in self._generic_codes()


class RentriClient:
    """Client per API RENTRI Formulari e CA RENTRI.

    Le richieste sono firmate secondo il profilo AgID configurato per
    l'interoperabilità. Il certificato P12 qui caricato serve all'autenticazione
    delle API: non viene mai assunto automaticamente come certificato di firma xFIR.
    """

    FORMULARI_BASE_PATH = "/formulari/v1.0"
    CA_BASE_PATH = "/ca-rentri/v1.0"

    def __init__(
        self,
        env: str = "demo",
        demo_base_url: str = "https://demoapi.rentri.gov.it",
        prod_base_url: str = "https://api.rentri.gov.it",
        p12_path: str = "",
        p12_password: Optional[str] = None,
        issuer: str = "",
        identificativo: str = "",
        num_iscr_sito: str = "",
        jwt_audience: Optional[str] = None,
        jwt_subject: Optional[str] = None,
        timeout: float = 30.0,
        max_retries_429: int = 2,
    ) -> None:
        self.env = (env or "demo").lower().strip()
        if self.env not in {"demo", "prod"}:
            raise ValueError("RENTRI_ENV deve essere 'demo' oppure 'prod'.")

        self.host_base = (
            prod_base_url.rstrip("/") if self.env == "prod" else demo_base_url.rstrip("/")
        )
        self.service_base_url = f"{self.host_base}{self.FORMULARI_BASE_PATH}"
        self.ca_base_url = f"{self.host_base}{self.CA_BASE_PATH}"

        base_id = (issuer or identificativo or "").strip()
        if not base_id:
            raise ValueError("Identificativo / issuer del soggetto obbligatorio.")

        self.issuer = base_id
        self.subject = (jwt_subject or "").strip()
        self.identificativo = (identificativo or base_id).strip()
        self.num_iscr_sito = (num_iscr_sito or "").strip()

        # Audience RENTRI: rentrigov.demo.api (Demo) / rentrigov.api (Produzione).
        default_aud = "rentrigov.api" if self.env == "prod" else "rentrigov.demo.api"
        raw_aud = jwt_audience if jwt_audience is not None else os.getenv("RENTRI_JWT_AUDIENCE", "")
        self.audience = raw_aud.strip() if raw_aud.strip() else default_aud

        self.timeout = float(timeout)
        self.max_retries_429 = int(max_retries_429)
        self.p12_path = os.path.abspath(p12_path) if p12_path else ""
        self.private_key: Any = None
        self.cert: Optional[x509.Certificate] = None
        self.x5c_chain: List[str] = []
        self.jwt_algorithm: str = "ES256"

        self._load_p12(self.p12_path, p12_password)

    @staticmethod
    def _detect_jwt_algorithm(key: Any) -> str:
        if isinstance(key, ec.EllipticCurvePrivateKey):
            return "ES256"
        if isinstance(key, rsa.RSAPrivateKey):
            return "RS256"
        cls_name = type(key).__name__.lower()
        return "ES256" if ("ec" in cls_name or "elliptic" in cls_name) else "RS256"

    def _load_p12(self, p12_path: str, password: Optional[str]) -> None:
        if not p12_path or not os.path.exists(p12_path):
            raise FileNotFoundError(f"File .p12 non trovato: {p12_path}")

        with open(p12_path, "rb") as file_handle:
            raw = file_handle.read()

        pwd = password.encode("utf-8") if password else None
        priv_key, cert, _additional_certs = pkcs12.load_key_and_certificates(raw, pwd)
        if priv_key is None or cert is None:
            raise ValueError("Il file .p12 non contiene una chiave privata e un certificato validi.")

        self.private_key = priv_key
        self.jwt_algorithm = self._detect_jwt_algorithm(priv_key)
        self.cert = cert
        self.x5c_chain = [
            base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
        ]

    def get_certificate_info(self) -> Dict[str, Any]:
        return {
            "env": self.env.upper(),
            "service_base_url": self.service_base_url,
            "ca_base_url": self.ca_base_url,
            "p12_path": self.p12_path,
            "jwt_iss": self.issuer,
            "jwt_aud": self.audience,
            "jwt_alg": self.jwt_algorithm,
            "subject": self.cert.subject.rfc4514_string() if self.cert else "N/D",
            "issuer_cert": self.cert.issuer.rfc4514_string() if self.cert else "N/D",
            "serial_number": hex(self.cert.serial_number) if self.cert else "N/D",
            "valid_from": self.cert.not_valid_before_utc.isoformat() if self.cert else "N/D",
            "valid_to": self.cert.not_valid_after_utc.isoformat() if self.cert else "N/D",
        }

    def get_runtime_info(self) -> Dict[str, Any]:
        return {
            "env": self.env.upper(),
            "host_base": self.host_base,
            "service_base_url": self.service_base_url,
            "ca_base_url": self.ca_base_url,
            "issuer": self.issuer,
            "identificativo": self.identificativo,
            "num_iscr_sito": self.num_iscr_sito,
            "jwt_audience": self.audience,
            "jwt_algorithm": self.jwt_algorithm,
            "p12_path": self.p12_path,
        }

    def _private_key_pem(self) -> bytes:
        if self.private_key is None:
            raise ValueError("Chiave privata non disponibile.")
        if isinstance(self.private_key, bytes):
            return self.private_key
        if isinstance(self.private_key, str):
            return self.private_key.encode("utf-8")
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def _build_jwt(self, extra_claims: Optional[Dict[str, Any]] = None) -> str:
        now = int(time.time())
        payload: Dict[str, Any] = {
            "jti": str(uuid.uuid4()),
            "aud": self.audience,
            "iss": self.issuer,
            "exp": now + 120,
            "iat": now,
            "nbf": now,
        }
        if self.subject:
            payload["sub"] = self.subject
        if extra_claims:
            payload.update(extra_claims)

        headers = {"alg": self.jwt_algorithm, "typ": "JWT", "x5c": self.x5c_chain}
        return jwt.encode(
            payload,
            self._private_key_pem(),
            algorithm=self.jwt_algorithm,
            headers=headers,
        )

    @staticmethod
    def _sha256_digest_header(body_bytes: bytes) -> str:
        digest = hashlib.sha256(body_bytes).digest()
        return f"SHA-256={base64.b64encode(digest).decode('ascii')}"

    def _build_headers(
        self,
        body_bytes: Optional[bytes] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Accept": "application/json, application/problem+json",
            "Authorization": f"Bearer {self._build_jwt()}",
        }
        if body_bytes is not None:
            content_type = "application/json; charset=utf-8"
            digest_value = self._sha256_digest_header(body_bytes)
            headers["Content-Type"] = content_type
            headers["Digest"] = digest_value
            headers["Agid-JWT-Signature"] = self._build_jwt(
                {
                    "signed_headers": [
                        {"digest": digest_value},
                        {"content-type": content_type},
                    ]
                }
            )
        if extra_headers:
            headers.update(extra_headers)
        return headers

    async def _request(
        self,
        method: str,
        relative_path: str,
        params: Optional[List[Tuple[str, Any]]] = None,
        json_body: Optional[Any] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        base_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        root = (base_url or self.service_base_url).rstrip("/")
        suffix = relative_path if relative_path.startswith("/") or not relative_path else f"/{relative_path}"
        url = f"{root}{suffix}"
        body_bytes = (
            json.dumps(json_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if json_body is not None
            else None
        )

        attempt = 0
        while True:
            headers = self._build_headers(body_bytes=body_bytes, extra_headers=extra_headers)
            try:
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as http_client:
                    response = await http_client.request(
                        method=method.upper(),
                        url=url,
                        params=params,
                        content=body_bytes,
                        headers=headers,
                    )
            except httpx.TimeoutException as exc:
                raise RentriApiError(504, f"Timeout chiamando RENTRI {method.upper()} {url}", str(exc)) from exc
            except httpx.HTTPError as exc:
                raise RentriApiError(502, f"Errore di collegamento a RENTRI {method.upper()} {url}", str(exc)) from exc

            if response.status_code < 400:
                paging_headers = {
                    key: value
                    for key, value in response.headers.items()
                    if key.lower().startswith("paging-")
                }
                if not response.content:
                    data: Any = None
                else:
                    try:
                        data = response.json()
                    except ValueError:
                        data = response.text
                return {
                    "data": data,
                    "paging": paging_headers,
                    "status_code": response.status_code,
                    "headers": {
                        key: value
                        for key, value in response.headers.items()
                        if key.lower() in {"content-type", "location", "retry-after"}
                    },
                }

            retry_after: Optional[int] = None
            retry_raw = response.headers.get("Retry-After")
            if retry_raw and retry_raw.isdigit():
                retry_after = int(retry_raw)

            try:
                error_detail: Any = response.json()
            except ValueError:
                error_detail = response.text or "(nessun corpo risposta)"

            error = RentriApiError(
                status_code=response.status_code,
                message=f"RENTRI {method.upper()} {url} -> HTTP {response.status_code}",
                detail={"url": str(response.url), "method": method.upper(), "response": error_detail},
                retry_after=retry_after,
            )

            if response.status_code in {400, 401, 403, 404, 409, 423, 422, 503}:
                raise error

            if response.status_code == 429 and attempt < self.max_retries_429:
                wait_seconds = retry_after if retry_after is not None and retry_after <= 10 else 2
                attempt += 1
                await asyncio.sleep(wait_seconds)
                continue

            raise error

    async def elenco_formulari(
        self,
        num_iscr_sito: Optional[str] = None,
        identificativo_soggetto: Optional[str] = None,
        solo_senza_visibilita_siti: Optional[bool] = None,
        numero_fir: Optional[str] = None,
        codice_blocco: Optional[str] = None,
        data_creazione_da: Optional[str] = None,
        data_creazione_a: Optional[str] = None,
        data_emissione_da: Optional[str] = None,
        data_emissione_a: Optional[str] = None,
        codice_eer: Optional[str] = None,
        stati: Optional[List[str]] = None,
        trasformato_in_cartaceo: Optional[bool] = None,
        paging_page: int = 1,
        paging_page_size: int = 100,
    ) -> Dict[str, Any]:
        site = (num_iscr_sito if num_iscr_sito is not None else self.num_iscr_sito).strip()
        subject = (identificativo_soggetto or "").strip()

        if site and subject:
            raise ValueError(
                "Specificare solo 'num_iscr_sito' oppure solo 'identificativo_soggetto', mai entrambi."
            )
        if not site and not subject:
            subject = self.identificativo

        if paging_page < 1:
            raise ValueError("Paging-Page deve essere >= 1.")
        if not (1 <= paging_page_size <= 100):
            raise ValueError("Paging-PageSize deve essere compreso tra 1 e 100.")
        if codice_eer and len(codice_eer.strip()) > 8:
            raise ValueError("codice_eer non può superare 8 caratteri.")

        params: List[Tuple[str, Any]] = []
        if site:
            params.append(("num_iscr_sito", site))
        elif subject:
            params.append(("identificativo_soggetto", subject))

        optional_scalar = {
            "solo_senza_visibilita_siti": solo_senza_visibilita_siti,
            "numero_fir": numero_fir.strip() if numero_fir else None,
            "codice_blocco": codice_blocco.strip() if codice_blocco else None,
            "data_creazione_da": data_creazione_da.strip() if data_creazione_da else None,
            "data_creazione_a": data_creazione_a.strip() if data_creazione_a else None,
            "data_emissione_da": data_emissione_da.strip() if data_emissione_da else None,
            "data_emissione_a": data_emissione_a.strip() if data_emissione_a else None,
            "codice_eer": codice_eer.strip() if codice_eer else None,
            "trasformato_in_cartaceo": trasformato_in_cartaceo,
        }
        for key, value in optional_scalar.items():
            if value is not None and value != "":
                params.append((key, value))

        if stati:
            for status in stati:
                if status and status.strip():
                    params.append(("stati", status.strip()))

        headers = {"Paging-Page": str(paging_page), "Paging-PageSize": str(paging_page_size)}
        return await self._request("GET", "", params=params, extra_headers=headers)

    async def dettaglio_fir(self, numero_fir: str) -> Dict[str, Any]:
        number = (numero_fir or "").strip()
        if not number:
            raise ValueError("numero_fir obbligatorio.")
        return await self._request("GET", f"/{quote(number, safe='')}")

    @staticmethod
    def _validate_transaction_id(transazione_id: str) -> str:
        value = (transazione_id or "").strip()
        if not value:
            raise ValueError("transazione_id obbligatorio.")
        try:
            return str(uuid.UUID(value))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("transazione_id non è un GUID valido.") from exc

    async def stato_transazione(self, transazione_id: str) -> Dict[str, Any]:
        """Recupera lo stato di una transazione asincrona RENTRI.

        Endpoint Formulari documentato: GET /{transazione_id}/status.
        """
        transaction_id = self._validate_transaction_id(transazione_id)
        return await self._request("GET", f"/{transaction_id}/status")

    async def esito_transazione(self, transazione_id: str) -> Dict[str, Any]:
        """Recupera il risultato finale di una transazione asincrona RENTRI.

        Endpoint Formulari documentato: GET /{transazione_id}/result.
        """
        transaction_id = self._validate_transaction_id(transazione_id)
        return await self._request("GET", f"/{transaction_id}/result")

    async def invia_accettazione_fir(
        self,
        numero_fir: str,
        tipo_accettazione: str,
        quantita_accettata: float,
        data_ora_arrivo: str,
        reply_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Costruisce e invia il payload di accettazione a partire dai campi UI."""
        number = (numero_fir or "").strip()
        tipo = (tipo_accettazione or "").strip().upper()
        if not number:
            raise ValueError("numero_fir obbligatorio.")
        if tipo not in {"A", "P", "R"}:
            raise ValueError("Tipo accettazione non valido: usare A, P oppure R.")
        try:
            quantity = float(quantita_accettata)
        except (TypeError, ValueError) as exc:
            raise ValueError("quantita_accettata deve essere numerica.") from exc
        if quantity < 0:
            raise ValueError("quantita_accettata non può essere negativa.")
        if tipo == "R" and quantity != 0:
            raise ValueError("Per il respingimento totale la quantità accettata deve essere 0.")
        if tipo in {"A", "P"} and quantity <= 0:
            raise ValueError("La quantità accettata deve essere maggiore di 0.")
        arrival = (data_ora_arrivo or "").strip()
        if not arrival:
            raise ValueError("data_ora_arrivo obbligatoria.")

        # Contratto RENTRI (esempio ufficiale C#):
        # {
        #   "tipoAccettazione": "A",
        #   "quantitaAccettata": { "valore": 800 },
        #   "dataOraArrivo": "2024-06-13T13:52:06.304Z"
        # }
        # La UI e l'API locale continuano a usare snake_case; qui traduciamo
        # i nomi e la struttura nel formato REST richiesto da RENTRI.
        quantity_value: int | float = int(quantity) if quantity.is_integer() else quantity
        payload = {
            "tipoAccettazione": tipo,
            "quantitaAccettata": {
                "valore": quantity_value,
            },
            "dataOraArrivo": arrival,
        }
        headers = {"X-ReplyTo": reply_to.strip()} if reply_to and reply_to.strip() else None
        return await self._request(
            "POST",
            f"/{quote(number, safe='')}/accettazione",
            json_body=payload,
            extra_headers=headers,
        )

    @staticmethod
    def _normalizza_certificato_x509_base64(certificato_base64: str) -> str:
        """Valida e normalizza un certificato X.509 in Base64 DER.

        Accetta file .cer/.der binari, PEM e contenuti DER a loro volta
        codificati in Base64. RENTRI riceve sempre il certificato DER Base64.
        """
        compact = "".join((certificato_base64 or "").split())
        if not compact:
            raise ValueError("Certificato X.509 vuoto.")
        try:
            raw = base64.b64decode(compact, validate=True)
        except Exception as exc:
            raise ValueError("Il certificato non è una codifica Base64 valida.") from exc

        candidates = [raw]
        # Alcuni .cer sono file testuali che contengono il Base64 del DER,
        # invece del DER binario diretto.
        try:
            text_candidate = raw.decode("ascii").strip()
            if text_candidate and not text_candidate.startswith("-----BEGIN"):
                nested = base64.b64decode("".join(text_candidate.split()), validate=True)
                if nested != raw:
                    candidates.append(nested)
        except Exception:
            pass

        certificate = None
        for candidate in candidates:
            try:
                certificate = x509.load_der_x509_certificate(candidate)
                break
            except ValueError:
                try:
                    certificate = x509.load_pem_x509_certificate(candidate)
                    break
                except ValueError:
                    continue

        if certificate is None:
            raise ValueError(
                "Il file selezionato non contiene un certificato X.509 valido. "
                "Seleziona il certificato di firma remota RENTRI (.cer), non il P12 di interoperabilità."
            )

        der = certificate.public_bytes(serialization.Encoding.DER)
        return base64.b64encode(der).decode("ascii")

    async def genera_hash_fir(
        self,
        numero_fir: str,
        certificato_base64: str,
        reply_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Richiede a RENTRI l'hash xFIR usando il certificato X.509 del firmatario.

        Contratto documentato RENTRI (esempio C#):
            {"certificato": "<certificato X.509 codificato Base64>"}

        Il certificato passato qui è quello di firma (nel caso dell'utente,
        il .cer di firma remota RENTRI), NON il certificato P12 di interoperabilità.
        """
        number = (numero_fir or "").strip()
        if not number:
            raise ValueError("numero_fir obbligatorio.")
        if not (certificato_base64 or "").strip():
            raise ValueError("Il certificato X.509 di firma (.cer) è obbligatorio per generare l'hash.")
        certificate = self._normalizza_certificato_x509_base64(certificato_base64)
        payload = {"certificato": certificate}
        headers = {"X-ReplyTo": reply_to.strip()} if reply_to and reply_to.strip() else None
        return await self._request(
            "POST",
            f"/{quote(number, safe='')}/hash",
            json_body=payload,
            extra_headers=headers,
        )

    async def acquisizione_firma_fir(
        self,
        numero_fir: str,
        token: str,
        firma_base64: str,
        certificato_base64: str,
        identificativo_utente: str,
        reply_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        number = (numero_fir or "").strip()
        if not number or not token or not firma_base64 or not certificato_base64 or not identificativo_utente:
            raise ValueError(
                "numero_fir, token, firma_base64, certificato_base64 e identificativo_utente sono obbligatori. "
                "Non viene riutilizzato automaticamente il certificato P12 di interoperabilità."
            )

        certificate = self._normalizza_certificato_x509_base64(certificato_base64)
        body: Dict[str, Any] = {
            "token": token.strip(),
            "firma": firma_base64.strip(),
            "certificato": certificate,
            "identificativo_utente": identificativo_utente.strip(),
        }
        headers = {"X-ReplyTo": reply_to.strip()} if reply_to and reply_to.strip() else None
        return await self._request(
            "POST",
            f"/{quote(number, safe='')}/acquisizione-firma",
            json_body=body,
            extra_headers=headers,
        )

    async def rollback_ultima_firma(
        self,
        numero_fir: str,
        endpoint_suffix: str = "rollback-firma",
        reply_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Richiede il rollback dell'ultima firma propria.

        Endpoint documentato: POST /{numero_fir}/rollback-firma.
        """
        number = (numero_fir or "").strip()
        suffix = (endpoint_suffix or "").strip().strip("/")
        allowed_suffixes = {"rollback-firma", "rollback", "rollback-ultima-firma"}
        if not number:
            raise ValueError("numero_fir obbligatorio.")
        if suffix not in allowed_suffixes:
            raise ValueError(
                "Suffisso rollback non ammesso. Valori consentiti: "
                + ", ".join(sorted(allowed_suffixes))
            )
        headers = {"X-ReplyTo": reply_to.strip()} if reply_to and reply_to.strip() else None
        return await self._request(
            "POST",
            f"/{quote(number, safe='')}/{suffix}",
            json_body=None,
            extra_headers=headers,
        )

    async def ca_elenco_credenziali(
        self,
        identificativo_soggetto: str,
        reply_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Elenca le credenziali CA per l'identificativo del soggetto.

        La API RENTRI richiede identificativo_soggetto come query string anche
        se la chiamata è una GET senza body.
        """
        subject_id = (identificativo_soggetto or "").strip()
        if not subject_id:
            raise ValueError(
                "identificativo_soggetto obbligatorio per GET /credentials/list. "
                "Usa l'identificativo RENTRI del soggetto abilitato."
            )
        headers = {"X-ReplyTo": reply_to.strip()} if reply_to and reply_to.strip() else None
        return await self._request(
            "GET",
            "/credentials/list",
            params=[("identificativo_soggetto", subject_id)],
            extra_headers=headers,
            base_url=self.ca_base_url,
        )

    async def ca_info_credenziali(
        self,
        credentials_id: str,
        auth_info: bool = True,
        cert_info: bool = False,
        certificates: str = "None",
        lang: str = "it-IT",
        reply_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Recupera le informazioni CSC della credenziale, inclusi i metodi auth.

        L'endpoint RENTRI espone credentials_id e i flag auth_info/cert_info
        come query string. Per costruire auth_data in modo conforme è necessario
        richiedere auth_info=true e leggere auth.objects dalla risposta.
        """
        credential = (credentials_id or "").strip()
        if not credential:
            raise ValueError("credentials_id obbligatorio per GET /credentials/info.")
        if certificates not in {"None", "Single", "Chain"}:
            raise ValueError("certificates deve essere None, Single oppure Chain.")
        params: List[Tuple[str, Any]] = [
            ("credentials_id", credential),
            ("auth_info", "true" if auth_info else "false"),
        ]
        if cert_info:
            params.append(("cert_info", "true"))
            params.append(("certificates", certificates))
        if lang:
            params.append(("lang", lang))
        headers = {"X-ReplyTo": reply_to.strip()} if reply_to and reply_to.strip() else None
        return await self._request(
            "GET",
            "/credentials/info",
            params=params,
            extra_headers=headers,
            base_url=self.ca_base_url,
        )

    async def ca_autorizza_credenziali(
        self,
        credentials_id: str,
        numero_fir: str,
        digest_to_sign: str,
        auth_data: Optional[List[Dict[str, str]]] = None,
        client_data: Optional[str] = None,
        reply_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Richiede l'autorizzazione della credenziale per firmare un hash.

        La richiesta genera la notifica al dispositivo associato al boarding.
        Il client invia un solo hash e non memorizza PIN/OTP.
        """
        credential = (credentials_id or "").strip()
        number = (numero_fir or "").strip()
        digest = (digest_to_sign or "").strip()
        if not credential or not number or not digest:
            raise ValueError("credentials_id, numero_fir e digest_to_sign sono obbligatori.")
        if not auth_data:
            raise ValueError(
                "La CA richiede auth_data. Prima leggi GET /credentials/info?auth_info=true "
                "e inserisci i dati previsti dagli oggetti di autenticazione restituiti."
            )
        # For CSC mobile-app/Notification auth objects, the standard payload is id-only.
        # Do not invent a value, PIN or OTP for these out-of-band objects.
        normalized_auth_data: List[Dict[str, str]] = []
        for index, item in enumerate(auth_data):
            if not isinstance(item, dict) or not str(item.get("id", "")).strip():
                raise ValueError(f"auth_data[{index}] deve contenere un id valido.")
            normalized_item = {"id": str(item["id"]).strip()}
            if item.get("value") is not None:
                normalized_item["value"] = str(item["value"])
            normalized_auth_data.append(normalized_item)
        payload: Dict[str, Any] = {
            "credentials_id": credential,
            "num_signatures": 1,
            "hashes": [digest],
            "hash_algo": "2.16.840.1.101.3.4.2.1",  # SHA-256
            "description": f"Firma FIR {number}",
            "auth_data": normalized_auth_data,
            "client_data": client_data or str(uuid.uuid4()),
        }
        headers = {"X-ReplyTo": reply_to.strip()} if reply_to and reply_to.strip() else None
        return await self._request(
            "POST", "/credentials/authorize", json_body=payload,
            extra_headers=headers, base_url=self.ca_base_url,
        )

    async def ca_conferma_autorizzazione(
        self,
        credentials_id: str,
        handle: str,
        otp: str,
        pin: str,
        allowed: bool = True,
        reply_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Conferma/rifiuta l'autorizzazione dopo la notifica sul dispositivo."""
        credential = (credentials_id or "").strip()
        request_handle = (handle or "").strip()
        if not credential or not request_handle:
            raise ValueError("credentials_id e handle della richiesta sono obbligatori.")
        if allowed and not (pin or "").strip():
            raise ValueError("Inserisci il PIN operativo RENTRI.")
        payload = {
            "credentials_id": credential,
            "handle": request_handle,
            "otp": (otp or "").strip(),
            "allowed": bool(allowed),
            "pin": (pin or "").strip(),
        }
        headers = {"X-ReplyTo": reply_to.strip()} if reply_to and reply_to.strip() else None
        return await self._request(
            "PUT", "/credentials/authorize-confirmation", json_body=payload,
            extra_headers=headers, base_url=self.ca_base_url,
        )

    @staticmethod
    def _signature_algorithm_for_certificate(certificato_base64: str) -> str:
        """Determina l'OID di firma in base alla chiave pubblica del .cer.

        ECDSA/SHA-256 è l'algoritmo riportato nell'esempio ufficiale RENTRI.
        Per un certificato RSA si usa sha256WithRSAEncryption.
        """
        normalized = RentriClient._normalizza_certificato_x509_base64(certificato_base64)
        der = base64.b64decode(normalized)
        certificate = x509.load_der_x509_certificate(der)
        public_key = certificate.public_key()
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return "1.2.840.10045.4.3.2"  # ecdsa-with-SHA256
        if isinstance(public_key, rsa.RSAPublicKey):
            return "1.2.840.113549.1.1.11"  # sha256WithRSAEncryption
        raise ValueError(
            "Tipo di chiave del certificato .cer non supportato dalla firma CA RENTRI: "
            f"{type(public_key).__name__}."
        )

    async def ca_firma_hash(
        self,
        credentials_id: str,
        sad: str,
        digest_to_sign: str,
        certificato_base64: str,
        client_data: Optional[str] = None,
        reply_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Firma il digest tramite POST /signatures/sign-hash."""
        credential = (credentials_id or "").strip()
        authorization = (sad or "").strip()
        digest = (digest_to_sign or "").strip()
        if not credential or not authorization or not digest:
            raise ValueError("credentials_id, SAD e digest_to_sign sono obbligatori.")
        if not (certificato_base64 or "").strip():
            raise ValueError("Il certificato .cer RENTRI è necessario per determinare l'algoritmo di firma.")
        normalized_cert = self._normalizza_certificato_x509_base64(certificato_base64)
        sign_algo = self._signature_algorithm_for_certificate(normalized_cert)
        payload = {
            "credentials_id": credential,
            "sad": authorization,
            "hashes": [digest],
            "hash_algo": "2.16.840.1.101.3.4.2.1",  # SHA-256
            "sign_algo": sign_algo,
            "sign_algo_params": "",
            "client_data": client_data or str(uuid.uuid4()),
        }
        headers = {"X-ReplyTo": reply_to.strip()} if reply_to and reply_to.strip() else None
        return await self._request(
            "POST", "/signatures/sign-hash", json_body=payload,
            extra_headers=headers, base_url=self.ca_base_url,
        )
