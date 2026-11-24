from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from typing import Any, Dict


class UsbSignerError(RuntimeError):
    """Errore durante la lettura o l'uso del certificato presente nello store Windows."""


def _powershell_executable() -> str:
    if os.name != "nt":
        raise UsbSignerError(
            "La firma con chiavetta USB e disponibile soltanto su Windows. Avvia il gestionale sul PC al quale e collegato il dispositivo."
        )
    candidates = [
        shutil.which("powershell.exe"),
        os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    raise UsbSignerError("Windows PowerShell 5.1 non trovato. Verifica che Windows PowerShell sia installato.")


def _run_powershell(script: str, timeout_seconds: int = 45) -> Dict[str, Any]:
    executable = _powershell_executable()
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    command = [
        executable,
        "-NoLogo",
        "-NoProfile",
        "-STA",
        "-ExecutionPolicy",
        "Bypass",
        "-WindowStyle",
        "Hidden",
        "-EncodedCommand",
        encoded,
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise UsbSignerError(
            "Operazione scaduta. Se Windows o InfoCert stavano mostrando la richiesta PIN, completala e riprova. Il gestionale non conserva il PIN."
        ) from exc
    except OSError as exc:
        raise UsbSignerError(f"Impossibile avviare PowerShell: {exc}") from exc

    stdout = (completed.stdout or "").strip()
    payload: Dict[str, Any] | None = None
    for line in reversed(stdout.splitlines()):
        candidate = line.strip().lstrip("\ufeff")
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            payload = parsed
            break

    if payload is None:
        stderr = (completed.stderr or "").strip()
        details = stderr or stdout or f"PowerShell terminato con codice {completed.returncode}."
        raise UsbSignerError("Risposta non leggibile dal componente Windows di firma. " + details[-1800:])

    if not payload.get("ok"):
        message = str(payload.get("error") or "Errore non specificato dal provider Windows.")
        raise UsbSignerError(message)

    return payload


_LIST_CERTIFICATES_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
try {
    $result = @()
    $now = Get-Date
    $stores = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')
    foreach ($storePath in $stores) {
        $certs = Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue
        foreach ($cert in $certs) {
            if (-not $cert.HasPrivateKey) { continue }
            if ($cert.NotBefore -gt $now -or $cert.NotAfter -lt $now) { continue }
            $oid = [string]$cert.PublicKey.Oid.Value
            $algorithm = $null
            if ($oid -eq '1.2.840.113549.1.1.1') { $algorithm = 'RSA' }
            elseif ($oid -eq '1.2.840.10045.2.1') { $algorithm = 'ECDSA' }
            else { continue }

            $keyUsageText = 'Unknown'
            $signatureUsage = $true
            foreach ($extension in $cert.Extensions) {
                if ($extension.Oid.Value -eq '2.5.29.15') {
                    $ku = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]$extension
                    $keyUsageText = $ku.KeyUsages.ToString()
                    $hasDigital = (($ku.KeyUsages -band [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) -ne 0)
                    $hasContent = (($ku.KeyUsages -band [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::NonRepudiation) -ne 0)
                    $signatureUsage = ($hasDigital -or $hasContent)
                    break
                }
            }

            $keySize = 0
            try { $keySize = [int]$cert.PublicKey.Key.KeySize } catch { }

            $result += [pscustomobject]@{
                thumbprint = ([string]$cert.Thumbprint).Replace(' ', '').ToUpperInvariant()
                subject = [string]$cert.Subject
                issuer = [string]$cert.Issuer
                serial_number = [string]$cert.SerialNumber
                valid_from = $cert.NotBefore.ToUniversalTime().ToString('o')
                valid_to = $cert.NotAfter.ToUniversalTime().ToString('o')
                key_algorithm = $algorithm
                key_algorithm_oid = $oid
                key_size = $keySize
                key_usage = $keyUsageText
                suitable_for_signature = [bool]$signatureUsage
                store_location = ($storePath -split '\\')[1]
                certificate_base64 = [Convert]::ToBase64String($cert.RawData)
            }
        }
    }
    $unique = @($result | Sort-Object thumbprint -Unique)
    [ordered]@{ ok = $true; certificates = $unique; windows_user = $env:USERNAME } | ConvertTo-Json -Depth 6 -Compress
}
catch {
    [ordered]@{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
    exit 1
}
'''


def list_windows_signing_certificates() -> Dict[str, Any]:
    result = _run_powershell(_LIST_CERTIFICATES_SCRIPT, timeout_seconds=40)
    certificates = result.get("certificates") or []
    if isinstance(certificates, dict):
        certificates = [certificates]
    if not isinstance(certificates, list):
        raise UsbSignerError("Formato inatteso nella risposta dello store certificati Windows.")
    return {
        "certificates": certificates,
        "windows_user": result.get("windows_user") or "",
        "count": len(certificates),
        "provider": "Windows Certificate Store / CSP-CNG",
        "pin_storage": "none",
    }


def sign_digest_with_windows_certificate(
    thumbprint: str,
    digest_to_sign_base64: str,
    expected_certificate_base64: str,
) -> Dict[str, Any]:
    clean_thumbprint = "".join(ch for ch in (thumbprint or "") if ch.isalnum()).upper()
    if len(clean_thumbprint) < 20:
        raise UsbSignerError("Seleziona un certificato USB valido dall'elenco Windows.")
    if not digest_to_sign_base64 or not expected_certificate_base64:
        raise UsbSignerError("Digest o certificato mancanti: genera prima l'hash RENTRI.")

    payload = {
        "thumbprint": clean_thumbprint,
        "digest_to_sign": digest_to_sign_base64.strip(),
        "expected_certificate": "".join(expected_certificate_base64.split()),
    }
    payload_b64 = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii")

    script = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
try {
    $payloadJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD_B64__'))
    $data = $payloadJson | ConvertFrom-Json
    $thumb = ([string]$data.thumbprint).Replace(' ', '').ToUpperInvariant()

    $cert = $null
    foreach ($storePath in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
        $cand = Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue | Where-Object { ([string]$_.Thumbprint).Replace(' ', '').ToUpperInvariant() -eq $thumb } | Select-Object -First 1
        if ($cand) { $cert = $cand; break }
    }
    if (-not $cert) { throw 'Certificato non trovato nello store Windows. Reinserisci la chiavetta e premi Rileva certificati.' }
    if (-not $cert.HasPrivateKey) { throw 'Windows trova il certificato, ma non la relativa chiave privata. Verifica driver e middleware InfoCert.' }

    $certBase64 = [Convert]::ToBase64String($cert.RawData)
    if ($certBase64 -ne [string]$data.expected_certificate) {
        throw 'Il certificato selezionato non coincide piu con quello usato per generare l hash. Rileva nuovamente il certificato e rigenera l hash.'
    }

    $now = Get-Date
    if ($cert.NotBefore -gt $now -or $cert.NotAfter -lt $now) {
        throw 'Il certificato selezionato non e attualmente valido.'
    }

    $digest = [Convert]::FromBase64String([string]$data.digest_to_sign)
    if ($digest.Length -ne 32) { throw ('Il digest ricevuto non e SHA-256: lunghezza ' + $digest.Length + ' byte.') }

    $oid = [string]$cert.PublicKey.Oid.Value
    if ($oid -eq '1.2.840.113549.1.1.1') {
        $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        if ($null -eq $key) { throw 'Il provider Windows non espone la chiave privata RSA. Verifica il middleware InfoCert.' }
        try { $signature = $key.SignHash($digest, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1) }
        finally { $key.Dispose() }
        $signatureAlgorithm = 'RSA-SHA256-PKCS1'
        $signatureAlgorithmOid = '1.2.840.113549.1.1.11'
    }
    elseif ($oid -eq '1.2.840.10045.2.1') {
        $key = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
        if ($null -eq $key) { throw 'Il provider Windows non espone la chiave privata ECDSA. Verifica il middleware InfoCert.' }
        try { $signature = $key.SignHash($digest) }
        finally { $key.Dispose() }
        $signatureAlgorithm = 'ECDSA-SHA256-P1363'
        $signatureAlgorithmOid = '1.2.840.10045.4.3.2'
    }
    else {
        throw ('Algoritmo della chiave non supportato: ' + $oid)
    }

    [ordered]@{
        ok = $true
        thumbprint = $thumb
        subject = [string]$cert.Subject
        issuer = [string]$cert.Issuer
        certificate_base64 = $certBase64
        signature_base64 = [Convert]::ToBase64String($signature)
        key_algorithm = if ($oid -eq '1.2.840.113549.1.1.1') { 'RSA' } else { 'ECDSA' }
        signature_algorithm = $signatureAlgorithm
        signature_algorithm_oid = $signatureAlgorithmOid
    } | ConvertTo-Json -Depth 5 -Compress
}
catch {
    [ordered]@{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
    exit 1
}
'''.replace('__PAYLOAD_B64__', payload_b64)

    result = _run_powershell(script, timeout_seconds=120)
    signature_b64 = str(result.get("signature_base64") or "").strip()
    cert_b64 = str(result.get("certificate_base64") or "").strip()
    if not signature_b64 or not cert_b64:
        raise UsbSignerError("Windows non ha restituito una firma o il certificato pubblico.")
    try:
        base64.b64decode(signature_b64, validate=True)
        base64.b64decode(cert_b64, validate=True)
    except Exception as exc:
        raise UsbSignerError("La risposta del provider Windows contiene Base64 non valido.") from exc
    return {
        "thumbprint": result.get("thumbprint"),
        "subject": result.get("subject"),
        "issuer": result.get("issuer"),
        "certificate_base64": cert_b64,
        "signature_base64": signature_b64,
        "key_algorithm": result.get("key_algorithm"),
        "signature_algorithm": result.get("signature_algorithm"),
        "signature_algorithm_oid": result.get("signature_algorithm_oid"),
    }
