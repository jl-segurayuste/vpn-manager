"""TOTP (verificación en dos pasos) — implementación propia del estándar RFC 6238.

Sin dependencias externas: genera el secreto, el código de 6 dígitos y la URI
`otpauth://` que leen las apps de autenticación (Google Authenticator, Aegis…).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

_STEP = 30
_DIGITS = 6


def generate_secret(length: int = 20) -> str:
    """Secreto en base32 (sin relleno), como esperan las apps de autenticación."""
    return base64.b32encode(secrets.token_bytes(length)).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int, digits: int = _DIGITS) -> str:
    pad = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32.upper() + pad, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def now_code(secret: str, at: float | None = None) -> str:
    return _hotp(secret, int((at if at is not None else time.time()) // _STEP))


def find_matching_step(secret: str, code: str, window: int = 1, at: float | None = None) -> int | None:
    """Como `verify`, pero devuelve el número de paso (step) que coincidió, o
    None si ninguno lo hizo. Se necesita por separado porque `verify` es sin
    estado (no sabe si ese código ya se usó antes) -- el llamador que sí
    lleve el estado (ver `UserStore.verify_totp`) puede comparar este step
    contra el último consumido para impedir reutilizar el mismo código dos
    veces, que es justo la garantía anti-repetición que se supone que da
    TOTP frente a una contraseña estática."""
    if not secret or not code:
        return None
    code = code.strip().replace(" ", "")
    counter = int((at if at is not None else time.time()) // _STEP)
    for w in range(-window, window + 1):
        step = counter + w
        if hmac.compare_digest(_hotp(secret, step), code):
            return step
    return None


def verify(secret: str, code: str, window: int = 1, at: float | None = None) -> bool:
    """Valida el código admitiendo ±`window` pasos (tolerancia de reloj). No
    protege contra reutilización del mismo código -- para eso, usar
    `UserStore.verify_totp`, que sí registra el último paso consumido."""
    return find_matching_step(secret, code, window=window, at=at) is not None


def provisioning_uri(secret: str, account: str, issuer: str = "VPN Manager") -> str:
    label = urllib.parse.quote(f"{issuer}:{account}")
    params = urllib.parse.urlencode(
        {"secret": secret, "issuer": issuer, "digits": _DIGITS, "period": _STEP}
    )
    return f"otpauth://totp/{label}?{params}"
