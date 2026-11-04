"""Autenticación del panel: hash de contraseñas y protección anti–fuerza bruta.

- Contraseñas con PBKDF2-SHA256 (sin dependencias externas), comparación en
  tiempo constante.
- Por defecto seguro: en producción sin contraseña configurada, la app NO arranca;
  en sandbox usa una credencial de desarrollo con un aviso claro.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time

_ALG = "pbkdf2_sha256"
_ITERATIONS = 600_000
_DEV_PASSWORD = "admin"  # solo en sandbox, con aviso

log = logging.getLogger("vpn_manager.auth")


def hash_password(password: str, iterations: int = _ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"{_ALG}${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        alg, iterations, salt_hex, hash_hex = stored.split("$")
        if alg != _ALG:
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
        )
    except (ValueError, AttributeError):
        return False
    return hmac.compare_digest(dk.hex(), hash_hex)


def resolve_credentials(admin_user: str, admin_password_hash: str, sandbox: bool) -> tuple[str, str]:
    """Devuelve (usuario, hash). Aplica el principio de «seguro por defecto»."""
    if admin_password_hash:
        return admin_user, admin_password_hash
    if not sandbox:
        raise RuntimeError(
            "Falta VPNM_ADMIN_PASSWORD_HASH: el panel no arranca sin contraseña "
            "en producción. Genera un hash con «python -m vpn_manager.hashpw»."
        )
    log.warning(
        "⚠️  Modo desarrollo: usando credenciales por defecto «%s/%s». "
        "Configura VPNM_ADMIN_PASSWORD_HASH antes de exponer el panel.",
        admin_user, _DEV_PASSWORD,
    )
    return admin_user, hash_password(_DEV_PASSWORD)


def resolve_secret(secret_key: str, sandbox: bool = True) -> str:
    if secret_key:
        return secret_key
    if not sandbox:
        raise RuntimeError(
            "Falta VPNM_SECRET_KEY: el panel no arranca sin clave de sesión en "
            "producción. Genérala con «python -c \"import secrets; "
            "print(secrets.token_hex(32))\"»."
        )
    log.warning(
        "⚠️  VPNM_SECRET_KEY no configurada: se usa una clave efímera "
        "(las sesiones se pierden al reiniciar)."
    )
    return secrets.token_hex(32)


class LoginThrottle:
    """Limita los intentos de login por IP (ventana deslizante)."""

    def __init__(self, max_attempts: int = 5, lock_seconds: int = 300) -> None:
        self.max_attempts = max_attempts
        self.lock_seconds = lock_seconds
        self._fails: dict[str, list[float]] = {}

    def is_blocked(self, key: str) -> bool:
        now = time.monotonic()
        fails = [t for t in self._fails.get(key, []) if now - t < self.lock_seconds]
        self._fails[key] = fails
        return len(fails) >= self.max_attempts

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        # Sin esto, cada IP que fallaba una vez se quedaba para siempre en memoria.
        if len(self._fails) > 10_000:
            self._fails = {
                k: v for k, v in self._fails.items() if v and now - v[-1] < self.lock_seconds
            }
        self._fails.setdefault(key, []).append(now)

    def reset(self, key: str) -> None:
        self._fails.pop(key, None)
