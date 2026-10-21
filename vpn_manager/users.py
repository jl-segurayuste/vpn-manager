"""Usuarios, roles y permisos del panel.

- Almacén de usuarios en un fichero JSON (contraseñas con PBKDF2, nunca en claro).
- Tres roles con conjuntos de permisos. El backend exige el permiso en cada endpoint;
  la UI solo adapta lo que muestra.
- Seguro por defecto: si no hay fichero de usuarios, se siembra (en memoria) el admin
  de la configuración; al crear/editar usuarios se persiste.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import auth, totp

# ── Roles y permisos ───────────────────────────────────────────────────────
PERMISSIONS: dict[str, set[str]] = {
    "admin": {
        "clients:read", "clients:write", "clients:config", "service:control", "server:read",
        "server:write", "logs:read", "users:manage", "system:install", "audit:read",
    },
    "operator": {
        "clients:read", "clients:write", "clients:config", "service:control", "server:read", "logs:read",
    },
    # Solo lectura: ve clientes y conexiones, pero no descarga sus configuraciones (llevan la clave
    # privada del cliente: con ellas se entra en la red)
    "viewer": {"clients:read", "server:read", "logs:read"},
}
ROLES = list(PERMISSIONS)
ROLE_LABELS = {"admin": "Administrador", "operator": "Operador", "viewer": "Solo lectura"}

_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,31}$")
# Hash de relleno para igualar tiempos cuando el usuario no existe (anti-enumeración).
_DUMMY_HASH = auth.hash_password("x")


class UserError(Exception):
    """Error de negocio en la gestión de usuarios."""


def role_permissions(role: str) -> set[str]:
    return PERMISSIONS.get(role, set())


class UserStore:
    def __init__(self, path: Path, seed_user: str, seed_hash: str, seed_role: str = "admin") -> None:
        self.path = path
        self.users: dict[str, dict] = {}
        if path and path.exists():
            try:
                self.users = json.loads(path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                self.users = {}
        if not self.users:
            self.users = {seed_user: {"password_hash": seed_hash, "role": seed_role}}

    # ── Persistencia ────────────────────────────────────────────────────────
    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.users, indent=2), encoding="utf-8")

    # ── Consulta ──────────────────────────────────────────────────────────
    def exists(self, username: str) -> bool:
        return username in self.users

    def role(self, username: str) -> str | None:
        u = self.users.get(username)
        return u["role"] if u else None

    def has_perm(self, username: str, perm: str) -> bool:
        role = self.role(username)
        return bool(role) and perm in role_permissions(role)

    def verify(self, username: str, password: str) -> bool:
        u = self.users.get(username)
        if not u:
            auth.verify_password(password, _DUMMY_HASH)  # iguala el tiempo
            return False
        return auth.verify_password(password, u["password_hash"])

    def list(self) -> list[dict]:
        return [
            {"username": k, "role": v["role"], "role_label": ROLE_LABELS.get(v["role"], v["role"]),
             "totp": bool(v.get("totp_enabled"))}
            for k, v in sorted(self.users.items())
        ]

    # ── Verificación en dos pasos (TOTP) ──────────────────────────────────
    def totp_enabled(self, username: str) -> bool:
        u = self.users.get(username)
        return bool(u and u.get("totp_enabled"))

    def totp_secret(self, username: str) -> str | None:
        u = self.users.get(username)
        return u.get("totp_secret") if u else None

    def set_totp_secret(self, username: str, secret: str) -> None:
        """Guarda un secreto pendiente de confirmar (aún no activo).

        Con la verificación ya activa no se puede: antes esto la desactivaba, así que con una sesión
        robada se quitaba el 2FA sin dar ningún código (desactivarlo sí lo pide)."""
        if username not in self.users:
            raise UserError(f"No existe el usuario «{username}».")
        if self.users[username].get("totp_enabled"):
            raise UserError("La verificación en dos pasos ya está activa: desactívala primero con un código.")
        self.users[username]["totp_secret"] = secret
        self.users[username]["totp_enabled"] = False
        self._save()

    def enable_totp(self, username: str) -> None:
        if not self.users.get(username, {}).get("totp_secret"):
            raise UserError("Primero genera el código QR (configurar).")
        self.users[username]["totp_enabled"] = True
        self._bump_epoch(username)
        self._save()

    def disable_totp(self, username: str) -> None:
        if username in self.users:
            self.users[username].pop("totp_secret", None)
            self.users[username]["totp_enabled"] = False
            self._bump_epoch(username)
            self._save()

    # ── Versión de sesión ─────────────────────────────────────────────────
    # La sesión es una cookie firmada sin estado en el servidor: sin esto, una copia robada seguía
    # valiendo tras cambiar la contraseña hasta caducar. La sesión guarda la versión del usuario al
    # entrar y deja de valer cuando cambia (contraseña o 2FA).
    def session_epoch(self, username: str) -> int:
        u = self.users.get(username)
        return int(u.get("session_epoch", 0)) if u else -1

    def _bump_epoch(self, username: str) -> None:
        self.users[username]["session_epoch"] = self.session_epoch(username) + 1

    def verify_totp(self, username: str, code: str, window: int = 1, at: float | None = None) -> bool:
        """Valida un código TOTP e impide reutilizarlo. Bug real encontrado
        2026-08-09: `totp.verify()` es sin estado -- el mismo código válido
        (visto en un log, por encima del hombro...) se podía reenviar un
        número ilimitado de veces y siempre se aceptaba, anulando la garantía
        anti-repetición que es la razón de ser de TOTP frente a una
        contraseña estática. Se registra el último paso consumido por
        usuario y se rechaza cualquier código que no sea estrictamente
        posterior."""
        u = self.users.get(username)
        if not u:
            return False
        secret = u.get("totp_secret")
        if not secret:
            return False
        step = totp.find_matching_step(secret, code, window=window, at=at)
        if step is None:
            return False
        last = u.get("totp_last_counter")
        if last is not None and step <= last:
            return False
        u["totp_last_counter"] = step
        self._save()
        return True

    def _admins(self) -> list[str]:
        return [k for k, v in self.users.items() if v["role"] == "admin"]

    # ── Mutación ──────────────────────────────────────────────────────────
    @staticmethod
    def _check(username: str, role: str | None, password: str | None) -> None:
        if not _USERNAME_RE.match(username or ""):
            raise UserError(
                "El usuario solo puede tener letras, números y . _ - (2 a 32 caracteres)."
            )
        if role is not None and role not in ROLES:
            raise UserError(f"Rol no válido. Usa uno de: {', '.join(ROLES)}.")
        if password is not None and len(password) < 8:
            raise UserError("La contraseña debe tener al menos 8 caracteres.")

    def add(self, username: str, password: str, role: str) -> None:
        self._check(username, role, password)
        if username in self.users:
            raise UserError(f"Ya existe un usuario «{username}».")
        self.users[username] = {"password_hash": auth.hash_password(password), "role": role}
        self._save()

    def update(self, username: str, role: str | None = None, password: str | None = None) -> None:
        if username not in self.users:
            raise UserError(f"No existe el usuario «{username}».")
        self._check(username, role, password)
        if role is not None:
            # No dejar el sistema sin administradores.
            if self.users[username]["role"] == "admin" and role != "admin" and self._admins() == [username]:
                raise UserError("No puedes quitar el último administrador.")
            self.users[username]["role"] = role
        if password is not None:
            self.users[username]["password_hash"] = auth.hash_password(password)
            self._bump_epoch(username)          # cierra las sesiones abiertas de ese usuario
        self._save()

    def delete(self, username: str) -> None:
        if username not in self.users:
            raise UserError(f"No existe el usuario «{username}».")
        if self.users[username]["role"] == "admin" and self._admins() == [username]:
            raise UserError("No puedes borrar el último administrador.")
        del self.users[username]
        self._save()
