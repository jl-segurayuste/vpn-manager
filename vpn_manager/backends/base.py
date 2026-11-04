"""Modelo común y contrato de los backends VPN (OpenVPN / WireGuard).

La API y la UI hablan solo este lenguaje; cada backend traduce sus detalles.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from pydantic import BaseModel


class VpnClient(BaseModel):
    """Un cliente/peer dado de alta en el servidor."""

    name: str
    status: str  # valid | revoked | expired | disabled
    serial: str | None = None
    expires_at: datetime | None = None


class VpnConnection(BaseModel):
    """Una conexión activa en este momento."""

    name: str
    real_address: str | None = None
    virtual_address: str | None = None
    bytes_received: int = 0
    bytes_sent: int = 0
    connected_since: datetime | None = None


class ServiceStatus(BaseModel):
    backend: str  # openvpn | wireguard
    active: bool
    detail: str = ""


class ConfigDirective(BaseModel):
    key: str
    value: str = ""


class ServerInfo(BaseModel):
    """Configuración del servidor VPN (solo lectura)."""

    backend: str
    public_endpoint: str | None = None  # IP/dominio público al que conectan
    port: str | None = None
    proto: str | None = None
    device: str | None = None
    subnet: str | None = None  # rango de IPs de la VPN
    cipher: str | None = None  # cifrados de datos
    auth: str | None = None  # algoritmo de autenticación HMAC
    tls_version: str | None = None
    max_clients: str | None = None
    dns_servers: list[str] = []  # DNS empujados a los clientes
    routes: list[str] = []  # rutas empujadas a los clientes
    crl_enabled: bool = False
    # Todas las directivas del fichero de configuración, sin filtrar.
    directives: list[ConfigDirective] = []


# ── Errores de dominio (la API los traduce a códigos HTTP) ─────────────────────
class VpnError(Exception):
    """Error de negocio del backend."""


# Directivas que hacen que el servicio (root) ejecute órdenes o cargue código. Las que ya están en la
# configuración se conservan al editarla; añadirlas o cambiarlas desde el panel exige
# VPNM_ALLOW_COMMAND_DIRECTIVES=true: si no, una sesión de administrador robada bastaba para ejecutar
# órdenes como root en el servidor.
OPENVPN_COMMAND_DIRECTIVES = frozenset({
    "up", "down", "client-connect", "client-disconnect", "learn-address", "auth-user-pass-verify",
    "tls-verify", "ipchange", "route-up", "route-pre-down", "plugin", "script-security", "config",
})
WIREGUARD_COMMAND_DIRECTIVES = frozenset({"preup", "postup", "predown", "postdown"})


def check_command_directives(
    submitted: list[tuple[str, str]], current: set[tuple[str, str]], command_keys: frozenset[str], allowed: bool
) -> str | None:
    """Mensaje de error si se añade o cambia una directiva que ejecuta órdenes sin permitirlo."""
    if allowed:
        return None
    for key, value in submitted:
        if key.lower() in command_keys and (key.lower(), value.strip()) not in current:
            return (
                f"«{key}» ejecuta órdenes como root en el servidor: por seguridad no se puede añadir ni "
                "cambiar desde el panel (las que ya existen se conservan). Si lo necesitas, edítalo en el "
                "servidor o arranca el panel con VPNM_ALLOW_COMMAND_DIRECTIVES=true."
            )
    return None


class InvalidName(VpnError):
    """Nombre de cliente no válido (caracteres no permitidos)."""


class NotFound(VpnError):
    """No existe ningún cliente con ese nombre."""


class AlreadyExists(VpnError):
    """Ya existe un cliente con ese nombre."""


class Forbidden(VpnError):
    """Operación no permitida (p. ej. tocar el certificado del servidor)."""


class VpnBackend(ABC):
    """Contrato común a OpenVPN y WireGuard."""

    name: str

    # ── Lectura ────────────────────────────────────────────────────────────
    @abstractmethod
    def status(self) -> ServiceStatus: ...

    @abstractmethod
    def clients(self) -> list[VpnClient]: ...

    @abstractmethod
    def connections(self) -> list[VpnConnection]: ...

    # ── Escritura (Fase 2) ─────────────────────────────────────────────────
    def create_client(self, name: str) -> VpnClient:
        """Da de alta una persona/dispositivo (genera su certificado)."""
        raise NotImplementedError

    def revoke_client(self, name: str) -> VpnClient:
        """Retira el acceso de un cliente (revoca su certificado + CRL)."""
        raise NotImplementedError

    def client_config(self, name: str) -> str:
        """Devuelve el fichero de configuración del cliente para descargar."""
        raise NotImplementedError

    def renew_client(self, name: str) -> VpnClient:
        """Renueva (reemite) el certificado de un cliente activo o caducado."""
        raise NotImplementedError

    # ── Control del servicio, conexiones y registros ───────────────────────
    def service_action(self, action: str) -> ServiceStatus:
        """Arranca, para, reinicia o recarga el servidor VPN."""
        raise NotImplementedError

    def disconnect(self, name: str) -> None:
        """Corta la conexión activa de un cliente."""
        raise NotImplementedError

    def logs(self, lines: int = 50) -> list[str]:
        """Últimas líneas del registro del servidor VPN."""
        raise NotImplementedError

    def server_info(self) -> ServerInfo:
        """Parámetros de configuración del servidor VPN."""
        raise NotImplementedError
