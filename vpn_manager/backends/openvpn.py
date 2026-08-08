"""Adaptador OpenVPN.

- Clientes/certificados: parsea el `index.txt` de la PKI (easy-rsa).
- Conexiones activas: parsea el fichero de `status` de OpenVPN.
- Estado del servicio: en sandbox no toca el sistema; en real usa `systemctl`.
- Alta / revocación / descarga de config: en sandbox opera sobre la PKI del
  sandbox; en real delega en `easy-rsa` (subprocess, sin shell).
"""
from __future__ import annotations

import re
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .base import (
    AlreadyExists,
    ConfigDirective,
    Forbidden,
    InvalidName,
    NotFound,
    ServerInfo,
    ServiceStatus,
    VpnBackend,
    VpnClient,
    VpnConnection,
    VpnError,
)

_CN_RE = re.compile(r"/CN=([^/]+)")
_INDEX_STATUS = {"V": "valid", "R": "revoked", "E": "expired"}
# Nombre seguro: empieza por alfanumérico; solo letras/números/._- ; 1..64.
# Evita inyección en comandos, traversal de rutas y CN con caracteres raros.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_CLIENT_VALID_YEARS = 3
_SERVICE_ACTIONS = ("start", "stop", "restart", "reload")


def _parse_asn1_time(raw: str) -> datetime | None:
    """easy-rsa usa tiempo ASN.1: YYMMDDHHMMSSZ (<2050) o YYYYMMDDHHMMSSZ (>=2050)."""
    raw = raw.strip()
    fmt = "%y%m%d%H%M%SZ" if len(raw) == 13 else "%Y%m%d%H%M%SZ"
    try:
        return datetime.strptime(raw, fmt).replace(tzinfo=UTC)
    except ValueError:
        return None


class OpenVpnBackend(VpnBackend):
    name = "openvpn"

    def __init__(
        self,
        pki_index: Path,
        status_file: Path,
        service: str,
        sandbox: bool,
        server_cn: str = "server",
        log_file: Path | None = None,
        server_conf: Path | None = None,
        public_endpoint: str = "vpn.ejemplo.local",
    ) -> None:
        self.pki_index = pki_index
        self.status_file = status_file
        self.service = service
        self.sandbox = sandbox
        self.server_cn = server_cn
        self.log_file = log_file
        self.server_conf = server_conf
        self.public_endpoint = public_endpoint
        # easy-rsa vive en el directorio padre de la PKI; los .ovpn generados se
        # guardan junto a la PKI (sandbox/openvpn/clients en modo sandbox).
        self.easyrsa_dir = pki_index.parent.parent
        self.client_dir = pki_index.parent.parent / "clients"

    # ── Validación / utilidades de la PKI ──────────────────────────────────
    def _check_name(self, name: str) -> str:
        name = (name or "").strip()
        if not _NAME_RE.match(name):
            raise InvalidName(
                "El nombre solo puede tener letras, números y los signos . _ - "
                "(entre 1 y 64 caracteres)."
            )
        if name == self.server_cn:
            raise Forbidden("Ese nombre está reservado para el servidor.")
        return name

    def _index_lines(self) -> list[str]:
        if not self.pki_index.exists():
            return []
        return self.pki_index.read_text(encoding="utf-8").splitlines()

    def _find(self, name: str) -> tuple[int, list[str]] | None:
        """Devuelve (índice de línea, columnas) de la entrada con ese CN, o None."""
        for i, line in enumerate(self._index_lines()):
            parts = line.split("\t")
            if len(parts) < 6 or parts[0] not in _INDEX_STATUS:
                continue
            m = _CN_RE.search(parts[5])
            if m and m.group(1).strip() == name:
                return i, parts
        return None

    def _next_serial(self) -> str:
        used = []
        for line in self._index_lines():
            parts = line.split("\t")
            if len(parts) >= 4:
                try:
                    used.append(int(parts[3].strip(), 16))
                except ValueError:
                    pass
        return f"{(max(used) + 1) if used else 1:02x}"

    @staticmethod
    def _asn1(dt: datetime) -> str:
        return dt.strftime("%y%m%d%H%M%SZ" if dt.year < 2050 else "%Y%m%d%H%M%SZ")

    def _write_index(self, lines: list[str]) -> None:
        self.pki_index.parent.mkdir(parents=True, exist_ok=True)
        self.pki_index.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # ── Estado del servicio ────────────────────────────────────────────────
    def status(self) -> ServiceStatus:
        if self.sandbox:
            return ServiceStatus(backend=self.name, active=True, detail="sandbox")
        try:
            out = subprocess.run(
                ["systemctl", "is-active", self.service],
                capture_output=True, text=True, timeout=5, check=False,
            )
            state = out.stdout.strip()
            return ServiceStatus(backend=self.name, active=state == "active", detail=state)
        except Exception as e:  # noqa: BLE001
            return ServiceStatus(backend=self.name, active=False, detail=str(e))

    # ── Clientes / certificados (PKI index) ────────────────────────────────
    def clients(self) -> list[VpnClient]:
        if not self.pki_index.exists():
            return []
        clients: list[VpnClient] = []
        for line in self.pki_index.read_text(encoding="utf-8").splitlines():
            parts = line.split("\t")
            if len(parts) < 6 or parts[0] not in _INDEX_STATUS:
                continue
            cn_match = _CN_RE.search(parts[5])
            if not cn_match:
                continue
            cn = cn_match.group(1).strip()
            if cn == self.server_cn:
                continue  # el cert del servidor no es un cliente
            clients.append(
                VpnClient(
                    name=cn,
                    status=_INDEX_STATUS[parts[0]],
                    serial=parts[3].strip() or None,
                    expires_at=_parse_asn1_time(parts[1]),
                )
            )
        return clients

    # ── Conexiones activas (status file) ───────────────────────────────────
    def connections(self) -> list[VpnConnection]:
        if not self.status_file.exists():
            return []
        lines = self.status_file.read_text(encoding="utf-8").splitlines()

        # Mapa CN -> dirección virtual (de la ROUTING TABLE).
        virtual: dict[str, str] = {}
        in_routes = False
        for ln in lines:
            if ln.startswith("ROUTING TABLE"):
                in_routes = True
                continue
            if ln.startswith("GLOBAL STATS"):
                in_routes = False
            if in_routes and "," in ln and not ln.startswith("Virtual Address"):
                cols = ln.split(",")
                if len(cols) >= 2:
                    virtual[cols[1].strip()] = cols[0].strip()

        conns: list[VpnConnection] = []
        in_clients = False
        for ln in lines:
            if ln.startswith("Common Name,Real Address"):
                in_clients = True
                continue
            if ln.startswith("ROUTING TABLE"):
                in_clients = False
            if in_clients and "," in ln:
                c = [x.strip() for x in ln.split(",")]
                if len(c) < 5:
                    continue
                since = None
                try:
                    since = datetime.strptime(c[4], "%Y-%m-%d %H:%M:%S").replace(
                        tzinfo=UTC
                    )
                except ValueError:
                    pass
                conns.append(
                    VpnConnection(
                        name=c[0],
                        real_address=c[1],
                        virtual_address=virtual.get(c[0]),
                        bytes_received=int(c[2]) if c[2].isdigit() else 0,
                        bytes_sent=int(c[3]) if c[3].isdigit() else 0,
                        connected_since=since,
                    )
                )
        return conns

    # ── Escritura: alta ────────────────────────────────────────────────────
    def create_client(self, name: str) -> VpnClient:
        name = self._check_name(name)
        if self._find(name) is not None:
            raise AlreadyExists(f"Ya existe un acceso con el nombre «{name}».")

        if not self.sandbox:
            self._easyrsa("build-client-full", name, "nopass", batch=True)
            found = self._find(name)
            if found is None:  # pragma: no cover - depende del entorno real
                raise VpnError("easy-rsa no registró el certificado.")
            parts = found[1]
            return VpnClient(
                name=name, status="valid",
                serial=parts[3].strip() or None, expires_at=_parse_asn1_time(parts[1]),
            )

        # Sandbox: registra la entrada en index.txt y genera el .ovpn.
        expiry = datetime.now(UTC) + timedelta(days=365 * _CLIENT_VALID_YEARS)
        serial = self._next_serial()
        lines = self._index_lines()
        lines.append(f"V\t{self._asn1(expiry)}\t\t{serial}\tunknown\t/CN={name}")
        self._write_index(lines)
        self._save_config(name, self._render_ovpn(name))
        return VpnClient(name=name, status="valid", serial=serial, expires_at=expiry)

    # ── Escritura: revocación ──────────────────────────────────────────────
    def revoke_client(self, name: str) -> VpnClient:
        name = self._check_name(name)
        found = self._find(name)
        if found is None:
            raise NotFound(f"No existe ningún acceso llamado «{name}».")
        idx, parts = found
        if parts[0] == "R":
            return VpnClient(
                name=name, status="revoked",
                serial=parts[3].strip() or None, expires_at=_parse_asn1_time(parts[1]),
            )

        if not self.sandbox:
            self._easyrsa("revoke", name, batch=True)
            self._easyrsa("gen-crl")
        else:
            now = self._asn1(datetime.now(UTC))
            parts = parts[:]
            parts[0] = "R"
            parts[2] = now  # fecha de revocación
            lines = self._index_lines()
            lines[idx] = "\t".join(parts)
            self._write_index(lines)
            cfg = self.client_dir / f"{name}.ovpn"
            if cfg.exists():
                cfg.unlink()  # el config ya no sirve

        return VpnClient(
            name=name, status="revoked",
            serial=parts[3].strip() or None, expires_at=_parse_asn1_time(parts[1]),
        )

    # ── Escritura: renovación ──────────────────────────────────────────────
    def renew_client(self, name: str) -> VpnClient:
        name = self._check_name(name)
        found = self._find(name)
        if found is None:
            raise NotFound(f"No existe ningún acceso llamado «{name}».")
        idx, parts = found
        if parts[0] == "R":
            raise Forbidden("No se puede renovar un acceso retirado; crea uno nuevo.")

        if not self.sandbox:
            self._easyrsa("renew", name, "nopass", batch=True)
            found = self._find(name)
            parts = found[1] if found else parts
        else:
            expiry = datetime.now(UTC) + timedelta(days=365 * _CLIENT_VALID_YEARS)
            parts = parts[:]
            parts[0] = "V"
            parts[1] = self._asn1(expiry)
            parts[2] = ""  # sin fecha de revocación
            lines = self._index_lines()
            lines[idx] = "\t".join(parts)
            self._write_index(lines)
            self._save_config(name, self._render_ovpn(name))

        return VpnClient(
            name=name, status="valid",
            serial=parts[3].strip() or None, expires_at=_parse_asn1_time(parts[1]),
        )

    # ── Descarga de configuración ──────────────────────────────────────────
    def client_config(self, name: str) -> str:
        name = self._check_name(name)
        found = self._find(name)
        if found is None:
            raise NotFound(f"No existe ningún acceso llamado «{name}».")
        if found[1][0] != "V":
            raise Forbidden("Solo se puede descargar la configuración de un acceso activo.")
        cfg = self.client_dir / f"{name}.ovpn"
        if cfg.exists():
            return cfg.read_text(encoding="utf-8")
        return self._render_ovpn(name)

    # ── Control del servicio ───────────────────────────────────────────────
    def service_action(self, action: str) -> ServiceStatus:
        if action not in _SERVICE_ACTIONS:
            raise InvalidName(
                f"Acción no permitida. Usa una de: {', '.join(_SERVICE_ACTIONS)}."
            )
        if self.sandbox:
            active = action != "stop"
            return ServiceStatus(
                backend=self.name, active=active, detail=f"sandbox: «{action}» simulado"
            )
        try:
            subprocess.run(
                ["systemctl", action, self.service],
                capture_output=True, text=True, timeout=30, check=True,
            )
        except subprocess.CalledProcessError as e:  # pragma: no cover
            raise VpnError(f"systemctl {action} falló: {e.stderr.strip() or e}") from e
        except (OSError, subprocess.TimeoutExpired) as e:  # pragma: no cover
            raise VpnError(f"No se pudo ejecutar systemctl: {e}") from e
        return self.status()

    # ── Conexiones: cortar una sesión ──────────────────────────────────────
    def disconnect(self, name: str) -> None:
        name = self._check_name(name)
        active = {c.name for c in self.connections()}
        if name not in active:
            raise NotFound(f"«{name}» no tiene ninguna conexión activa.")
        if not self.sandbox:  # pragma: no cover - requiere interfaz de management
            raise VpnError(
                "Desconexión en producción aún no implementada (requiere la "
                "interfaz de management de OpenVPN)."
            )
        # Sandbox: elimina del fichero de estado las filas del cliente (tanto la
        # de CLIENT LIST como la de ROUTING TABLE).
        if self.status_file.exists():
            kept = [
                ln for ln in self.status_file.read_text(encoding="utf-8").splitlines()
                if name not in [f.strip() for f in ln.split(",")]
            ]
            self.status_file.write_text("\n".join(kept) + "\n", encoding="utf-8")

    # ── Configuración del servidor ─────────────────────────────────────────
    def server_info(self) -> ServerInfo:
        info = ServerInfo(backend=self.name, public_endpoint=self.public_endpoint)
        if not (self.server_conf and self.server_conf.exists()):
            return info

        directives: dict[str, str] = {}
        pushes: list[str] = []
        for raw in self.server_conf.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", ";")):
                continue
            key, _, value = line.partition(" ")
            key = key.strip()
            value = value.strip()
            # Todas las directivas, en orden, para la vista completa.
            info.directives.append(ConfigDirective(key=key, value=value))
            directives[key] = value
            if key == "push":
                pushes.append(value.strip('"'))

        info.port = directives.get("port")
        info.proto = directives.get("proto")
        info.device = directives.get("dev")
        info.subnet = directives.get("server")
        info.cipher = directives.get("data-ciphers") or directives.get("cipher")
        info.auth = directives.get("auth")
        info.tls_version = directives.get("tls-version-min")
        info.max_clients = directives.get("max-clients")
        info.crl_enabled = "crl-verify" in directives

        # DNS y rutas empujadas a los clientes (directivas `push`).
        for p in pushes:
            parts = p.split()
            if len(parts) >= 2 and parts[0] == "dhcp-option" and parts[1] == "DNS":
                info.dns_servers.append(parts[2])
            elif parts and parts[0] == "route":
                info.routes.append(" ".join(parts[1:]))
        return info

    def update_server_config(self, directives: list[tuple[str, str]]) -> ServerInfo:
        """Valida y reescribe el server.conf a partir de la lista de directivas."""
        from .openvpn_schema import validate_directive

        if not self.server_conf:
            raise VpnError("No hay fichero de configuración del servidor definido.")
        cleaned: list[str] = []
        for key, value in directives:
            key = (key or "").strip()
            value = (value or "").strip()
            if not key:
                continue
            err = validate_directive(key, value)
            if err:
                raise InvalidName(err)
            cleaned.append(f"{key} {value}".rstrip())
        header = "# Configuración del servidor OpenVPN — gestionada por VPN Manager"
        self.server_conf.parent.mkdir(parents=True, exist_ok=True)
        self.server_conf.write_text(header + "\n" + "\n".join(cleaned) + "\n", encoding="utf-8")
        return self.server_info()

    # ── Registros ──────────────────────────────────────────────────────────
    def logs(self, lines: int = 50) -> list[str]:
        lines = max(1, min(lines, 1000))
        if self.log_file and self.log_file.exists():
            content = self.log_file.read_text(encoding="utf-8", errors="replace").splitlines()
            return content[-lines:]
        if self.sandbox:
            return []
        try:  # pragma: no cover - depende del entorno real
            out = subprocess.run(
                ["journalctl", "-u", self.service, "-n", str(lines), "--no-pager"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            return out.stdout.splitlines()
        except Exception as e:  # noqa: BLE001  # pragma: no cover
            return [f"(no se pudieron leer los registros: {e})"]

    # ── Helpers de escritura ───────────────────────────────────────────────
    def _save_config(self, name: str, content: str) -> None:
        self.client_dir.mkdir(parents=True, exist_ok=True)
        (self.client_dir / f"{name}.ovpn").write_text(content, encoding="utf-8")

    def _render_ovpn(self, name: str) -> str:
        marca = "# SANDBOX / DEMO — sin material criptográfico real" if self.sandbox else ""
        info = self.server_info()
        port = info.port or "1194"
        proto = (info.proto or "udp").split()[0]
        dev = info.device or "tun"
        cipher = (info.cipher or "AES-256-GCM").split(":")[0]
        auth = info.auth or "SHA256"
        return (
            f"# Configuración OpenVPN para «{name}»\n"
            f"{marca}\n"
            "client\n"
            f"dev {dev}\n"
            f"proto {proto}\n"
            f"remote {self.public_endpoint} {port}\n"
            "resolv-retry infinite\n"
            "nobind\n"
            "persist-key\n"
            "persist-tun\n"
            "remote-cert-tls server\n"
            f"data-ciphers {cipher}\n"
            f"auth {auth}\n"
            "verb 3\n"
            f"# <ca>, <cert> y <key> de «{name}» se insertan aquí en producción.\n"
        )

    def _easyrsa(self, *args: str, batch: bool = False) -> None:
        cmd = ["./easyrsa"]
        if batch:
            cmd.append("--batch")
        cmd.extend(args)
        try:
            subprocess.run(
                cmd, cwd=self.easyrsa_dir, capture_output=True, text=True,
                timeout=60, check=True,
            )
        except subprocess.CalledProcessError as e:  # pragma: no cover
            raise VpnError(f"easy-rsa falló: {e.stderr.strip() or e}") from e
        except (OSError, subprocess.TimeoutExpired) as e:  # pragma: no cover
            raise VpnError(f"No se pudo ejecutar easy-rsa: {e}") from e
