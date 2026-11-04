"""Adaptador OpenVPN.

- Clientes/certificados: parsea el `index.txt` de la PKI (easy-rsa).
- Conexiones activas: parsea el fichero de `status` de OpenVPN.
- Estado del servicio: en sandbox no toca el sistema; en real usa `systemctl`.
- Alta / revocación / descarga de config: en sandbox opera sobre la PKI del
  sandbox; en real delega en `easy-rsa` (subprocess, sin shell).
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ..fsutil import write_private
from .base import (
    OPENVPN_COMMAND_DIRECTIVES,
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
    check_command_directives,
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


def _quit(sock: socket.socket) -> None:
    """Cierra la sesión de management con cortesía; si el servidor ya cortó, da igual."""
    try:
        sock.sendall(b"quit\n")
    except OSError:
        pass


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
        allow_command_directives: bool = False,
    ) -> None:
        self.allow_command_directives = allow_command_directives
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
        if name in self._server_names():
            raise Forbidden("Ese nombre está reservado para el servidor.")
        return name

    # ── Ficheros del servidor (server.conf) ────────────────────────────────
    def _server_dir(self) -> Path:
        return self.server_conf.parent if self.server_conf else self.easyrsa_dir

    def _conf_directives(self) -> dict[str, str]:
        """Primera aparición de cada directiva del server.conf (clave -> resto de la línea)."""
        found: dict[str, str] = {}
        if self.server_conf and self.server_conf.exists():
            for raw in self.server_conf.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line[0] in "#;":
                    continue
                key, _, value = line.partition(" ")
                found.setdefault(key, value.strip())
        return found

    def _conf_path(self, directive: str) -> Path | None:
        """Ruta de un fichero del server.conf (`crl-verify crl.pem`); las relativas, como OpenVPN,
        respecto al directorio del server.conf (el WorkingDirectory de openvpn-server@)."""
        value = self._conf_directives().get(directive)
        if not value:
            return None
        path = Path(value.split()[0])
        return path if path.is_absolute() else self._server_dir() / path

    def _server_names(self) -> set[str]:
        """CN del certificado del servidor: el configurado y el del `cert` del server.conf. El
        instalador de angristan lo llama server_<aleatorio>: con solo «server», salía como un cliente
        más y se podía revocar desde el panel (y la VPN dejaba de funcionar)."""
        names = {self.server_cn}
        cert = self._conf_path("cert")
        if cert is not None:
            names.add(cert.stem)
        return names

    def _index_lines(self) -> list[str]:
        if not self.pki_index.exists():
            return []
        return self.pki_index.read_text(encoding="utf-8").splitlines()

    def _entries(self) -> dict[str, list[tuple[int, list[str]]]]:
        """CN -> [(índice de línea, columnas)] en orden del index.txt."""
        found: dict[str, list[tuple[int, list[str]]]] = {}
        for i, line in enumerate(self._index_lines()):
            parts = line.split("\t")
            if len(parts) < 6 or parts[0] not in _INDEX_STATUS:
                continue
            m = _CN_RE.search(parts[5])
            if m:
                found.setdefault(m.group(1).strip(), []).append((i, parts))
        return found

    @staticmethod
    def _current(entries: list[tuple[int, list[str]]]) -> tuple[int, list[str]]:
        """La entrada vigente de un CN: la última válida o, si no hay, la última. Tras renovar (o
        retirar y volver a crear) hay varias con el mismo nombre; antes se tomaba la primera, la
        del certificado antiguo, y el acceso renovado salía como retirado."""
        valid = [e for e in entries if e[1][0] == "V"]
        return (valid or entries)[-1]

    def _find(self, name: str) -> tuple[int, list[str]] | None:
        """Devuelve (índice de línea, columnas) de la entrada vigente con ese CN, o None."""
        entries = self._entries().get(name)
        return self._current(entries) if entries else None

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
        server_names = self._server_names()
        for cn, entries in self._entries().items():
            parts = self._current(entries)[1]
            if cn in server_names:
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
        found = self._find(name)
        if found is not None and found[1][0] == "V":
            raise AlreadyExists(f"Ya existe un acceso con el nombre «{name}».")

        if not self.sandbox:
            self._easyrsa("build-client-full", name, "nopass", batch=True)
            found = self._find(name)
            if found is None:  # pragma: no cover - depende del entorno real
                raise VpnError("easy-rsa no registró el certificado.")
            parts = found[1]
            self._save_config(name, self._build_real_config(name))
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
            (self.client_dir / f"{name}.ovpn").unlink(missing_ok=True)   # ya no sirve
            self._publish_crl()
            # La CRL solo frena las conexiones nuevas: la sesión abierta seguiría hasta renegociar
            # (1 h por defecto). Si hay interfaz de management, se corta ya.
            if self._management_address() is not None:
                try:
                    self._management_kill(name)
                except VpnError:
                    pass
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
            self._save_config(name, self._build_real_config(name))   # certificado nuevo
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
        if not self.sandbox:
            # Cliente creado fuera del panel: se genera y se guarda para la próxima vez.
            content = self._build_real_config(name)
            self._save_config(name, content)
            return content
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
        if not self.sandbox:
            if not self._management_kill(name):
                raise NotFound(f"«{name}» no tiene ninguna conexión activa.")
            return
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
        current: set[tuple[str, str]] = set()
        if self.server_conf.exists():
            for raw in self.server_conf.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if line and line[0] not in "#;":
                    key, _, value = line.partition(" ")
                    current.add((key.lower(), value.strip()))
        err = check_command_directives(
            [((k or "").strip(), v or "") for k, v in directives], current,
            OPENVPN_COMMAND_DIRECTIVES, self.allow_command_directives,
        )
        if err:
            raise Forbidden(err)
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
        write_private(self.server_conf, header + "\n" + "\n".join(cleaned) + "\n")   # atómico
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
        write_private(self.client_dir / f"{name}.ovpn", content)

    # ── Configuración real del cliente ─────────────────────────────────────
    # Antes, en producción el .ovpn salía sin CA, certificado, clave ni clave TLS (solo un
    # comentario «se insertan aquí en producción»): ninguna configuración descargada conectaba.
    def _build_real_config(self, name: str) -> str:
        pki = self.pki_index.parent
        template = self._server_dir() / "client-template.txt"     # la que deja el instalador
        if template.exists():
            base = template.read_text(encoding="utf-8").rstrip("\n") + "\n"
        else:
            base = "\n".join(ln for ln in self._render_ovpn(name).splitlines() if not ln.startswith("# <ca>")) + "\n"
        try:
            ca = (pki / "ca.crt").read_text(encoding="utf-8").strip()
            cert_text = (pki / "issued" / f"{name}.crt").read_text(encoding="utf-8")
            key = (pki / "private" / f"{name}.key").read_text(encoding="utf-8").strip()
        except FileNotFoundError as e:
            raise VpnError(f"Falta material de la PKI para «{name}»: {e.filename}") from e
        begin = cert_text.find("-----BEGIN CERTIFICATE-----")
        end = cert_text.find("-----END CERTIFICATE-----")
        if begin < 0 or end < 0:
            raise VpnError(f"El certificado de «{name}» no tiene formato PEM.")
        cert = cert_text[begin:end + len("-----END CERTIFICATE-----")]
        parts = [base, f"<ca>\n{ca}\n</ca>\n", f"<cert>\n{cert}\n</cert>\n", f"<key>\n{key}\n</key>\n"]
        parts.append(self._tls_block())
        return "".join(parts)

    def _tls_block(self) -> str:
        """La clave del canal de control que use el servidor (tls-crypt-v2, tls-crypt o tls-auth)."""
        directives = self._conf_directives()
        if "tls-crypt-v2" in directives:
            server_key = self._conf_path("tls-crypt-v2")
            fd, tmp = tempfile.mkstemp(dir=self._server_dir(), prefix=".tls-crypt-v2-client.")
            os.close(fd)
            try:
                subprocess.run(
                    ["openvpn", "--tls-crypt-v2", str(server_key), "--genkey", "tls-crypt-v2-client", tmp],
                    capture_output=True, text=True, timeout=30, check=True,
                )
                client_key = Path(tmp).read_text(encoding="utf-8").strip()
            except subprocess.CalledProcessError as e:
                raise VpnError(f"No se pudo generar la clave tls-crypt-v2: {e.stderr.strip() or e}") from e
            except (OSError, subprocess.TimeoutExpired) as e:
                raise VpnError(f"No se pudo ejecutar openvpn para la clave tls-crypt-v2: {e}") from e
            finally:
                Path(tmp).unlink(missing_ok=True)
            return f"<tls-crypt-v2>\n{client_key}\n</tls-crypt-v2>\n"
        for directive, tag in (("tls-crypt", "tls-crypt"), ("tls-auth", "tls-auth")):
            if directive in directives:
                path = self._conf_path(directive)
                try:
                    shared = path.read_text(encoding="utf-8").strip()
                except OSError as e:
                    raise VpnError(f"No se puede leer la clave {directive} ({path}): {e}") from e
                prefix = "key-direction 1\n" if directive == "tls-auth" else ""
                return f"{prefix}<{tag}>\n{shared}\n</{tag}>\n"
        return ""

    # ── Interfaz de management (desconectar sesiones) ──────────────────────
    def _management_address(self):
        """("unix", ruta) o ("tcp", (host, puerto)) según la directiva `management`, más el fichero
        de contraseña si lo hay; None si el servidor no tiene management."""
        value = self._conf_directives().get("management")
        if not value:
            return None
        parts = value.split()
        if len(parts) >= 2 and parts[1] == "unix":
            sock = Path(parts[0])
            pw = parts[2] if len(parts) > 2 else None
            return "unix", (sock if sock.is_absolute() else self._server_dir() / sock), pw
        if len(parts) >= 2 and parts[1].isdigit():
            pw = parts[2] if len(parts) > 2 else None
            return "tcp", (parts[0], int(parts[1])), pw
        return None

    def _management_kill(self, name: str) -> bool:
        """Corta las sesiones de `name` (comando `kill <cn>`). True si había alguna."""
        addr = self._management_address()
        if addr is None:
            raise VpnError(
                "Para desconectar hace falta la interfaz de management de OpenVPN: añade al server.conf "
                "«management /run/openvpn-server/management.sock unix» y reinicia el servicio."
            )
        kind, where, pw_file = addr
        family = socket.AF_UNIX if kind == "unix" else socket.AF_INET
        target = str(where) if kind == "unix" else where
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect(target)
                reader = sock.makefile("rb")
                if pw_file:
                    password = self._conf_relative(pw_file).read_text(encoding="utf-8").splitlines()[0]
                    sock.sendall(password.encode() + b"\n")
                sock.sendall(f"kill {name}\n".encode())
                for raw in reader:
                    line = raw.decode(errors="replace").strip()
                    # Con contraseña llega antes «SUCCESS: password is correct»: solo cuenta la
                    # respuesta al kill («SUCCESS/ERROR: common name …»).
                    if "SUCCESS: common name" in line:
                        _quit(sock)
                        return True
                    if "ERROR:" in line:
                        _quit(sock)
                        if "common name" in line and "not found" in line:
                            return False
                        raise VpnError(f"La interfaz de management respondió: {line[line.index('ERROR:'):]}")
        except OSError as e:
            raise VpnError(f"No se pudo usar la interfaz de management ({target}): {e}") from e
        raise VpnError("La interfaz de management cerró la conexión sin responder.")

    def _conf_relative(self, value: str) -> Path:
        path = Path(value)
        return path if path.is_absolute() else self._server_dir() / path

    def _publish_crl(self) -> None:
        """Copia la CRL nueva a donde la lee el servidor (`crl-verify`). Antes solo se generaba en
        la PKI: con el instalador de angristan el servidor lee una copia en /etc/openvpn/server y un
        acceso «retirado» seguía conectando."""
        target = self._conf_path("crl-verify")
        source = self.pki_index.parent / "crl.pem"
        if target is None:
            raise VpnError(
                "El server.conf no tiene crl-verify: el certificado queda revocado en la PKI, pero el "
                "servidor no lo comprobará hasta que se configure crl-verify."
            )
        if target.resolve() != source.resolve():
            # 0644: OpenVPN la vuelve a leer tras bajar privilegios (user nobody)
            write_private(target, source.read_bytes(), 0o644)
            target.chmod(0o644)

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
