"""Adaptador WireGuard.

- Peers (clientes): parsea el `wg0.conf` (cada `[Peer]` precedido por `# nombre`).
- Conexiones activas: parsea la salida de `wg show`.
- Estado del servicio: en sandbox no toca el sistema; en real `systemctl`.
- Alta / baja / descarga de config + QR: en sandbox opera sobre el `wg0.conf` del
  sandbox; en real usa `wg`/`wg-quick`.

WireGuard no tiene certificados ni caducidad: un peer se define por su clave pública.
Por eso `VpnClient.status` es siempre «valid» y `expires_at` queda vacío.
"""
from __future__ import annotations

import base64
import ipaddress
import os
import re
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .base import (
    AlreadyExists,
    ConfigDirective,
    InvalidName,
    NotFound,
    ServerInfo,
    ServiceStatus,
    VpnBackend,
    VpnClient,
    VpnConnection,
    VpnError,
)

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SERVICE_ACTIONS = ("start", "stop", "restart", "reload")
# "1 minute, 12 seconds ago" → segundos
_UNIT_SECONDS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400, "week": 604800}


def _genkey() -> str:
    """Clave estilo WireGuard (32 bytes en base64). En sandbox no es material real."""
    return base64.b64encode(os.urandom(32)).decode()


def _handshake_to_dt(text: str) -> datetime | None:
    """Convierte «1 minute, 12 seconds ago» en un datetime aproximado."""
    total = 0
    for num, unit in re.findall(r"(\d+)\s+(second|minute|hour|day|week)s?", text):
        total += int(num) * _UNIT_SECONDS[unit]
    if total == 0 and "ago" not in text:
        return None
    return datetime.now(UTC) - timedelta(seconds=total)


def _transfer_to_bytes(text: str) -> int:
    m = re.match(r"([\d.]+)\s*([KMGT]?i?B)", text.strip())
    if not m:
        return 0
    value = float(m.group(1))
    unit = m.group(2).replace("i", "").upper()
    factor = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}.get(unit, 1)
    return int(value * factor)


class WireGuardBackend(VpnBackend):
    name = "wireguard"

    def __init__(
        self,
        conf: Path,
        show_file: Path,
        service: str,
        sandbox: bool,
        interface: str = "wg0",
        log_file: Path | None = None,
        public_endpoint: str = "vpn.ejemplo.local",
        dns: str = "1.1.1.1",
    ) -> None:
        self.conf = conf
        self.show_file = show_file
        self.service = service
        self.sandbox = sandbox
        self.interface = interface
        self.log_file = log_file
        self.public_endpoint = public_endpoint
        self.dns = dns
        self.client_dir = conf.parent / "clients"

    # ── Validación / parseo del wg0.conf ───────────────────────────────────
    def _check_name(self, name: str) -> str:
        name = (name or "").strip()
        if not _NAME_RE.match(name):
            raise InvalidName(
                "El nombre solo puede tener letras, números y los signos . _ - "
                "(entre 1 y 64 caracteres)."
            )
        return name

    def _conf_lines(self) -> list[str]:
        if not self.conf.exists():
            return []
        return self.conf.read_text(encoding="utf-8").splitlines()

    def _parse_interface(self) -> dict[str, str]:
        iface: dict[str, str] = {}
        in_iface = False
        for line in self._conf_lines():
            s = line.strip()
            if s.startswith("[Interface]"):
                in_iface = True
                continue
            if s.startswith("["):
                in_iface = False
                continue
            if in_iface and "=" in s and not s.startswith("#"):
                k, _, v = s.partition("=")
                iface[k.strip()] = v.strip()
        return iface

    def _parse_peers(self) -> list[dict[str, str]]:
        """Lista de peers: {name, public_key, allowed_ips}."""
        peers: list[dict[str, str]] = []
        pending_name = None
        cur: dict[str, str] | None = None
        for line in self._conf_lines():
            s = line.strip()
            if s.startswith("#"):
                pending_name = s.lstrip("# ").strip()
                continue
            if s.startswith("[Peer]"):
                cur = {"name": pending_name or "", "public_key": "", "allowed_ips": ""}
                peers.append(cur)
                pending_name = None
                continue
            if s.startswith("[Interface]"):
                cur = None
                pending_name = None
                continue
            if cur is not None and "=" in s:
                k, _, v = s.partition("=")
                k = k.strip().lower()
                if k == "publickey":
                    cur["public_key"] = v.strip()
                elif k == "allowedips":
                    cur["allowed_ips"] = v.strip()
        return peers

    def _find(self, name: str) -> dict[str, str] | None:
        for p in self._parse_peers():
            if p["name"] == name:
                return p
        return None

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

    # ── Clientes (peers) ───────────────────────────────────────────────────
    def clients(self) -> list[VpnClient]:
        result: list[VpnClient] = []
        for p in self._parse_peers():
            if not p["name"]:
                continue
            result.append(
                VpnClient(
                    name=p["name"], status="valid",
                    serial=(p["public_key"][:12] + "…") if p["public_key"] else None,
                    expires_at=None,
                )
            )
        return result

    # ── Conexiones activas (wg show) ───────────────────────────────────────
    def connections(self) -> list[VpnConnection]:
        text = self._wg_show_text()
        if text is None:
            return []
        key_to_name = {p["public_key"]: p["name"] for p in self._parse_peers()}
        conns: list[VpnConnection] = []
        cur: dict[str, str] | None = None
        for raw in text.splitlines():
            s = raw.strip()
            if s.startswith("peer:"):
                cur = {"key": s.split(":", 1)[1].strip()}
            elif cur is not None and s.startswith("endpoint:"):
                cur["endpoint"] = s.split(":", 1)[1].strip()
            elif cur is not None and s.startswith("allowed ips:"):
                cur["allowed"] = s.split(":", 1)[1].strip().split(",")[0].split("/")[0]
            elif cur is not None and s.startswith("latest handshake:"):
                cur["handshake"] = s.split(":", 1)[1].strip()
            elif cur is not None and s.startswith("transfer:"):
                cur["transfer"] = s.split(":", 1)[1].strip()
            elif not s and cur is not None:
                self._emit_conn(cur, key_to_name, conns)
                cur = None
        if cur is not None:
            self._emit_conn(cur, key_to_name, conns)
        return conns

    def _wg_show_text(self) -> str | None:
        """Salida de `wg show <iface>` para parsear conexiones. En modo REAL la
        ejecuta EN VIVO (el estado no vive en ningún fichero); en sandbox lee el
        fixture `show_file`. Sin esto, «Conexiones en tiempo real» no mostraría
        nada con WireGuard real."""
        if not self.sandbox:
            try:
                return self._wg_out("show", self.interface)
            except VpnError:
                return None
        if self.show_file and self.show_file.exists():
            return self.show_file.read_text(encoding="utf-8")
        return None

    @staticmethod
    def _emit_conn(cur, key_to_name, conns) -> None:
        # Solo cuentan como "conectados" los que tienen handshake reciente.
        if "handshake" not in cur:
            return
        rx = tx = 0
        if "transfer" in cur:
            parts = cur["transfer"].split(",")
            if len(parts) == 2:
                rx = _transfer_to_bytes(parts[0].replace("received", ""))
                tx = _transfer_to_bytes(parts[1].replace("sent", ""))
        conns.append(
            VpnConnection(
                name=key_to_name.get(cur["key"], cur["key"][:12] + "…"),
                real_address=cur.get("endpoint"),
                virtual_address=cur.get("allowed"),
                bytes_received=rx, bytes_sent=tx,
                connected_since=_handshake_to_dt(cur.get("handshake", "")),
            )
        )

    # ── Alta de peer ───────────────────────────────────────────────────────
    def create_client(self, name: str) -> VpnClient:
        name = self._check_name(name)
        if self._find(name) is not None:
            raise AlreadyExists(f"Ya existe un dispositivo con el nombre «{name}».")

        priv, pub = self._genkeypair()
        ip = self._next_ip()
        if not self.sandbox:  # pragma: no cover - requiere wg en el host
            self._wg("set", self.interface, "peer", pub, "allowed-ips", f"{ip}/32")
        block = f"\n# {name}\n[Peer]\nPublicKey = {pub}\nAllowedIPs = {ip}/32\n"
        with self.conf.open("a", encoding="utf-8") as f:
            f.write(block)
        self._save_config(name, self._render_conf(name, priv, ip))
        return VpnClient(name=name, status="valid", serial=pub[:12] + "…", expires_at=None)

    # ── Baja de peer ───────────────────────────────────────────────────────
    def revoke_client(self, name: str) -> VpnClient:
        name = self._check_name(name)
        peer = self._find(name)
        if peer is None:
            raise NotFound(f"No existe ningún dispositivo llamado «{name}».")
        if not self.sandbox and peer["public_key"]:  # pragma: no cover
            self._wg("set", self.interface, "peer", peer["public_key"], "remove")
        self._remove_peer_block(name)
        cfg = self.client_dir / f"{name}.conf"
        if cfg.exists():
            cfg.unlink()
        return VpnClient(name=name, status="revoked", serial=None, expires_at=None)

    # ── Descarga de configuración ──────────────────────────────────────────
    def client_config(self, name: str) -> str:
        name = self._check_name(name)
        if self._find(name) is None:
            raise NotFound(f"No existe ningún dispositivo llamado «{name}».")
        cfg = self.client_dir / f"{name}.conf"
        if cfg.exists():
            return cfg.read_text(encoding="utf-8")
        # Si no se guardó (peer preexistente del fixture), genera una plantilla.
        peer = self._find(name)
        ip = (peer["allowed_ips"] or "10.9.0.0/32").split("/")[0]
        return self._render_conf(name, "(clave-privada-del-dispositivo)", ip)

    # ── Configuración del servidor ─────────────────────────────────────────
    def server_info(self) -> ServerInfo:
        iface = self._parse_interface()
        info = ServerInfo(
            backend=self.name,
            public_endpoint=self.public_endpoint,
            port=iface.get("ListenPort"),
            proto="UDP (WireGuard)",
            device=self.interface,
            subnet=iface.get("Address"),
            cipher="ChaCha20-Poly1305",
            auth="Curve25519 + BLAKE2s",
            max_clients=str(len(self._parse_peers())),
            dns_servers=[self.dns] if self.dns else [],
        )
        # Directivas sin exponer NUNCA la clave privada del servidor.
        for line in self._conf_lines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s.lower().startswith("privatekey"):
                info.directives.append(ConfigDirective(key="PrivateKey", value="(oculta)"))
                continue
            if "=" in s:
                k, _, v = s.partition("=")
                info.directives.append(ConfigDirective(key=k.strip(), value=v.strip()))
            else:
                info.directives.append(ConfigDirective(key=s, value=""))
        return info

    def _peer_section_text(self) -> str:
        """Texto crudo desde el primer bloque de peer (preserva comentarios/claves)."""
        lines = self._conf_lines()
        start = None
        for i, line in enumerate(lines):
            if line.strip().startswith("[Peer]"):
                start = i - 1 if i > 0 and lines[i - 1].strip().startswith("#") else i
                break
        return "\n".join(lines[start:]) if start is not None else ""

    def update_server_config(self, directives: list[tuple[str, str]]) -> ServerInfo:
        """Reescribe el [Interface] del wg0.conf preservando la clave privada y los peers."""
        from .wireguard_schema import validate_directive

        priv = self._parse_interface().get("PrivateKey", "")
        out: list[str] = []
        for key, value in directives:
            key = (key or "").strip()
            value = (value or "").strip()
            if not key or key == "PrivateKey":
                continue  # la clave privada no se edita desde aquí
            err = validate_directive(key, value)
            if err:
                raise InvalidName(err)
            out.append(f"{key} = {value}" if value else key)

        lines = ["# Configuración WireGuard — gestionada por VPN Manager", "[Interface]"]
        if priv:
            lines.append(f"PrivateKey = {priv}")
        lines.extend(out)
        body = "\n".join(lines) + "\n"
        peers = self._peer_section_text()
        if peers:
            body += "\n" + peers.rstrip("\n") + "\n"
        self.conf.write_text(body, encoding="utf-8")
        return self.server_info()

    # ── Control del servicio y registros ───────────────────────────────────
    def service_action(self, action: str) -> ServiceStatus:
        if action not in _SERVICE_ACTIONS:
            raise InvalidName(f"Acción no permitida. Usa una de: {', '.join(_SERVICE_ACTIONS)}.")
        if self.sandbox:
            return ServiceStatus(
                backend=self.name, active=action != "stop", detail=f"sandbox: «{action}» simulado"
            )
        try:  # pragma: no cover
            subprocess.run(
                ["systemctl", action, self.service],
                capture_output=True, text=True, timeout=30, check=True,
            )
        except subprocess.CalledProcessError as e:  # pragma: no cover
            raise VpnError(f"systemctl {action} falló: {e.stderr.strip() or e}") from e
        except (OSError, subprocess.TimeoutExpired) as e:  # pragma: no cover
            raise VpnError(f"No se pudo ejecutar systemctl: {e}") from e
        return self.status()

    def logs(self, lines: int = 50) -> list[str]:
        lines = max(1, min(lines, 1000))
        if self.log_file and self.log_file.exists():
            return self.log_file.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]
        return []

    # ── QR de la configuración del cliente ─────────────────────────────────
    def client_qr_svg(self, name: str) -> str:
        try:
            import segno
        except ImportError as e:  # pragma: no cover
            raise VpnError("Falta la dependencia «segno» para generar el QR.") from e
        config = self.client_config(name)
        qr = segno.make(config, error="m")
        return qr.svg_inline(scale=4, border=2)

    # ── Helpers ────────────────────────────────────────────────────────────
    def _next_ip(self) -> str:
        iface = self._parse_interface()
        network = ipaddress.ip_network(iface.get("Address", "10.9.0.1/24"), strict=False)
        used = {iface.get("Address", "").split("/")[0]}
        for p in self._parse_peers():
            if p["allowed_ips"]:
                used.add(p["allowed_ips"].split("/")[0])
        for host in network.hosts():
            if str(host) not in used:
                return str(host)
        raise VpnError("No quedan direcciones libres en el rango de la VPN.")

    def _render_conf(self, name: str, priv: str, ip: str) -> str:
        iface = self._parse_interface()
        port = iface.get("ListenPort", "51820")
        return (
            f"# Configuración WireGuard para «{name}»\n"
            "[Interface]\n"
            f"PrivateKey = {priv}\n"
            f"Address = {ip}/32\n"
            f"DNS = {self.dns}\n\n"
            "[Peer]\n"
            f"PublicKey = {self._server_pubkey()}\n"
            f"Endpoint = {self.public_endpoint}:{port}\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "PersistentKeepalive = 25\n"
        )

    def _save_config(self, name: str, content: str) -> None:
        self.client_dir.mkdir(parents=True, exist_ok=True)
        (self.client_dir / f"{name}.conf").write_text(content, encoding="utf-8")

    def _remove_peer_block(self, name: str) -> None:
        """Elimina del wg0.conf el comentario «# name» y su bloque [Peer]."""
        lines = self._conf_lines()
        out: list[str] = []
        i = 0
        while i < len(lines):
            if lines[i].strip() == f"# {name}":
                # salta el comentario, el [Peer] y sus claves hasta el próximo bloque/blanco
                i += 1
                if i < len(lines) and lines[i].strip().startswith("[Peer]"):
                    i += 1
                    while i < len(lines) and lines[i].strip() and not lines[i].strip().startswith("["):
                        i += 1
                # consume una línea en blanco separadora si la hay
                if i < len(lines) and not lines[i].strip():
                    i += 1
                continue
            out.append(lines[i])
            i += 1
        self.conf.write_text("\n".join(out).rstrip("\n") + "\n", encoding="utf-8")

    def _wg(self, *args: str) -> None:  # pragma: no cover - requiere wg real
        try:
            subprocess.run(["wg", *args], capture_output=True, text=True, timeout=30, check=True)
        except subprocess.CalledProcessError as e:
            raise VpnError(f"wg falló: {e.stderr.strip() or e}") from e
        except (OSError, subprocess.TimeoutExpired) as e:
            raise VpnError(f"No se pudo ejecutar wg: {e}") from e

    def _wg_out(self, *args: str, stdin: str | None = None) -> str:  # pragma: no cover - requiere wg real
        """Ejecuta `wg` y devuelve su stdout (para genkey/pubkey/show)."""
        try:
            res = subprocess.run(
                ["wg", *args], input=stdin, capture_output=True, text=True, timeout=30, check=True
            )
            return res.stdout.strip()
        except subprocess.CalledProcessError as e:
            raise VpnError(f"wg falló: {e.stderr.strip() or e}") from e
        except (OSError, subprocess.TimeoutExpired) as e:
            raise VpnError(f"No se pudo ejecutar wg: {e}") from e

    def _genkeypair(self) -> tuple[str, str]:
        """Par (privada, pública) del cliente. En modo real deriva la pública de la
        privada con `wg genkey`/`wg pubkey` (obligatorio: si no coinciden, el
        handshake falla). En sandbox usa claves ficticias (no material real)."""
        if self.sandbox:
            return _genkey(), _genkey()
        priv = self._wg_out("genkey")
        return priv, self._wg_out("pubkey", stdin=priv)

    def _server_pubkey(self) -> str:  # pragma: no cover - requiere wg real
        """Clave pública del servidor para el config del cliente. En real: de
        `wg show <iface> public-key`, con respaldo derivándola del `PrivateKey` del
        wg0.conf. En sandbox: placeholder (comportamiento previo, no rompe tests)."""
        if self.sandbox:
            return "(clave-publica-del-servidor)"
        try:
            pub = self._wg_out("show", self.interface, "public-key")
            if pub:
                return pub
        except VpnError:
            pass
        priv = self._parse_interface().get("PrivateKey")
        return self._wg_out("pubkey", stdin=priv) if priv else "(clave-publica-del-servidor)"
