"""Paquete de alta disponibilidad: combina el acceso OpenVPN (primario) de un
cliente con su par WireGuard (respaldo) en un único ZIP descargable, con
failover automático y DNS correcto en la conmutación.

Por qué existe este módulo: un failover manual bien probado durante semanas
seguía rompiendo la resolución de nombres internos en cuanto conmutaba al
respaldo, porque el dominio DNS de "solo esto por el túnel" nunca se replicó
en el perfil de respaldo — la red funcionaba, pero nada resoluble por nombre.
Este módulo genera ambas cosas juntas desde el primer día, para que ese fallo
no pueda repetirse: el respaldo WireGuard lleva el DNS correcto en su propio
fichero (`PostUp`/`PostDown`), no depende de la app ni de NetworkManager.
"""
from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field


@dataclass
class FailoverConfig:
    """Parámetros del paquete de alta disponibilidad para un cliente concreto."""

    name: str
    # Objetivo(s) de comprobación de salud: algo que SOLO se alcanza a través
    # de la VPN primaria (p. ej. la IP de la LAN remota o del propio servidor
    # de gestión) — comprobar "¿hay Internet?" no dice nada sobre si el túnel
    # primario en concreto funciona.
    health_check_hosts: list[str]
    health_check_port: int = 443
    split_dns_domain: str = ""  # p.ej. "~miempresa.local" (vacío = sin split-DNS)
    dns_servers: list[str] = field(default_factory=list)
    notify_webhook: str = ""  # URL genérica (ntfy, Discord, etc.); vacío = sin avisos
    check_interval_seconds: int = 60


def render_wireguard_conf_with_dns(base_conf: str, cfg: FailoverConfig) -> str:
    """Sustituye la línea `DNS =` plana de la plantilla por PostUp/PostDown de
    split-DNS, si se pidió. Sin esto, el respaldo funciona a nivel de red pero
    deja de resolver los dominios internos en cuanto se activa.
    """
    if not cfg.split_dns_domain or not cfg.dns_servers:
        return base_conf

    servers = " ".join(cfg.dns_servers)
    post_up = (
        f'PostUp = resolvectl dns %i {servers}; '
        f'resolvectl domain %i "{cfg.split_dns_domain}"'
    )
    post_down = "PostDown = resolvectl revert %i"

    lines = [ln for ln in base_conf.splitlines() if not ln.strip().startswith("DNS =")]
    out: list[str] = []
    inserted = False
    for line in lines:
        out.append(line)
        if not inserted and line.strip().startswith("PrivateKey"):
            out.append(post_up)
            out.append(post_down)
            inserted = True
    if not inserted:  # plantilla sin PrivateKey real (placeholder) -- añadir al principio
        out = [post_up, post_down, *out]
    return "\n".join(out) + "\n"


def render_failover_script(cfg: FailoverConfig) -> str:
    """Genera el script de vigilancia + failover (bash, portable).

    Se apoya solo en `wg-quick` + `ip`/`resolvectl` + `curl` — funciona en
    cualquier Linux con wireguard-tools instalado, con o sin NetworkManager.
    Idempotente frente al fallo real encontrado en producción: si la
    interfaz de respaldo ya existe de un intento anterior sin limpiar,
    `wg-quick up` falla con "already exists" — aquí se limpia antes.
    """
    hosts = " ".join(cfg.health_check_hosts)
    return f'''#!/usr/bin/env bash
# Generado por vpn-manager -- vigila la VPN primaria de "{cfg.name}" y, si
# deja de responder de verdad (dos comprobaciones seguidas), activa el
# respaldo WireGuard ("{cfg.name}-backup.conf"). No vuelve a la primaria en
# automático al recuperarse -- eso se hace a mano, para evitar oscilar.
#
# Requiere: wireguard-tools (wg-quick), curl. Pensado para ejecutarse via
# cron o un systemd timer cada {cfg.check_interval_seconds}s.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
WG_CONF="${{SCRIPT_DIR}}/{cfg.name}-backup.conf"
WG_IFACE="{cfg.name}-backup"
HEALTH_HOSTS=({hosts})
HEALTH_PORT={cfg.health_check_port}
NOTIFY_URL="{cfg.notify_webhook}"

notify() {{
  local msg="$1"
  [ -n "$NOTIFY_URL" ] || return 0
  curl -fsS -m 8 -d "$msg" "$NOTIFY_URL" >/dev/null 2>&1 || true
}}

healthy() {{
  local host
  for host in "${{HEALTH_HOSTS[@]}}"; do
    timeout 5 bash -c "echo > /dev/tcp/${{host}}/${{HEALTH_PORT}}" 2>/dev/null && return 0
  done
  return 1
}}

# Ya estamos en el respaldo y todo bien -- nada que hacer.
if ip link show "$WG_IFACE" >/dev/null 2>&1 && healthy; then
  exit 0
fi

healthy && exit 0

# Primer fallo -- puede ser un hipo puntual, confirmar con un segundo intento.
sleep 8
healthy && exit 0

notify "VPN primaria caida, activando respaldo WireGuard ({cfg.name})"

# Idempotente: si la interfaz ya existe de un intento anterior sin limpiar,
# tirarla primero (evita el "already exists" de wg-quick).
if ip link show "$WG_IFACE" >/dev/null 2>&1; then
  wg-quick down "$WG_CONF" >/dev/null 2>&1 || ip link delete dev "$WG_IFACE" 2>/dev/null || true
fi

if wg-quick up "$WG_CONF"; then
  sleep 3
  if healthy; then
    notify "Respaldo WireGuard activo, conectividad restaurada ({cfg.name})"
  else
    notify "ALERTA: el respaldo WireGuard tampoco recupero conectividad ({cfg.name}) -- revisar a mano"
  fi
else
  notify "ALERTA: wg-quick up fallo para el respaldo ({cfg.name}) -- revisar a mano"
fi
'''


def render_readme(cfg: FailoverConfig) -> str:
    return f'''# Paquete de alta disponibilidad — {cfg.name}

- `{cfg.name}.ovpn` — conexión primaria (OpenVPN). Impórtala normalmente.
- `{cfg.name}-backup.conf` — respaldo WireGuard. Colócalo en
  `/etc/wireguard/{cfg.name}-backup.conf` (permisos 600, `chmod 600`).
- `{cfg.name}-failover.sh` — vigila la primaria y activa el respaldo si hace
  falta. Dale permiso de ejecución y prográmalo cada
  {cfg.check_interval_seconds} segundos:

  ```
  chmod +x {cfg.name}-failover.sh
  crontab -e
  # anadir: * * * * * /ruta/a/{cfg.name}-failover.sh
  ```

No vuelve a la VPN primaria en automático al recuperarse — eso se hace a
mano (`wg-quick down /etc/wireguard/{cfg.name}-backup.conf`) una vez
confirmado que la primaria ya funciona, para evitar oscilar entre las dos.
'''


def build_bundle_zip(*, openvpn_conf: str, wireguard_conf: str, cfg: FailoverConfig) -> bytes:
    """Empaqueta ambas configs + el script de failover + un README en un ZIP."""
    wg_conf_with_dns = render_wireguard_conf_with_dns(wireguard_conf, cfg)
    script = render_failover_script(cfg)
    readme = render_readme(cfg)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{cfg.name}.ovpn", openvpn_conf)
        zf.writestr(f"{cfg.name}-backup.conf", wg_conf_with_dns)
        zf.writestr(f"{cfg.name}-failover.sh", script)
        zf.writestr("README.md", readme)
    return buf.getvalue()
