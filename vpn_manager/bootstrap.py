"""Instalación y desinstalación «llave en mano» de los servidores VPN.

Reutiliza los conocidos instaladores de angristan (MIT), que además de instalar los
paquetes configuran el servidor completo (PKI, server.conf, firewall/NAT, primer
cliente) en muchas distribuciones — y que, ejecutados de nuevo sobre una instalación
ya existente, también saben desinstalarla por completo:

- OpenVPN:   https://github.com/angristan/openvpn-install   (openvpn-install.sh)
- WireGuard: https://github.com/angristan/wireguard-install (wireguard-install.sh)

NO incluimos su código en el repositorio: el panel **descarga** el script de una URL
**fijada a un commit concreto** y **verifica su SHA-256** antes de ejecutarlo (cadena
de suministro). Sin checksum configurado, no se ejecuta (fail-closed). En sandbox solo
se simula (no descarga ni ejecuta).

Invocación de desinstalación por backend (verificado contra el contenido real de
cada commit fijado en `config.py`, no contra `master` — las dos versiones no tienen
por qué comportarse igual):
- **OpenVPN** (commit `935e559…`): la propia CLI del script ya trae un subcomando
  `uninstall --force` completamente desatendido — no necesita variables de entorno
  ni entrada por stdin, `--force` salta la confirmación interactiva
  (`REMOVE=y` internamente).
- **WireGuard** (commit `832fb98…`): sigue siendo el estilo antiguo de menú
  interactivo, sin subcomandos. `manageMenu()` comprueba `MENU_OPTION` con un
  `until` ANTES de leer de stdin, así que fijarla a `4` (opción "Uninstall
  WireGuard") salta ese menú — pero la confirmación de `uninstallWg()`
  (`read -rp "Do you really want to remove WireGuard? [y/n]: " REMOVE`) es una
  lectura incondicional que ignora cualquier `REMOVE` ya exportado, así que hace
  falta además alimentar `"y\\n"` por stdin.

Instalación desatendida de WireGuard (commit `832fb98…`) — mapeada línea a línea de
`installQuestions()` + `newClient()` (esta última se invoca automáticamente al final
de `installWireGuard()`, no hay forma de saltarla):
- La mayoría de preguntas están protegidas por un `until <regex-válida>; do read;
  done` — si la variable ya viene preestablecida por entorno y cumple la validación,
  el `read` nunca se ejecuta. Cubre `SERVER_PUB_NIC`, `SERVER_WG_NIC`,
  `SERVER_WG_IPV4`, `SERVER_WG_IPV6`, `SERVER_PORT`, `CLIENT_DNS_1`, `CLIENT_DNS_2`,
  `ALLOWED_IPS`, y (en `newClient()`) `CLIENT_NAME` combinado con `CLIENT_EXISTS`.
  `CLIENT_EXISTS=0` es seguro de fijar a ciegas porque esta rama solo se alcanza en
  una instalación recién creada, sin ningún cliente todavía — nunca puede haber
  colisión real.
- Dos son lecturas incondicionales (`read` sin `until` que las proteja, ignoran
  cualquier variable ya exportada): la IP/dominio público al principio, y "Press
  any key to continue..." al final del cuestionario. Ambas necesitan una línea real
  por stdin.
- Dos más, dentro de `newClient()`, combinan validación (`until IPV4_EXISTS==0`) con
  un cálculo real que solo ocurre DENTRO del cuerpo del bucle (`CLIENT_WG_IPV4 =
  BASE_IP.DOT_IP`) — pre-fijar la condición a "ya cumplida" saltaría también ese
  cálculo, dejando la IP del cliente vacía. Para estas dos sí hace falta responder
  por stdin con un valor real, no basta con el truco de variable de entorno. En una
  instalación recién creada el primer hueco libre siempre es ".2" (el ".1" es el
  propio servidor) — no es una suposición, es lo que el propio script ya calcula de
  forma determinista en el `for DOT_IP in {2..254}` justo antes de cada bucle.
- `SERVER_PUB_NIC` (la interfaz de red pública) no se puede fijar a un valor
  inventado de forma segura: varía por máquina real. Se detecta en Python
  (`_detect_public_interface()`, sin `shell=True`, replica la misma consulta de
  ruta por defecto que hace el propio script) justo antes de invocarlo, en el mismo
  host — así que no es una suposición externa, es confirmar lo que el script habría
  autodetectado él solo. Si no se puede detectar (host sin ruta por defecto), se
  falla explícitamente ANTES de lanzar el script, en vez de arriesgarse a que el
  `until` correspondiente quede esperando un stdin que nunca llega.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
import urllib.request
from pathlib import Path

REPOS = {
    "openvpn": "angristan/openvpn-install",
    "wireguard": "angristan/wireguard-install",
}

# Puerto UDP por defecto que ofrece el propio script (aleatorio en el rango
# 49152-65535 cada vez que se ejecuta interactivamente) — en modo desatendido se usa
# el puerto estándar de WireGuard (51820, IANA) en su lugar: mismo efecto (cualquier
# valor 1-65535 pasa la validación del script), pero predecible para quien tenga que
# documentar/abrir el puerto en un firewall, en vez de un valor aleatorio distinto
# cada instalación.
_WIREGUARD_DEFAULT_PORT = "51820"
# Mismos defaults que el propio script ofrece interactivamente (Cloudflare) para lo
# que no tiene un settings.* ya existente en este proyecto.
_WIREGUARD_DEFAULT_DNS_2 = "1.0.0.1"
_WIREGUARD_DEFAULT_ALLOWED_IPS = "0.0.0.0/0,::/0"
_WIREGUARD_DEFAULT_WG_IPV4 = "10.66.66.1"
_WIREGUARD_DEFAULT_WG_IPV6 = "fd42:42:42::1"
_WIREGUARD_DEFAULT_CLIENT_NAME = "cliente1"  # mismo nombre que ya usa OpenVPN arriba


def _detect_public_interface() -> str | None:
    """Replica `ip -4 route ls | grep default | awk '... dev ...'` sin shell ni
    pipes — la misma consulta que `installQuestions()` hace para autorrellenar
    `SERVER_PUB_NIC`. Se ejecuta en el mismo host que va a correr el script, así que
    el resultado es una confirmación de lo que el script detectaría solo, no una
    suposición externa."""
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):  # pragma: no cover - entorno real
        return None
    tokens = out.stdout.split()
    if "dev" in tokens:
        idx = tokens.index("dev")
        if idx + 1 < len(tokens):
            return tokens[idx + 1]
    return None

# Cómo invocar la desinstalación en cada script — ver la nota de verificación en el
# docstring del módulo. `args` se añaden a la línea de comandos, `env` se añade al
# entorno del proceso, `stdin` (si no es None) se pasa como `input=` a subprocess.run.
_UNINSTALL_INVOCATION: dict[str, dict] = {
    "openvpn": {"args": ["uninstall", "--force"], "env": {}, "stdin": None},
    "wireguard": {"args": [], "env": {"MENU_OPTION": "4"}, "stdin": "y\n"},
}


class BootstrapError(Exception):
    """Error de negocio en la instalación llave en mano."""


def _source(backend: str, settings) -> tuple[str, str]:
    if backend == "openvpn":
        return settings.bootstrap_openvpn_url, settings.bootstrap_openvpn_sha256
    if backend == "wireguard":
        return settings.bootstrap_wireguard_url, settings.bootstrap_wireguard_sha256
    raise BootstrapError(f"Backend no válido: «{backend}».")


def fetch_and_verify(url: str, sha256_expected: str, dest: Path) -> Path:
    """Descarga `url`, comprueba su SHA-256 y lo guarda en `dest` (modo 700)."""
    if not url:
        raise BootstrapError("No hay URL del script configurada.")
    if not sha256_expected:
        raise BootstrapError("No hay SHA-256 configurado: no se ejecuta sin verificar.")
    if not url.startswith(("https://", "file://")):
        raise BootstrapError("La URL debe ser https://.")
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = resp.read()
    except Exception as e:
        raise BootstrapError(f"No se pudo descargar el script: {e}") from e
    actual = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual, sha256_expected.strip().lower()):
        raise BootstrapError(
            "El SHA-256 del script descargado NO coincide con el configurado "
            f"(esperado {sha256_expected[:12]}…, obtenido {actual[:12]}…). No se ejecuta."
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    dest.chmod(0o700)
    return dest


def unattended_env(backend: str, settings) -> dict[str, str]:
    """Variables para ejecutar el script en modo desatendido — ver la nota de
    verificación en el docstring del módulo. Para WireGuard, `SERVER_PUB_NIC` se
    omite del dict si no se pudo detectar (host sin ruta por defecto); `run()`
    comprueba esto explícitamente antes de invocar el script de verdad."""
    if backend == "openvpn":
        return {
            "AUTO_INSTALL": "y", "APPROVE_INSTALL": "y", "APPROVE_IP": "y",
            "IPV6_SUPPORT": "n", "PORT_CHOICE": "1", "PROTOCOL_CHOICE": "1",
            "DNS": "1", "COMPRESSION_ENABLED": "n", "CUSTOMIZE_ENC": "n",
            "CLIENT": "cliente1", "PASS": "1",
            "ENDPOINT": settings.openvpn_public_endpoint,
        }
    env = {
        "SERVER_WG_NIC": settings.wireguard_interface,
        "SERVER_WG_IPV4": _WIREGUARD_DEFAULT_WG_IPV4,
        "SERVER_WG_IPV6": _WIREGUARD_DEFAULT_WG_IPV6,
        "SERVER_PORT": _WIREGUARD_DEFAULT_PORT,
        "CLIENT_DNS_1": settings.wireguard_dns,
        "CLIENT_DNS_2": _WIREGUARD_DEFAULT_DNS_2,
        "ALLOWED_IPS": _WIREGUARD_DEFAULT_ALLOWED_IPS,
        "CLIENT_NAME": _WIREGUARD_DEFAULT_CLIENT_NAME,
        "CLIENT_EXISTS": "0",
    }
    nic = _detect_public_interface()
    if nic is not None:
        env["SERVER_PUB_NIC"] = nic
    return env


def _wireguard_install_stdin(settings) -> str:
    """Las 4 respuestas que `installQuestions()`/`newClient()` piden por stdin sin
    forma de saltarlas por variable de entorno — ver el docstring del módulo para
    el porqué de cada una y por qué ".2" es correcto (no una suposición) en una
    instalación recién creada."""
    lines = [
        settings.wireguard_public_endpoint,  # IPv4 or IPv6 public address
        "",                                   # Press any key to continue...
        "2",                                  # Client WireGuard IPv4 (BASE_IP.2)
        "2",                                  # Client WireGuard IPv6 (BASE_IP::2)
    ]
    return "\n".join(lines) + "\n"


def _install_stdin(backend: str, settings) -> str | None:
    if backend == "wireguard":
        return _wireguard_install_stdin(settings)
    return None


def plan(backend: str, settings) -> dict:
    url, sha = _source(backend, settings)
    return {
        "backend": backend,
        "repo": REPOS.get(backend, ""),
        "url": url,
        "checksum_configured": bool(url and sha),
        "env": unattended_env(backend, settings),
    }


def run(backend: str, settings, sandbox: bool) -> dict:
    url, sha = _source(backend, settings)
    p = plan(backend, settings)
    if not (url and sha):
        raise BootstrapError(
            "Instalación llave en mano no configurada: fija la URL (a un commit) y su "
            "SHA-256 en VPNM_BOOTSTRAP_* para este backend."
        )
    if sandbox:
        return {"installed": False, "simulated": True, "plan": p,
                "detail": "Sandbox: se descargaría y verificaría el script, sin ejecutarlo."}
    if not settings.allow_install:
        raise BootstrapError("Instalación deshabilitada. Activa VPNM_ALLOW_INSTALL=true.")
    if os.geteuid() != 0:
        raise BootstrapError("La instalación requiere ejecutarse como root.")

    backend_env = unattended_env(backend, settings)
    if backend == "wireguard" and "SERVER_PUB_NIC" not in backend_env:
        # Fail-closed explícito en vez de lanzar el script y arriesgarnos a que su
        # `until [[ SERVER_PUB_NIC =~ ... ]]; do read; done` se quede esperando un
        # stdin que nunca íbamos a alimentar (no hay valor seguro que inventar aquí,
        # varía por máquina real) — ver el docstring del módulo.
        raise BootstrapError(
            "No se pudo detectar la interfaz de red pública de este host (sin ruta "
            "por defecto) — la instalación llave en mano de WireGuard no puede "
            "continuar de forma desatendida. Instala manualmente o resuelve la "
            "ruta por defecto antes de reintentar."
        )

    dest = Path(settings.bootstrap_dir) / f"{backend}-install.sh"
    fetch_and_verify(url, sha, dest)  # pragma: no cover - red + root
    env = {**os.environ, **backend_env}
    try:  # pragma: no cover - requiere root
        r = subprocess.run(
            ["bash", str(dest)], env=env, input=_install_stdin(backend, settings),
            capture_output=True, text=True, timeout=900, check=True,
        )
    except subprocess.CalledProcessError as e:  # pragma: no cover
        raise BootstrapError(f"El instalador falló: {e.stderr.strip() or e}") from e
    except (OSError, subprocess.TimeoutExpired) as e:  # pragma: no cover
        raise BootstrapError(f"No se pudo ejecutar el instalador: {e}") from e
    return {"installed": True, "simulated": False, "plan": p, "output": r.stdout[-3000:]}


def uninstall_plan(backend: str, settings) -> dict:
    url, sha = _source(backend, settings)
    invocation = _UNINSTALL_INVOCATION.get(backend)
    if invocation is None:
        raise BootstrapError(f"Backend no válido: «{backend}».")
    return {
        "backend": backend,
        "repo": REPOS.get(backend, ""),
        "url": url,
        "checksum_configured": bool(url and sha),
        "invocation": {
            "command": ["bash", f"{backend}-install.sh", *invocation["args"]],
            "env": invocation["env"],
            "needs_stdin_confirmation": invocation["stdin"] is not None,
        },
    }


def run_uninstall(backend: str, settings, sandbox: bool) -> dict:
    url, sha = _source(backend, settings)
    invocation = _UNINSTALL_INVOCATION.get(backend)
    if invocation is None:
        raise BootstrapError(f"Backend no válido: «{backend}».")
    p = uninstall_plan(backend, settings)
    if not (url and sha):
        raise BootstrapError(
            "Desinstalación llave en mano no configurada: fija la URL (a un commit) y su "
            "SHA-256 en VPNM_BOOTSTRAP_* para este backend."
        )
    if sandbox:
        return {"uninstalled": False, "simulated": True, "plan": p,
                "detail": "Sandbox: se descargaría y verificaría el script, sin ejecutarlo."}
    if not settings.allow_install:
        raise BootstrapError("Desinstalación deshabilitada. Activa VPNM_ALLOW_INSTALL=true.")
    if os.geteuid() != 0:
        raise BootstrapError("La desinstalación requiere ejecutarse como root.")

    dest = Path(settings.bootstrap_dir) / f"{backend}-install.sh"
    fetch_and_verify(url, sha, dest)  # pragma: no cover - red + root
    env = {**os.environ, **invocation["env"]}
    try:  # pragma: no cover - requiere root
        r = subprocess.run(
            ["bash", str(dest), *invocation["args"]],
            env=env, input=invocation["stdin"],
            capture_output=True, text=True, timeout=900, check=True,
        )
    except subprocess.CalledProcessError as e:  # pragma: no cover
        raise BootstrapError(f"El desinstalador falló: {e.stderr.strip() or e}") from e
    except (OSError, subprocess.TimeoutExpired) as e:  # pragma: no cover
        raise BootstrapError(f"No se pudo ejecutar el desinstalador: {e}") from e
    return {"uninstalled": True, "simulated": False, "plan": p, "output": r.stdout[-3000:]}
