"""Instalación y desinstalación de los servicios VPN, adaptándose a la distribución
de Linux.

Detecta la distro (`/etc/os-release`) y su gestor de paquetes, y sabe qué paquetes
instalar/quitar para OpenVPN/WireGuard en cada familia. Soporta de forma directa las
dos más usadas (Debian/Ubuntu con apt y RHEL/Fedora con dnf) y, como extra, Arch y
openSUSE.

Seguridad (instala/desinstala como root):
- En **sandbox** NO toca nada: devuelve el plan (modo simulación).
- En **producción** la acción real exige, además del rol admin: `VPNM_ALLOW_INSTALL=true`
  y ejecutarse como root. Comandos por lista (sin shell), con timeout y auditoría. El
  mismo flag gobierna instalar Y desinstalar — ambas cambian el estado del sistema por
  igual, no hay razón para un flag separado.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

BACKENDS = ("openvpn", "wireguard")

# Gestor de paquetes -> cómo instalar (plantilla de comando, sin shell).
_INSTALL_CMD = {
    "apt": ["apt-get", "install", "-y"],
    "dnf": ["dnf", "install", "-y"],
    "yum": ["yum", "install", "-y"],
    "pacman": ["pacman", "-S", "--noconfirm"],
    "zypper": ["zypper", "--non-interactive", "install"],
}
# Gestor de paquetes -> cómo desinstalar. apt distingue remove/purge (purge también
# quita ficheros de configuración de los paquetes, ej. /etc/openvpn); el resto de
# gestores no tienen esa distinción de forma nativa (pacman -Rns ya limpia
# dependencias huérfanas + config; dnf/zypper remove ya se comporta como un purge).
_UNINSTALL_CMD = {
    "apt": ["apt-get", "remove", "-y"],
    "dnf": ["dnf", "remove", "-y"],
    "yum": ["yum", "remove", "-y"],
    "pacman": ["pacman", "-Rns", "--noconfirm"],
    "zypper": ["zypper", "--non-interactive", "remove"],
}
_UNINSTALL_PURGE_CMD = {
    "apt": ["apt-get", "purge", "-y"],
}
# Comando previo de actualización de índices (si aplica).
_UPDATE_CMD = {
    "apt": ["apt-get", "update"],
}
# Paquetes por gestor y backend.
_PACKAGES: dict[str, dict[str, list[str]]] = {
    "apt": {"openvpn": ["openvpn", "easy-rsa"], "wireguard": ["wireguard", "wireguard-tools"]},
    "dnf": {"openvpn": ["openvpn", "easy-rsa"], "wireguard": ["wireguard-tools"]},
    "yum": {"openvpn": ["openvpn", "easy-rsa"], "wireguard": ["wireguard-tools"]},
    "pacman": {"openvpn": ["openvpn", "easy-rsa"], "wireguard": ["wireguard-tools"]},
    "zypper": {"openvpn": ["openvpn", "easy-rsa"], "wireguard": ["wireguard-tools"]},
}
# Mapeo de ID/ID_LIKE de la distro a gestor (respaldo si no se detecta por binario).
_DISTRO_MANAGER = {
    "debian": "apt", "ubuntu": "apt", "linuxmint": "apt", "raspbian": "apt",
    "fedora": "dnf", "rhel": "dnf", "centos": "dnf", "rocky": "dnf", "almalinux": "dnf",
    "arch": "pacman", "manjaro": "pacman",
    "opensuse": "zypper", "sles": "zypper",
}


class InstallError(Exception):
    """Error de negocio en la instalación."""


def _parse_os_release(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line or line.strip().startswith("#"):
            continue
        key, _, value = line.partition("=")
        data[key.strip()] = value.strip().strip('"')
    return data


def detect_distro(os_release: str | Path | None = None) -> dict:
    path = Path(os_release) if os_release else Path("/etc/os-release")
    text = ""
    if isinstance(os_release, str) and "=" in os_release:
        text = os_release  # se pasó el contenido directamente (tests)
    elif path.exists():
        text = path.read_text(encoding="utf-8", errors="replace")
    data = _parse_os_release(text)
    return {
        "id": data.get("ID", "").lower(),
        "id_like": data.get("ID_LIKE", "").lower(),
        "name": data.get("PRETTY_NAME") or data.get("NAME") or "Linux",
    }


def detect_package_manager(distro: dict | None = None) -> str | None:
    # 1) Por binario disponible (lo más fiable).
    for mgr in ("apt-get", "dnf", "yum", "pacman", "zypper"):
        if shutil.which(mgr):
            return "apt" if mgr == "apt-get" else mgr
    # 2) Por ID / ID_LIKE de la distro.
    distro = distro or detect_distro()
    if distro["id"] in _DISTRO_MANAGER:
        return _DISTRO_MANAGER[distro["id"]]
    for like in distro["id_like"].split():
        if like in _DISTRO_MANAGER:
            return _DISTRO_MANAGER[like]
    return None


def _installed_status() -> dict[str, bool]:
    return {
        "openvpn": shutil.which("openvpn") is not None,
        "easyrsa": shutil.which("easyrsa") is not None or Path("/usr/share/easy-rsa").exists(),
        "wireguard": shutil.which("wg") is not None,
    }


def system_info() -> dict:
    distro = detect_distro()
    mgr = detect_package_manager(distro)
    return {
        "distro": distro,
        "package_manager": mgr,
        "supported": mgr in _INSTALL_CMD if mgr else False,
        "is_root": os.geteuid() == 0,
        "installed": _installed_status(),
    }


def install_plan(backend: str, manager: str | None = None) -> dict:
    if backend not in BACKENDS:
        raise InstallError(f"Backend no válido. Usa uno de: {', '.join(BACKENDS)}.")
    mgr = manager or detect_package_manager()
    if not mgr or mgr not in _INSTALL_CMD:
        return {"backend": backend, "supported": False, "package_manager": mgr,
                "packages": [], "commands": []}
    packages = list(_PACKAGES[mgr][backend])
    # RHEL/Fedora: OpenVPN vive en EPEL en RHEL y derivados.
    distro = detect_distro()
    if backend == "openvpn" and mgr in ("dnf", "yum") and "fedora" not in distro["id"]:
        packages = ["epel-release", *packages]
    commands = []
    if mgr in _UPDATE_CMD:
        commands.append(_UPDATE_CMD[mgr])
    commands.append([*_INSTALL_CMD[mgr], *packages])
    return {"backend": backend, "supported": True, "package_manager": mgr,
            "packages": packages, "commands": commands}


def install(backend: str, sandbox: bool, allow_install: bool, timeout: int = 600) -> dict:
    plan = install_plan(backend)
    if not plan["supported"]:
        raise InstallError(
            "No se reconoce el gestor de paquetes de esta distribución; instala "
            f"{backend} manualmente."
        )
    if sandbox:
        return {"installed": False, "simulated": True, "plan": plan,
                "detail": "Sandbox: no se instala nada; este es el plan que se ejecutaría."}
    if not allow_install:
        raise InstallError(
            "Instalación deshabilitada. Activa VPNM_ALLOW_INSTALL=true para permitirla."
        )
    if os.geteuid() != 0:
        raise InstallError("La instalación requiere ejecutarse como root.")
    output = []
    for cmd in plan["commands"]:  # pragma: no cover - requiere root + paquetes reales
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True)
            output.append(r.stdout[-2000:])
        except subprocess.CalledProcessError as e:
            raise InstallError(f"«{' '.join(cmd)}» falló: {e.stderr.strip() or e}") from e
        except (OSError, subprocess.TimeoutExpired) as e:
            raise InstallError(f"No se pudo ejecutar «{' '.join(cmd)}»: {e}") from e
    return {"installed": True, "simulated": False, "plan": plan, "output": "\n".join(output)}


def uninstall_plan(backend: str, manager: str | None = None, purge: bool = False) -> dict:
    if backend not in BACKENDS:
        raise InstallError(f"Backend no válido. Usa uno de: {', '.join(BACKENDS)}.")
    mgr = manager or detect_package_manager()
    if not mgr or mgr not in _UNINSTALL_CMD:
        return {"backend": backend, "supported": False, "package_manager": mgr,
                "packages": [], "commands": [], "purge": purge}
    # A diferencia de install_plan, nunca se incluye epel-release aquí: es un
    # repositorio compartido por todo el sistema, no algo propio de este backend —
    # quitarlo al desinstalar OpenVPN podría romper cualquier otro paquete que
    # dependa de EPEL sin relación alguna con la VPN.
    packages = [p for p in _PACKAGES[mgr][backend] if p != "epel-release"]
    cmd_template = _UNINSTALL_PURGE_CMD.get(mgr) if purge else None
    cmd_template = cmd_template or _UNINSTALL_CMD[mgr]
    commands = [[*cmd_template, *packages]]
    return {"backend": backend, "supported": True, "package_manager": mgr,
            "packages": packages, "commands": commands, "purge": purge}


def uninstall(
    backend: str, sandbox: bool, allow_install: bool, purge: bool = False, timeout: int = 600
) -> dict:
    plan = uninstall_plan(backend, purge=purge)
    if not plan["supported"]:
        raise InstallError(
            "No se reconoce el gestor de paquetes de esta distribución; desinstala "
            f"{backend} manualmente."
        )
    if sandbox:
        return {"uninstalled": False, "simulated": True, "plan": plan,
                "detail": "Sandbox: no se desinstala nada; este es el plan que se ejecutaría."}
    if not allow_install:
        raise InstallError(
            "Desinstalación deshabilitada. Activa VPNM_ALLOW_INSTALL=true para permitirla."
        )
    if os.geteuid() != 0:
        raise InstallError("La desinstalación requiere ejecutarse como root.")
    output = []
    for cmd in plan["commands"]:  # pragma: no cover - requiere root + paquetes reales
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True)
            output.append(r.stdout[-2000:])
        except subprocess.CalledProcessError as e:
            raise InstallError(f"«{' '.join(cmd)}» falló: {e.stderr.strip() or e}") from e
        except (OSError, subprocess.TimeoutExpired) as e:
            raise InstallError(f"No se pudo ejecutar «{' '.join(cmd)}»: {e}") from e
    return {"uninstalled": True, "simulated": False, "plan": plan, "output": "\n".join(output)}
