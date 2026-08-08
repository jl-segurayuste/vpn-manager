"""Comprobaciones de seguridad / preparación para producción.

Revisa la configuración en marcha y avisa de ajustes inseguros (credenciales de
desarrollo, clave de sesión efímera, cookies sin Secure tras HTTPS, instalación
habilitada…). Pensado para que el administrador vea de un vistazo qué falta antes
de exponer el panel.
"""
from __future__ import annotations


# level: ok | info | warn
def checks(settings) -> list[dict]:
    out: list[dict] = []

    def add(level: str, message: str) -> None:
        out.append({"level": level, "message": message})

    if settings.sandbox:
        add("info", "Modo sandbox: el panel trabaja con datos de demostración y NO toca el "
                    "servidor VPN real.")
    else:
        add("ok", "Modo producción: gestionando el servidor VPN real.")

    # Contraseña de administrador.
    if settings.admin_password_hash:
        add("ok", "Contraseña de administrador configurada (hash).")
    elif settings.sandbox:
        add("warn", "Usando credenciales de desarrollo «admin/admin». Configura "
                    "VPNM_ADMIN_PASSWORD_HASH (genera con «python -m vpn_manager.hashpw»).")

    # Clave de sesión.
    if settings.secret_key:
        add("ok", "Clave de sesión persistente configurada.")
    else:
        add("warn", "Clave de sesión efímera: las sesiones se pierden al reiniciar. "
                    "Fija VPNM_SECRET_KEY.")

    # Cookies seguras / HTTPS.
    if settings.cookie_secure:
        add("ok", "Cookies seguras (Secure + HSTS) activadas; sírvelo siempre tras HTTPS.")
    elif settings.sandbox:
        add("info", "Cookies sin «Secure» (aceptable en local). Activa VPNM_COOKIE_SECURE=true "
                    "cuando lo sirvas tras HTTPS.")
    else:
        add("warn", "Producción SIN cookies «Secure»: activa VPNM_COOKIE_SECURE=true y sírvelo "
                    "tras HTTPS.")

    # Instalación de servicios.
    if settings.allow_install:
        add("warn", "Instalación de servicios habilitada (VPNM_ALLOW_INSTALL=true): el panel "
                    "puede instalar paquetes como root. Déjalo en false salvo cuando lo uses.")

    return out


def summary_level(items: list[dict]) -> str:
    """Peor nivel del conjunto: warn > info > ok."""
    levels = {item["level"] for item in items}
    if "warn" in levels:
        return "warn"
    if "info" in levels:
        return "info"
    return "ok"
