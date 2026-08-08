"""Entrega de configuraciones de cliente: guardar en el servidor o enviar por correo.

Seguridad:
- Guardar: la ruta destino debe quedar DENTRO del directorio permitido
  (`export_dir`) — evita escritura arbitraria y *path traversal*.
- Correo: se valida la dirección; las credenciales SMTP vienen de configuración
  (nunca hardcodeadas). Aviso: el correo no es un canal seguro para claves.
"""
from __future__ import annotations

import re
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$")


class DeliveryError(Exception):
    """Error de negocio al entregar la configuración."""


def save_to_server(content: str, filename: str, dest: str, allowed_base: Path) -> Path:
    """Guarda `content` como `filename` dentro de `dest`, que debe estar bajo `allowed_base`."""
    if not _SAFE_NAME_RE.match(filename):
        raise DeliveryError("Nombre de fichero no válido.")
    allowed_base = allowed_base.resolve()
    # `dest` puede ser relativo (al base) o absoluto; en ambos casos debe caer dentro.
    target_dir = (allowed_base / dest).resolve() if not Path(dest).is_absolute() else Path(dest).resolve()
    if target_dir != allowed_base and allowed_base not in target_dir.parents:
        raise DeliveryError(
            f"La ruta debe estar dentro del directorio permitido: {allowed_base}"
        )
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / filename
    path.write_text(content, encoding="utf-8")
    return path


def validate_email(addr: str) -> str:
    addr = (addr or "").strip()
    if not _EMAIL_RE.match(addr):
        raise DeliveryError("Dirección de correo no válida.")
    return addr


def send_email(content: str, filename: str, to_addr: str, settings, sandbox: bool) -> dict:
    """Envía la config como adjunto. Sin SMTP configurado: simula en sandbox, error en prod."""
    to_addr = validate_email(to_addr)
    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = to_addr
    msg["Subject"] = f"Tu configuración VPN: {filename}"
    msg.set_content(
        "Adjuntamos tu configuración para conectarte a la VPN.\n\n"
        "Importante: trátala como una credencial; no la reenvíes."
    )
    msg.add_attachment(
        content.encode("utf-8"), maintype="application", subtype="octet-stream",
        filename=filename,
    )

    if not settings.smtp_host:
        if sandbox:
            outbox = (settings.export_dir / "outbox")
            outbox.mkdir(parents=True, exist_ok=True)
            eml = outbox / f"{filename}.{to_addr}.eml"
            eml.write_bytes(bytes(msg))
            return {"sent": True, "simulated": True, "to": to_addr}
        raise DeliveryError("SMTP no configurado: define VPNM_SMTP_HOST para enviar correos.")

    try:  # pragma: no cover - requiere servidor SMTP real
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
            if settings.smtp_starttls:
                smtp.starttls(context=ssl.create_default_context())
            if settings.smtp_user:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(msg)
    except Exception as e:
        raise DeliveryError(f"No se pudo enviar el correo: {e}") from e
    return {"sent": True, "simulated": False, "to": to_addr}
