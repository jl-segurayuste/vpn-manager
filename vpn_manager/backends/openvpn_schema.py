"""Esquema de las directivas de OpenVPN para el formulario de configuración.

Cada campo describe: clave, etiqueta, descripción, tipo de control (text/number/
select/toggle), opciones (si es desplegable) y validación mínima. La UI lo usa para
pintar el formulario; el backend lo usa para validar antes de escribir el server.conf.
"""
from __future__ import annotations

import re

# type: text | number | select | toggle
FIELDS: list[dict] = [
    {"key": "port", "label": "Puerto", "type": "number", "min": 1, "max": 65535,
     "desc": "Puerto en el que escucha el servidor (por defecto 1194)."},
    {"key": "proto", "label": "Protocolo", "type": "select",
     "options": ["udp", "tcp", "udp6", "tcp6"],
     "desc": "Protocolo de transporte. UDP es lo habitual (más rápido)."},
    {"key": "dev", "label": "Dispositivo", "type": "select", "options": ["tun", "tap"],
     "desc": "tun = enrutado (capa 3, lo normal); tap = puente (capa 2)."},
    {"key": "server", "label": "Rango de IPs (VPN)", "type": "text",
     "pattern": r"^\d{1,3}(\.\d{1,3}){3}\s+\d{1,3}(\.\d{1,3}){3}$",
     "desc": "Red y máscara que reparte la VPN. Ej.: 10.8.0.0 255.255.255.0"},
    {"key": "topology", "label": "Topología", "type": "select",
     "options": ["subnet", "net30", "p2p"],
     "desc": "subnet es la recomendada para clientes modernos."},
    {"key": "data-ciphers", "label": "Cifrados de datos", "type": "text",
     "desc": "Lista de cifrados permitidos, separados por «:». Ej.: AES-256-GCM:AES-128-GCM"},
    {"key": "data-ciphers-fallback", "label": "Cifrado de reserva", "type": "text",
     "desc": "Cifrado para clientes antiguos que no negocian. Ej.: AES-256-GCM"},
    {"key": "auth", "label": "Autenticación (HMAC)", "type": "select",
     "options": ["SHA256", "SHA512", "SHA1"],
     "desc": "Algoritmo de integridad de los paquetes."},
    {"key": "tls-version-min", "label": "TLS mínimo", "type": "select",
     "options": ["1.2", "1.3"],
     "desc": "Versión mínima de TLS aceptada en el canal de control."},
    {"key": "max-clients", "label": "Máx. dispositivos", "type": "number", "min": 1, "max": 100000,
     "desc": "Número máximo de clientes conectados a la vez."},
    {"key": "keepalive", "label": "Keepalive", "type": "text",
     "pattern": r"^\d+\s+\d+$",
     "desc": "Ping y tiempo de espera en segundos. Ej.: 10 120"},
    {"key": "user", "label": "Usuario del proceso", "type": "text",
     "desc": "Usuario al que baja privilegios el demonio. Ej.: nobody"},
    {"key": "group", "label": "Grupo del proceso", "type": "text",
     "desc": "Grupo al que baja privilegios. Ej.: nogroup"},
    {"key": "persist-key", "label": "Conservar claves", "type": "toggle",
     "desc": "No releer las claves al reiniciar el túnel."},
    {"key": "persist-tun", "label": "Conservar túnel", "type": "toggle",
     "desc": "No cerrar el dispositivo tun/tap al reiniciar."},
    {"key": "crl-verify", "label": "Lista de revocación (CRL)", "type": "text",
     "desc": "Ruta del fichero CRL para rechazar certificados revocados."},
    {"key": "verb", "label": "Nivel de log", "type": "number", "min": 0, "max": 11,
     "desc": "Verbosidad de los registros (0 = nada, 3 = normal, 9 = depuración)."},
]

FIELDS_BY_KEY = {f["key"]: f for f in FIELDS}

_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,40}$")


def validate_directive(key: str, value: str) -> str | None:
    """Devuelve un mensaje de error si la directiva no es válida, o None si lo es."""
    if not _KEY_RE.match(key):
        return f"Directiva no válida: «{key}»."
    if "\n" in value or "\r" in value:
        return f"El valor de «{key}» no puede tener saltos de línea."
    field = FIELDS_BY_KEY.get(key)
    if not field:
        return None  # directiva avanzada/desconocida: se acepta tal cual
    t = field["type"]
    if t == "number":
        if not value.strip().lstrip("-").isdigit():
            return f"«{field['label']}» debe ser un número."
        n = int(value)
        if "min" in field and n < field["min"]:
            return f"«{field['label']}» debe ser ≥ {field['min']}."
        if "max" in field and n > field["max"]:
            return f"«{field['label']}» debe ser ≤ {field['max']}."
    elif t == "select" and value and value not in field["options"]:
        return f"«{field['label']}» debe ser uno de: {', '.join(field['options'])}."
    elif (
        t == "text"
        and field.get("pattern")
        and value
        and not re.match(field["pattern"], value.strip())
    ):
        return f"«{field['label']}» no tiene el formato esperado."
    return None
