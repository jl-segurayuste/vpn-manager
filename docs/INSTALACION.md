# VPN Manager — Manual de instalación

Guía para instalar y poner en marcha VPN Manager, tanto en **desarrollo** (modo
sandbox, sin tocar ningún servidor real) como en **producción** (gestionando un
servidor OpenVPN y/o WireGuard real).

> Principio de seguridad: por defecto la aplicación trabaja contra `./sandbox/` y
> **nunca** toca el sistema. Apuntar a un servidor real es una decisión explícita por
> configuración.

---

## 1. Requisitos

- **Python 3.11 o superior**.
- En producción, en la misma máquina que el servidor VPN:
  - OpenVPN + **easy-rsa** (para la PKI) si se gestiona OpenVPN.
  - **wireguard-tools** (`wg`, `wg-quick`) si se gestiona WireGuard.
  - Permisos para leer/escribir la configuración del servidor y ejecutar
    `systemctl` sobre el servicio (normalmente vía `sudo`/unidad systemd).

---

## 2. Instalación en desarrollo (sandbox)

```bash
git clone https://github.com/jl-segurayuste/vpn-manager.git
cd vpn-manager
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Arranca el panel (modo sandbox por defecto)
python -m vpn_manager
```

- Panel en **http://127.0.0.1:8200**.
- Credenciales de desarrollo: **admin / admin** (aviso en el log; cámbialas para prod).
- Trabaja contra `./sandbox/` con datos de demostración; no toca nada del sistema.

### Pruebas y calidad

```bash
pytest -q          # 65 pruebas
ruff check .       # estilo
```

---

## 3. Configuración (variables de entorno)

Copia `.env.example` a `.env` y ajusta. Todas las variables llevan prefijo `VPNM_`.

### Generales y autenticación

| Variable | Por defecto | Descripción |
|----------|-------------|-------------|
| `VPNM_SANDBOX` | `true` | `false` para gestionar el servidor real. |
| `VPNM_ADMIN_USER` | `admin` | Usuario administrador. |
| `VPNM_ADMIN_PASSWORD_HASH` | *(vacío)* | Hash PBKDF2. **Obligatorio en producción.** Genera con `python -m vpn_manager.hashpw`. |
| `VPNM_SECRET_KEY` | *(vacío)* | Clave de firma de sesión. **Obligatoria en producción** (`python -c "import secrets;print(secrets.token_hex(32))"`). |
| `VPNM_COOKIE_SECURE` | `false` | `true` detrás de HTTPS. |

### OpenVPN

| Variable | Por defecto (sandbox) |
|----------|------------------------|
| `VPNM_OPENVPN_PKI_INDEX` | `sandbox/openvpn/pki/index.txt` → real: `/etc/openvpn/server/pki/index.txt` |
| `VPNM_OPENVPN_STATUS_FILE` | `sandbox/openvpn/openvpn-status.log` → real: el `status` del servidor |
| `VPNM_OPENVPN_LOG_FILE` | `sandbox/openvpn/openvpn.log` |
| `VPNM_OPENVPN_SERVER_CONF` | `sandbox/openvpn/server.conf` → real: `/etc/openvpn/server/server.conf` |
| `VPNM_OPENVPN_SERVICE` | `openvpn-server@server` |
| `VPNM_OPENVPN_PUBLIC_ENDPOINT` | `vpn.ejemplo.local` (IP/dominio público que va en el `.ovpn`) |

### WireGuard

| Variable | Por defecto (sandbox) |
|----------|------------------------|
| `VPNM_WIREGUARD_CONF` | `sandbox/wireguard/wg0.conf` → real: `/etc/wireguard/wg0.conf` |
| `VPNM_WIREGUARD_SHOW_FILE` | `sandbox/wireguard/wg-show.txt` (en real se usa `wg show`) |
| `VPNM_WIREGUARD_INTERFACE` | `wg0` |
| `VPNM_WIREGUARD_PUBLIC_ENDPOINT` | `vpn.ejemplo.local` |
| `VPNM_WIREGUARD_DNS` | `1.1.1.1` |

### Instalación y desinstalación de servicios (la app instala/quita OpenVPN/WireGuard)

| Variable | Por defecto | Descripción |
|----------|-------------|-------------|
| `VPNM_ALLOW_INSTALL` | `false` | Interruptor de seguridad. `true` para permitir instalar **o desinstalar** (además, el panel debe correr como **root**). Un único flag gobierna ambos sentidos. |
| `VPNM_BOOTSTRAP_OPENVPN_URL` | *(pineado a commit `935e559…`)* | URL del script de angristan **fijada a un commit** (`…/<COMMIT>/openvpn-install.sh`). |
| `VPNM_BOOTSTRAP_OPENVPN_SHA256` | *(pineado)* | SHA-256 de ese script. **Sin él no se ejecuta.** Re-pinear: `curl -sL <url> \| sha256sum`. |
| `VPNM_BOOTSTRAP_WIREGUARD_URL` / `_SHA256` | *(pineado a `832fb98…`)* | Igual para WireGuard (`angristan/wireguard-install`). |

> Los defaults vienen **pineados a un commit concreto de angristan + su SHA-256** (verificados
> el 2026-06-28). Para usar otra versión, sobrescribe URL **y** hash con `VPNM_BOOTSTRAP_*`.

- **Instalar / Desinstalar paquetes**: detecta la distro (apt/dnf/yum/pacman/zypper) e
  instala o quita los paquetes. En RHEL/derivados añade EPEL para OpenVPN al instalar
  (nunca se quita al desinstalar: es un repositorio compartido del sistema, no algo
  propio de la VPN). Desinstalar admite `purge=true` (solo con efecto real en apt) para
  también borrar los ficheros de configuración de los paquetes.
- **Instalación / Desinstalación completa (llave en mano)**: descarga el script de
  angristan de la versión fijada, **verifica su SHA-256** y lo ejecuta. Al instalar
  configura PKI + `server.conf` + firewall + primer cliente; al desinstalar los retira
  todos. En sandbox ambas direcciones solo se **simulan**.

  La forma de invocar tanto instalar como desinstalar difiere por backend, según lo
  que el script realmente soporta en el commit fijado (verificado línea a línea
  contra ambos, no contra `master`):
  - **OpenVPN**: el propio script ya trae subcomandos (`uninstall --force` para
    desinstalar) completamente desatendidos de fábrica — no necesita variables de
    entorno ni stdin más allá de las ya documentadas para instalar.
  - **WireGuard**: sigue siendo un script de menú interactivo antiguo, sin
    subcomandos. Para desinstalar, `MENU_OPTION=4` salta el menú y se alimenta
    `"y\n"` por stdin para la confirmación final, que el script pide siempre sin
    excepción. Para **instalar**, la variable `AUTO_INSTALL=y` que este proyecto
    usaba antes **no existe realmente en el script fijado** (`832fb98…`) — ese
    hallazgo llevó a mapear línea a línea todo `installQuestions()` +
    `newClient()` (esta última se ejecuta automáticamente al final, no hay forma
    de saltarla) y construir la automatización real:
    - Las preguntas protegidas por un `until <regex-válida>; do read; done` se
      saltan fijando la variable correspondiente por entorno de antemano
      (interfaz WireGuard, IPv4/IPv6 del servidor, puerto — `51820`, el estándar
      de WireGuard, en vez del aleatorio que ofrece el script —, DNS, rango de
      IPs permitidas, y el nombre + "no existe todavía" del primer cliente).
    - Dos preguntas son lecturas incondicionales que ignoran cualquier variable
      ya exportada (la IP/dominio público, y "Press any key to continue..."):
      se alimentan por stdin.
    - Dos más, del alta automática del primer cliente, combinan validación con
      un cálculo real dentro del propio bucle — saltarlas por variable dejaría
      la IP del cliente vacía. Se responde por stdin con `"2"` (el primer hueco
      libre, `.1` es el propio servidor — determinista en una instalación
      recién creada, no una suposición).
    - La interfaz de red pública (`SERVER_PUB_NIC`) no se fija a un valor
      inventado: se detecta en Python en el mismo host, justo antes de invocar
      el script (mismo cálculo que hace el propio script). Si no se puede
      detectar, la instalación **falla explícitamente antes de lanzar el
      script**, en vez de arriesgarse a un proceso colgado esperando un stdin
      que nunca llegaría.

    Verificado en vivo contra un host real (detección de interfaz correcta,
    variables de entorno y stdin exactos) y con tests que interceptan
    `subprocess.run` para fijar la invocación exacta — pero **no se ha
    ejecutado el script de angristan de verdad de principio a fin** (instalaría
    WireGuard, paquetes y reglas de firewall reales; ese último tramo solo
    puede probarse de forma responsable en un servidor real desechable, no en
    una máquina de desarrollo).

### Entrega de configuraciones (guardar / correo)

| Variable | Por defecto | Descripción |
|----------|-------------|-------------|
| `VPNM_EXPORT_DIR` | `sandbox/exports` | Directorio **permitido** para guardar configs (anti–traversal). |
| `VPNM_SMTP_HOST` | *(vacío)* | Servidor SMTP. Si está vacío, en sandbox se simula el envío. |
| `VPNM_SMTP_PORT` | `587` | |
| `VPNM_SMTP_USER` / `VPNM_SMTP_PASSWORD` | *(vacío)* | Credenciales SMTP. |
| `VPNM_SMTP_FROM` | `vpn-manager@localhost` | Remitente. |
| `VPNM_SMTP_STARTTLS` | `true` | STARTTLS. |

---

## 3.bis. Con Docker

Imagen multi-stage que corre como **usuario sin privilegios** (uid 10001), con
*healthcheck* incluido.

```bash
docker build -t vpn-manager .
docker run -p 8200:8200 vpn-manager        # demo (sandbox), admin/admin
# o con compose (volumen para usuarios/auditoría, read-only, cap_drop ALL):
docker compose up -d
```

Para **producción** pasa las variables al contenedor (`-e` o el bloque `environment`
del compose): `VPNM_SANDBOX=false`, las rutas reales (monta `/etc/openvpn`,
`/etc/wireguard` como volúmenes), `VPNM_ADMIN_PASSWORD_HASH`, `VPNM_SECRET_KEY` y
`VPNM_COOKIE_SECURE=true`. Para **instalar/gestionar el servicio del host** desde el
contenedor harían falta privilegios adicionales; valora ejecutarlo nativo (systemd)
en ese caso.

## 4. Despliegue en producción (interno)

> Recomendado: acceso **solo interno**, detrás de un proxy con HTTPS. No exponer a internet.

1. **Instala** en la máquina del servidor VPN (o con acceso a sus ficheros/servicio):
   ```bash
   python -m venv /opt/vpn-manager/.venv
   /opt/vpn-manager/.venv/bin/pip install -e /opt/vpn-manager
   ```
2. **Crea el `.env`** con `VPNM_SANDBOX=false`, las rutas reales, el hash de contraseña
   (`python -m vpn_manager.hashpw`), `VPNM_SECRET_KEY` y `VPNM_COOKIE_SECURE=true`.
3. **Unidad systemd** (ejemplo `/etc/systemd/system/vpn-manager.service`):
   ```ini
   [Unit]
   Description=VPN Manager
   After=network.target

   [Service]
   WorkingDirectory=/opt/vpn-manager
   EnvironmentFile=/opt/vpn-manager/.env
   ExecStart=/opt/vpn-manager/.venv/bin/python -m vpn_manager
   Restart=on-failure
   # Permisos acotados: solo lo necesario para gestionar el servicio VPN.

   [Install]
   WantedBy=multi-user.target
   ```
   ```bash
   sudo systemctl daemon-reload && sudo systemctl enable --now vpn-manager
   ```
4. **Proxy inverso + HTTPS** (Caddy/Nginx) delante, en la red interna.
5. **Permisos:** para arrancar/parar el servicio y editar la config, la cuenta del
   servicio necesita acceso (vía `sudoers` acotado o capacidades concretas). Concede
   lo mínimo imprescindible.

---

## 5. Verificación post-instalación

- `GET /health` responde `{"status":"ok","sandbox":false}`.
- El login con tu contraseña real funciona; admin/admin **no** (no hay default en prod).
- En el panel, la sección **Configuración** muestra los parámetros reales del servidor.

Consulta el [Manual de uso](MANUAL-DE-USO.md) para el día a día, y
[AUDITORIA-SEGURIDAD.md](AUDITORIA-SEGURIDAD.md) para la postura de seguridad.
