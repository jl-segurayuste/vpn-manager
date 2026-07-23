# VPN Manager

![CI](https://github.com/jl-segurayuste/vpn-manager/actions/workflows/ci.yml/badge.svg)

Panel web para **administrar un servidor VPN** (OpenVPN y WireGuard) desde una interfaz
sencilla, en lugar de por línea de comandos. Pensado para que **alguien sin conocimientos
técnicos** pueda gestionar quién tiene acceso a la red: dar de alta dispositivos, descargar
su configuración y retirarles el acceso.

## Características

- **Resumen**: totales de accesos activos, conectados y caducados/retirados.
- **Personas con acceso**: lista de certificados/clientes con su estado en lenguaje
  llano (*acceso activo*, *retirado*, *caducado*) y fecha de caducidad.
- **Alta de acceso**: crea un nuevo cliente y genera su fichero de configuración.
- **Descarga de configuración** (`.ovpn`) de cada acceso activo.
- **Retirar acceso**: revoca el certificado y regenera la CRL.
- **Renovar acceso**: reemite el certificado de un dispositivo caducado.
- **Configuración del servidor**: endpoint público, puerto, protocolo, **rango de
  IPs**, **cifrados**, autenticación, DNS y rutas empujadas, CRL… y todas las
  directivas del `server.conf`.
- **Control del servicio**: arrancar, parar, reiniciar y recargar el servidor.
- **Desconectar** una sesión activa.
- **Registros**: últimas líneas del log del servidor VPN.
- **Conexiones en tiempo real**: quién está conectado, desde cuándo y su tráfico.
- **Interfaz de escritorio** (no móvil) con barra lateral, y **marca por protocolo**:
  emblema y color según la VPN activa (OpenVPN en naranja, WireGuard en granate).
- **Paquete de alta disponibilidad** (`POST /api/ha/clients/{name}/bundle`): si un
  mismo cliente existe en ambos backends, empaqueta en un único ZIP su acceso
  primario (OpenVPN) + un respaldo WireGuard + un script de vigilancia que
  conmuta solo si el primario deja de responder de verdad. Genera también el
  DNS de conmutación correcto (split-DNS vía `PostUp`/`PostDown`) para que los
  nombres internos sigan resolviendo tras el failover — ver
  [`vpn_manager/ha_bundle.py`](vpn_manager/ha_bundle.py).

## Seguridad

- **Autenticación obligatoria.** Login con contraseña (**PBKDF2-SHA256**, 600k
  iteraciones, comparación en tiempo constante) y sesión en **cookie firmada**
  (`HttpOnly`, `SameSite=Strict`, `Secure` configurable). Todo el panel y la API
  requieren sesión; solo `/login` y `/health` son públicos.
- **Seguro por defecto.** En producción sin `VPNM_ADMIN_PASSWORD_HASH`, la app
  **se niega a arrancar**. En sandbox usa la credencial de desarrollo `admin/admin`
  mostrando un aviso.
- **Anti–fuerza bruta**: bloqueo temporal por IP tras varios intentos fallidos.
- **Sandbox por defecto.** En desarrollo apunta a `./sandbox/`, **nunca** a un
  servidor VPN real. Apuntar a producción es una decisión explícita por
  configuración (`VPNM_SANDBOX=false` + rutas reales).
- **Validación estricta de nombres** (`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`) para
  evitar inyección de comandos y *path traversal*.
- El certificado del **servidor** está protegido (no se puede crear ni revocar).
- Las operaciones reales delegan en `easy-rsa` mediante `subprocess` **sin shell**.
- El material criptográfico real está excluido del repositorio (ver `.gitignore`).

## Documentación

- [Manual de instalación](docs/INSTALACION.md) — dev (sandbox) y producción.
- [Manual de uso](docs/MANUAL-DE-USO.md) — el día a día del panel.
- [Especificación y hoja de ruta](docs/ESPECIFICACION.md) · [Auditoría de seguridad](docs/AUDITORIA-SEGURIDAD.md)

## Puesta en marcha

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m vpn_manager           # http://127.0.0.1:8200
```

En desarrollo (sandbox) entra con **admin / admin**. Para producción, copia
`.env.example` a `.env`, genera tu contraseña con `python -m vpn_manager.hashpw`
y fija `VPNM_SECRET_KEY`.

## Tests

```bash
pytest -q                              # pruebas unitarias/integración (parsers, API, auth, roles…)
ruff check .
pip install -e ".[e2e]" && pytest e2e/ # e2e de la interfaz en navegador (Playwright)
```

## API

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET`  | `/` | Panel web (requiere sesión) |
| `GET`/`POST` | `/login` | Página y envío de login |
| `POST` | `/logout` | Cierra la sesión |
| `GET`  | `/health` | Estado del servicio y modo sandbox (público) |
| `GET`  | `/api/openvpn/status` | Estado del servidor OpenVPN |
| `GET`  | `/api/openvpn/clients` | Lista de clientes/certificados |
| `GET`  | `/api/openvpn/connections` | Conexiones activas |
| `POST` | `/api/openvpn/clients` | Alta de cliente `{"name": "..."}` |
| `POST` | `/api/openvpn/clients/{name}/revoke` | Retira el acceso |
| `POST` | `/api/openvpn/clients/{name}/renew` | Renueva (reemite) el certificado |
| `GET`  | `/api/openvpn/clients/{name}/config` | Descarga el `.ovpn` |
| `POST` | `/api/openvpn/clients/{name}/save` | Guarda la config en una ruta del servidor |
| `POST` | `/api/openvpn/clients/{name}/email` | Envía la config por correo |
| `*`    | `/api/wireguard/*` | Equivalente para WireGuard (+ `/clients/{name}/qr`) |
| `POST` | `/api/openvpn/connections/{name}/disconnect` | Corta la conexión activa |
| `GET`  | `/api/openvpn/server` | Configuración del servidor (rangos, cifrados, DNS…) |
| `GET`  | `/api/openvpn/logs` | Últimas líneas del registro (`?lines=80`) |
| `POST` | `/api/openvpn/service/{action}` | `start`/`stop`/`restart`/`reload` |
| `POST` | `/api/ha/clients/{name}/bundle` | ZIP de alta disponibilidad (requiere el cliente ya creado en ambos backends) |

## Configuración

Variables de entorno con prefijo `VPNM_` (ver `vpn_manager/config.py`):
`VPNM_SANDBOX`, `VPNM_OPENVPN_PKI_INDEX`, `VPNM_OPENVPN_STATUS_FILE`,
`VPNM_OPENVPN_SERVICE`, etc.

## Hoja de ruta

- [x] **Fase 1** — OpenVPN, solo lectura (estado, clientes, conexiones).
- [x] **Fase 2** — OpenVPN, escritura (alta, revocación, descarga de config).
- [x] **Fase 3** — WireGuard (peers, claves, `wg show`, QR, configuración editable).
- [x] **Fase 4** — Historial y auditoría (página «Actividad», registro persistente).
- [ ] **Fase 5** — Despliegue interno. *(Autenticación, 2FA, hardening y HTTPS-ready ya hechos; falta desplegarlo y validarlo en vivo contra un servidor WireGuard real.)*

Detalle completo en [`docs/ESPECIFICACION.md`](docs/ESPECIFICACION.md).

## Licencia

MIT — ver [`LICENSE`](LICENSE).
