# VPN Manager — Especificación y hoja de ruta

> Panel web para **gestionar un servidor VPN** (OpenVPN **y** WireGuard) desde una
> interfaz, en lugar de por línea de comandos.
>
> **Estado (verificado contra el código 2026-07-08): completo y publicable.** Este
> documento es la especificación INICIAL (2026-06-21) y quedó desfasado — las fases
> 1-4 están hechas, no solo 1-3 como decían las anotaciones `[HECHO]`/`[EN CURSO]`
> de abajo (multiusuario+roles en `vpn_manager/users.py`, auditoría persistida en
> `vpn_manager/audit.py`, entrega de config en `vpn_manager/delivery.py`, instalador
> multi-distro en `vpn_manager/installer.py`). Solo queda la Fase 5 (despliegue) y
> los logos oficiales (activo gráfico que solo tiene José, ver README de `professional/`).

## 1. Objetivo

Hacer por web todo lo que hoy se hace por CLI en el propio servidor VPN:

- **Clientes / peers**: crear, listar, descargar config (`.ovpn` / `wg.conf`),
  habilitar/deshabilitar, **revocar**.
- **Certificados / claves**: PKI de OpenVPN (CA, server, clientes vía easy-rsa) y
  pares de claves WireGuard; ver caducidades, revocar (CRL).
- **Conexiones activas**: quién está conectado ahora (IP, desde cuándo, tráfico).
  OpenVPN vía `status` / management interface; WireGuard vía `wg show`.
- **Historial**: conexiones/desconexiones a lo largo del tiempo.
- **Estado del servicio**: estado de `openvpn-server@` / `wg-quick@`, arrancar/
  parar/recargar, ver logs.
- **Soporta los dos**: OpenVPN y WireGuard, con un modelo común y adaptadores.
- **Alta disponibilidad**: para un cliente que exista en ambos backends, empaquetar
  su acceso OpenVPN (primario) + el WireGuard homónimo (respaldo) + un script de
  failover en un único ZIP descargable, con el DNS de conmutación ya resuelto.

## 2. Principios de diseño

- **Adaptador por backend VPN**: una interfaz común (`VpnBackend`) con dos
  implementaciones (`OpenVpnBackend`, `WireGuardBackend`). La UI y la API no
  conocen los detalles de cada uno.
- **UX para no-técnicos**: la interfaz debe poder usarla alguien **sin
  conocimientos técnicos**. Elegante y sobria (un solo color de acento, casi sin
  iconos), lenguaje llano en vez de jerga ("Acceso activo / retirado / caducado"
  en lugar de "valid/revoked/expired"; "Dirección en la red" en lugar de "IP
  virtual"). Cada acción de CLI se ofrece como un botón claro con microcopia que
  explique qué hace.
- **Configurable y SEGURO POR DEFECTO en dev**: rutas y servicios configurables
  (`/etc/openvpn`, `/etc/wireguard`, comandos). En **desarrollo apunta a un
  sandbox** (`./sandbox/...`), **NUNCA a un servidor VPN de producción real**.
  Apuntar al servidor real es una decisión explícita de prod.
- **Privilegios mínimos**: las operaciones que requieren root (recargar servicio,
  escribir en `/etc/...`) se acotan; idealmente vía sudoers específicos o una capa
  de ejecución controlada. Nunca `shell=True` con entrada del usuario.

## 3. Seguridad (es gestión de acceso remoto → crítico)

- **[HECHO]** Autenticación: login con contraseña PBKDF2-SHA256 (600k it., comparación
  en tiempo constante) + sesión en cookie firmada (HttpOnly, SameSite=Strict, Secure
  configurable). Todo protegido salvo `/login` y `/health`. Seguro por defecto: en
  producción sin contraseña, no arranca. Anti–fuerza bruta por IP. Hash generable con
  `python -m vpn_manager.hashpw`.
- **[HECHO]** Autorización por rol: tres roles (admin/operador/visor,
  `vpn_manager/users.py`), permisos exigidos en el backend en cada endpoint.
- **[HECHO] Auditoría**: registro persistido (JSON-Lines, `vpn_manager/audit.py`)
  de toda acción sensible (crear/revocar cliente, parar servicio) con usuario,
  hora y resultado.
- **Acceso solo interno** (como CyberHound): nunca expuesto a internet.
- Validación estricta de entrada (nombres de cliente, etc.) → sin inyección de
  comandos. Plantillas de config parametrizadas.
- Las **claves privadas** de cliente se entregan una vez y no se almacenan en claro
  innecesariamente; CRL al revocar.

## 4. Stack (confirmado)

**Python + FastAPI** (encaja con herramientas de sistema: subprocess, parseo de
status, PKI) + UI web ligera servida por la propia API. Coherente con CyberHound.

> **Publicación:** este proyecto **sí se publicará en GitHub** (público, MIT)
> cuando esté todo verificado — a diferencia de FieldFlow. Hasta entonces, commits
> en local sin push y sin atribución a IA.

## 5. Hoja de ruta por fases

1. **[HECHO] Scaffold + adaptador OpenVPN (lectura)**: estado del servicio, listar
   clientes/certs (parseo de la PKI/index), conexiones activas (status file).
2. **[HECHO] Gestión OpenVPN (escritura)**: crear cliente, descargar `.ovpn`,
   revocar (CRL). En **sandbox** (en real delega en easy-rsa). 21 tests verdes.
3. **[HECHO] WireGuard**: adaptador (peers, `wg show`, config, alta/baja, QR) +
   config del servidor editable; selector OpenVPN/WireGuard en el panel.
4. **[HECHO] Extras**: entrega de config (descargar/guardar/correo, `delivery.py`);
   multiusuario + roles (admin/operador/visor) con permisos exigidos en el backend;
   instalación de servicios (paquetes multi-distro, `installer.py`); navegación por
   páginas; historial/auditoría persistida.
5. **[PENDIENTE] Despliegue interno** (cuando José lo diga): apuntar al servidor
   real con privilegios acotados, detrás del proxy interno. Único paso de código
   que falta antes: sustituir los logos placeholder por los oficiales de OpenVPN/
   WireGuard (`vpn_manager/ui/assets/README.md` — activo gráfico que solo tiene José).
6. **[HECHO 2026-07-23] Paquete de alta disponibilidad**: `POST
   /api/ha/clients/{name}/bundle` (`vpn_manager/ha_bundle.py`) + botón "Alta
   disponibilidad" en la vista de OpenVPN del panel. Nace de un fallo real
   encontrado en un failover manual bien probado durante semanas: rompía
   la resolución de nombres internos al conmutar a WireGuard, porque el
   dominio DNS de "solo esto por el túnel" nunca se replicaba en el
   perfil de respaldo. Este paquete genera ambas
   configs + el script de vigilancia juntos desde el primer día, con el
   split-DNS (`PostUp`/`PostDown` de `resolvectl`) ya resuelto en el propio
   `.conf` de WireGuard — no depende de la app en marcha ni de
   NetworkManager. 12 tests nuevos (`tests/test_ha_bundle.py`), CI verde.

## 6. Datos de entorno (verificado 2026-06-21)

- `openvpn` instalado (`/usr/sbin/openvpn`), con `/etc/openvpn/{server,client}`.
- WireGuard **no** instalado (se añadirá `wireguard-tools` para desarrollar su
  adaptador, o se simula en sandbox).
- ⚠️ Ningún servidor OpenVPN **de producción real se toca** en desarrollo autónomo.
