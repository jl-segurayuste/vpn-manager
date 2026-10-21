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
> los logos oficiales de OpenVPN y WireGuard (no se incluyen en el repo).

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
5. **[PENDIENTE] Despliegue interno**: apuntar al servidor
   real con privilegios acotados, detrás del proxy interno. Único paso de código
   que falta antes: sustituir los logos placeholder por los oficiales de OpenVPN/
   WireGuard (`vpn_manager/ui/assets/README.md`; no se distribuyen con el repo).
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
7. **[HECHO 2026-08-08] Desinstalación, en los dos niveles ya existentes de
   instalación** — el panel se declaraba equivalente a la CLI pero no tenía
   forma de desinstalar nada; se añadió al revisar el proyecto antes de
   publicarlo. `installer.py` gana `uninstall_plan()`/
   `uninstall()` (mismo modelo de seguridad que instalar: sandbox simula,
   `VPNM_ALLOW_INSTALL=true` + root en real, `purge=true` opcional para
   también borrar configuración de paquetes en apt). `bootstrap.py` gana
   `uninstall_plan()`/`run_uninstall()` para la vía llave en mano, con la
   invocación exacta **verificada línea a línea contra el contenido real de
   cada commit ya fijado** (no contra `master`, que puede diferir): OpenVPN
   (`935e559…`) ya trae un subcomando `uninstall --force` desatendido de
   fábrica; WireGuard (`832fb98…`) sigue siendo un menú interactivo antiguo,
   requiere `MENU_OPTION=4` (salta el menú, un `until` ya lo comprueba antes
   de leer de stdin) + `"y\n"` por stdin (la confirmación de `uninstallWg()`
   es una lectura incondicional que un `REMOVE` pre-exportado no puede
   saltarse). Botones "Desinstalar paquetes"/"Desinstalación completa" en la
   página Sistema, visibles solo cuando el servicio ya está instalado,
   doble `confirm()` en la vía completa por ser irreversible. 14 tests
   nuevos, dos de ellos interceptando `subprocess.run` para fijar la línea
   de comandos/entorno/stdin exactos por backend (no solo que "no lance
   excepción"). Verificado también en vivo contra el servidor real
   (`curl` a los 4 endpoints nuevos, sandbox), no solo con tests.

8. **[HECHO 2026-08-09] Instalación llave en mano de WireGuard, realmente
   desatendida** — el panel tiene que ser 100% equivalente a la CLI, sin
   excepciones; cerraba el hallazgo dejado pendiente en el punto
   anterior. `AUTO_INSTALL=y` (lo que `unattended_env()` usaba antes para
   WireGuard) no existe en el commit realmente fijado (`832fb98…`) — ese
   camino probablemente nunca había completado un arranque desatendido de
   verdad, se quedaba esperando la primera pregunta interactiva
   indefinidamente. Arreglado mapeando línea a línea todo
   `installQuestions()` + `newClient()` (esta última se ejecuta
   automáticamente al final de la instalación, no hay forma de saltarla):
   - Las preguntas protegidas por `until <regex-válida>; do read; done` se
     saltan fijando la variable correspondiente por entorno de antemano —
     interfaz WireGuard, IPv4/IPv6 del servidor, puerto (51820, el estándar
     de WireGuard, no el aleatorio que ofrece el script), DNS, rango de IPs,
     y nombre + "no existe todavía" del primer cliente (`CLIENT_EXISTS=0` es
     seguro de fijar a ciegas: solo se alcanza en una instalación recién
     creada, sin clientes previos posibles).
   - Dos preguntas son lecturas incondicionales que ignoran cualquier
     variable ya exportada (IP/dominio público, "Press any key to
     continue..."): se alimentan por stdin.
   - Dos más, del alta automática del primer cliente, combinan validación
     con un cálculo real dentro del propio cuerpo del bucle — saltarlas por
     variable dejaría la IP del cliente vacía. Se responde por stdin con
     `"2"` (primer hueco libre tras el propio servidor, determinista en una
     instalación recién creada, no una suposición).
   - `SERVER_PUB_NIC` (interfaz de red pública) nunca se inventa: se detecta
     en Python en el mismo host (`_detect_public_interface()`, sin
     `shell=True`, replica la misma consulta de ruta por defecto que hace el
     propio script) justo antes de invocarlo. Si no se puede detectar, la
     instalación falla explícitamente ANTES de lanzar el script, en vez de
     arriesgarse a un `until` colgado esperando un stdin que nunca llegaría.

   7 tests nuevos (detección de interfaz mockeada y casos límite, contenido
   exacto de variables de entorno y stdin, fallo explícito sin interfaz,
   invocación completa de `subprocess.run` interceptada). Verificado en vivo
   contra un host real: `_detect_public_interface()` devolvió correctamente
   la interfaz WiFi real de la máquina de desarrollo, y `GET
   /api/system/bootstrap/wireguard/plan` mostró el entorno completo y
   correcto vía la API real, no solo en tests. **No se ejecutó el script de
   angristan de principio a fin** (instalaría WireGuard, paquetes y reglas de
   firewall reales en la máquina) — ese último tramo solo puede verificarse
   de forma responsable en un servidor real desechable, documentado como tal
   en `INSTALACION.md`, no una carencia oculta.

## 6. Datos de entorno (verificado 2026-06-21)

## 6. Datos de entorno (verificado 2026-06-21)

- `openvpn` instalado (`/usr/sbin/openvpn`), con `/etc/openvpn/{server,client}`.
- WireGuard **no** instalado (se añadirá `wireguard-tools` para desarrollar su
  adaptador, o se simula en sandbox).
- ⚠️ Ningún servidor OpenVPN **de producción real se toca** en desarrollo autónomo.
