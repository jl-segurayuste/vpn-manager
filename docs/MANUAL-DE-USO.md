# VPN Manager — Manual de uso

Cómo administrar tu servidor VPN desde el panel web. Está pensado para que **alguien
sin conocimientos técnicos** pueda gestionar quién accede a la red, sin usar la línea
de comandos.

> Para instalar, ver el [Manual de instalación](INSTALACION.md).

---

## 1. Entrar al panel

1. Abre el panel en el navegador (por defecto `http://127.0.0.1:8200`).
2. Introduce tu **usuario y contraseña**. En desarrollo: `admin` / `admin`.
3. Para salir, usa **«Cerrar sesión»** abajo en la barra lateral.

La sesión se cierra sola tras un tiempo de inactividad. Tras varios intentos fallidos,
el acceso desde esa IP se bloquea unos minutos.

---

## 2. La barra lateral

- **Emblema y nombre del protocolo** (OpenVPN o WireGuard) con su color de marca,
  según la VPN que estés gestionando.
- **Estado del servicio**: «VPN funcionando» o «VPN detenida».
- **Navegación**: Resumen · Servicio · Configuración · Dispositivos · Conexiones · Registros.
- **Selector OpenVPN / WireGuard**: cambia entre los dos servidores (si ambos están
  configurados).

---

## 3. Resumen

Cuatro indicadores de un vistazo: estado del **servicio**, **accesos activos**,
**conectados ahora** y **caducados/retirados**.

## 4. Servicio

Controla el servidor VPN con botones claros:

- **Recargar**: relee la configuración **sin cortar** a los conectados.
- **Reiniciar**: aplica cambios reiniciando (desconecta un instante a los usuarios).
- **Parar / Arrancar**: detiene o levanta el servicio.

Las acciones que cortan conexiones piden confirmación.

## 5. Configuración del servidor

Muestra todos los parámetros con los que funciona el servidor: **endpoint público,
puerto, protocolo, rango de IPs, cifrados, autenticación, DNS, rutas, CRL** y, con
«Ver toda la configuración», **todas las directivas**.

### Editar la configuración (OpenVPN)

1. Pulsa **«Editar configuración»**.
2. Rellena los campos: cada uno tiene una **descripción**; los de opciones (protocolo,
   dispositivo, autenticación, TLS…) son **desplegables**; el resto, texto o número.
3. En **«Otras directivas (avanzado)»** puedes añadir o quitar cualquier directiva.
4. **«Guardar configuración»**. Si un valor no es válido, te avisa.
5. Después, pulsa **«Recargar»** en la sección Servicio para aplicar los cambios.

## 6. Dispositivos con acceso

Cada persona o dispositivo (portátil, móvil, tablet…) tiene un certificado/clave. Verás
su estado: **Acceso activo**, **Caducado** o **Acceso retirado**.

- **Añadir dispositivo**: pulsa el botón, escribe un nombre (p. ej. `portatil-ana`) y
  **«Crear acceso»**. Se genera su configuración.
- Para cada acceso activo:
  - **Descargar**: descarga el fichero de configuración (`.ovpn` o `.conf`).
  - **Código QR** (WireGuard): muestra un QR para escanear desde la app del móvil.
  - **Guardar en servidor**: guarda la config en una carpeta del servidor (dentro del
    directorio permitido).
  - **Enviar por correo**: envía la config a una dirección de correo.
    > Aviso: el correo no es un canal seguro; trata la configuración como una credencial.
  - **Retirar acceso**: revoca el certificado/clave (deja de poder conectarse).
- **Renovar acceso**: en un dispositivo **caducado**, reemite su certificado.

## 7. Conexiones activas

Quién está usando la VPN ahora mismo, su dirección en la red, desde cuándo y su tráfico.
En OpenVPN puedes **Desconectar** una sesión concreta.

## 8. Registros

Las últimas líneas del registro del servidor, con los errores resaltados. Pulsa
**«Actualizar»** para refrescar.

## 9. Cambiar entre OpenVPN y WireGuard

Si gestionas los dos, usa el **selector** de la barra lateral. El panel cambia los datos,
el logo y el color de marca. En WireGuard, cada dispositivo tiene además un **Código QR**
para escanear desde la app del móvil.

## 10. Usuarios y permisos (solo administradores)

En la página **Usuarios** (solo visible para administradores) gestionas quién entra al
panel y con qué permisos. Hay tres roles:

- **Administrador**: todo, incluida la gestión de usuarios, la edición de la
  configuración del servidor y la instalación de servicios.
- **Operador**: gestiona dispositivos (alta/baja/renovar/entregar config) y controla el
  servicio, pero no edita la configuración del servidor ni gestiona usuarios.
- **Solo lectura**: únicamente consulta; no puede hacer cambios.

Acciones: **Añadir usuario** (usuario + contraseña de 8+ caracteres + rol), **Cambiar
rol**, **Cambiar contraseña** y **Borrar**. No puedes borrarte a ti mismo ni dejar el
sistema sin ningún administrador. Cada usuario ve solo las acciones que su rol permite.

## 11. Sistema, instalación y desinstalación de servicios

La página **Sistema** muestra la **distribución** detectada, su **gestor de paquetes** y
qué servicios VPN están **instalados**. Un administrador puede instalar los que falten, o
desinstalar los que ya no hagan falta — los mismos dos niveles en ambos sentidos:

- **Instalar / Desinstalar paquetes**: instala o quita OpenVPN/WireGuard con el gestor de
  la distro (apt, dnf…). Al desinstalar, la configuración/PKI existente **no se toca**,
  solo los paquetes del sistema.
- **Instalación / Desinstalación completa**: «llave en mano» (configura o retira el
  servidor entero: PKI, `server.conf`, firewall/NAT) usando los scripts de
  [angristan](https://github.com/angristan/openvpn-install), que se **descargan de una
  versión fijada y se verifican por SHA-256** antes de ejecutarse. La desinstalación
  completa **borra la configuración y la PKI** — no se puede deshacer, el panel pide
  confirmación dos veces antes de ejecutarla.

> La acción real (instalar o desinstalar) requiere que el administrador la haya
> habilitado (`VPNM_ALLOW_INSTALL=true`) y que el panel corra como root. En el modo de
> prueba solo se **simula** (muestra el plan). Ver el [Manual de instalación](INSTALACION.md).

---

## 12. Preguntas frecuentes

- **¿Cómo doy acceso a una persona nueva?** Sección Dispositivos → «Añadir dispositivo»
  → escribe el nombre → «Crear acceso» → entrégale su config (descargar / correo / QR).
- **¿Cómo le quito el acceso a alguien?** En su fila, «Retirar acceso». Deja de conectarse
  de inmediato (se revoca y se actualiza la CRL).
- **¿Por qué un dispositivo sale «Caducado»?** Su certificado llegó a su fecha de
  caducidad. Pulsa «Renovar acceso».
- **¿Los datos se actualizan solos?** Sí, el panel se refresca cada 10 segundos.

Para la postura de seguridad del panel, ver [AUDITORIA-SEGURIDAD.md](AUDITORIA-SEGURIDAD.md).
