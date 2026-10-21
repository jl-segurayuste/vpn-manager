# Auditoría de seguridad — VPN Manager

Revisión previa a la publicación en GitHub. Fecha: 2026-06-22.
Alcance: backend (FastAPI), adaptador OpenVPN, autenticación, UI y repositorio.

## Resumen

Estado general: **apto para publicar** una vez aplicado el *hardening* descrito.
No se han encontrado vulnerabilidades críticas explotables en la lógica de la app.
El riesgo principal de una herramienta así (gestiona acceso remoto) está mitigado:
autenticación obligatoria, validación estricta de entrada, sandbox por defecto y
sin material criptográfico en el repo.

## Comprobaciones realizadas y resultado

| Área | Comprobación | Resultado |
|------|--------------|-----------|
| AuthN | Contraseña con PBKDF2-SHA256 (600k it.), comparación en tiempo constante | ✅ |
| AuthN | Sesión en cookie firmada `HttpOnly` + `SameSite=Strict` (+`Secure` en prod) | ✅ |
| AuthN | Login sin cortocircuito (no filtra por tiempo si el usuario existe) | ✅ (corregido) |
| AuthN | Anti–fuerza bruta: bloqueo por IP tras 5 intentos | ✅ |
| AuthN | Renovación de sesión en login (`session.clear()`) | ✅ |
| AuthZ | Todo `/api/*` y `/` exigen sesión; solo `/login` y `/health` públicos | ✅ |
| Config segura | En producción sin contraseña **o** sin `SECRET_KEY`, la app no arranca | ✅ (reforzado) |
| Inyección | Nombre de cliente validado por regex estricta; sin `shell=True` | ✅ |
| Path traversal | Regex prohíbe `/`, y nombres como `.`/`..`; filenames seguros | ✅ |
| Header injection | `Content-Disposition` con nombre ya validado (sin `"`, CR/LF) | ✅ |
| Clickjacking | `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` | ✅ (añadido) |
| MIME sniffing | `X-Content-Type-Options: nosniff` | ✅ (añadido) |
| Fuga por caché | `Cache-Control: no-store` en panel y API | ✅ (añadido) |
| CSP | `default-src 'self'`, sin recursos externos | ✅ (añadido) |
| CORS | Sin CORS permisivo → solo mismo origen | ✅ |
| Secretos en repo | `.gitignore` excluye `.env`, `*.key/crt/pem/ovpn`, configs cliente | ✅ |
| Auditoría | Log de login OK/KO, alta y revocación con usuario e IP | ✅ (añadido) |
| Dependencias | `python-multipart>=0.0.9` (sin la ReDoS antigua) | ✅ |

## Correcciones aplicadas en esta auditoría

1. **Cabeceras de seguridad** en toda respuesta (middleware): `X-Frame-Options`,
   `X-Content-Type-Options`, `Referrer-Policy`, `Cross-Origin-Opener-Policy`,
   `Content-Security-Policy` y `Cache-Control: no-store`.
2. **Login sin fuga temporal**: se evalúan usuario y contraseña sin cortocircuito.
3. **`SECRET_KEY` obligatoria en producción** (antes solo se avisaba).
4. **Registro de auditoría** de acciones sensibles (login, alta, revocación).

## Riesgos residuales / recomendaciones (no bloqueantes)

- **CSP con `'unsafe-inline'`**: la UI usa estilos y scripts en línea. Mitigado por
  `default-src 'self'` (no carga nada externo). *Mejora futura*: mover el JS a un
  fichero y usar CSP con *nonce* (como CyberHound).
- **Un único rol (admin)**. Para varios operadores: usuarios + roles + auditoría por
  usuario (previsto en la Fase 4).
- **Throttle en memoria**: se reinicia con el proceso y es por instancia. Suficiente
  para uso interno; si se escala, mover a almacenamiento compartido.
- **Exposición**: pensado para **acceso interno** detrás del proxy con HTTPS
  (`VPNM_COOKIE_SECURE=true`). No exponer a internet.
- **Al desplegar:** fijar `VPNM_ADMIN_PASSWORD_HASH` real, `VPNM_SECRET_KEY` y
  `VPNM_COOKIE_SECURE=true`.

## Anexo (superficie añadida tras la auditoría inicial)

- **Multiusuario + roles**: permisos exigidos **en el backend** en cada endpoint (no solo
  en la UI). 3 roles; no se puede quedar sin admin ni borrar la propia cuenta. Contraseñas
  PBKDF2; usuario validado por regex. Verificado con tests (operador/visor reciben 403).
- **Instalación y desinstalación de servicios**: alto riesgo en ambos sentidos (actúa
  como root, y desinstalar además es destructivo/irreversible). Mitigado igual que la
  instalación: rol admin (`system:install`) + `VPNM_ALLOW_INSTALL=true` + root;
  **sandbox solo simula**; comandos por lista (sin shell); auditoría. La UI pide
  confirmación **dos veces** antes de una desinstalación completa. `purge=true` (borrar
  también configuración de paquetes) es opt-in explícito, nunca el comportamiento por
  defecto.
- **Instalación/desinstalación llave en mano (angristan)**: descarga **solo `https://`**
  de una **URL fijada a commit** + **verificación SHA-256 obligatoria** (fail-closed sin
  checksum); el script no se incluye en el repo. Mismos interruptores que arriba. La
  invocación de desinstalación (subcomando `uninstall --force` en OpenVPN;
  `MENU_OPTION=4` + confirmación por stdin en WireGuard) se verificó línea a línea contra
  el contenido real de cada commit fijado, no contra la rama `master` de cada proyecto
  (que puede comportarse de forma distinta) — ver el detalle en
  [`INSTALACION.md`](INSTALACION.md).
- **Assets estáticos** (`/assets`): solo logos; servidos por StaticFiles (sin traversal).
- **Entrega de config**: «guardar en servidor» restringido a `export_dir` (anti-traversal);
  «correo» valida la dirección y avisa de que no es canal seguro.
- 2FA (TOTP con anti-repetición) y auditoría persistida en fichero ya están hechos; la
  revocación de sesiones, en la revisión de 2026-10-21 (abajo).

## Revisión de 2026-10-21

| # | Severidad | Hallazgo | Corrección |
|---|---|---|---|
| 1 | **Alta** | **El rol «Solo lectura» descargaba las configuraciones de los clientes** (OpenVPN, WireGuard, QR y paquete de alta disponibilidad), que llevan su clave privada: con ellas se entra en la red. Los endpoints solo pedían sesión. | Permiso nuevo `clients:config` (admin y operador); la UI oculta Descargar, QR y Alta disponibilidad a quien no lo tiene. Test `test_solo_lectura_no_descarga_configuraciones`. |
| 2 | **Media** | **Configurar el 2FA lo desactivaba sin código**: `POST /api/me/2fa/setup` ponía `totp_enabled=False`, así que con una sesión robada se quitaba la verificación (desactivarla sí pide código). | Con el 2FA activo, configurarlo de nuevo devuelve 409: hay que desactivarlo antes con un código. Test `test_configurar_2fa_no_la_desactiva`. |
| 3 | **Media** | **Sesiones sin revocación**: la sesión es una cookie firmada sin estado; tras cambiar la contraseña, una copia robada seguía valiendo hasta caducar. | Versión de sesión por usuario: cambiar la contraseña o el 2FA invalida las demás sesiones (la de quien hace el cambio sigue). Test `test_cambiar_la_contrasena_cierra_las_otras_sesiones`. |
| 4 | Baja | La función de escapado de la UI no escapaba comillas y los nombres de cliente van dentro de `onclick="…('nombre')"`: un CN con comillas creado fuera del panel podía inyectar JavaScript. | `esc()` escapa también `"` y `'`. |

Los tres tests fallan con el código anterior y pasan con el corregido.
