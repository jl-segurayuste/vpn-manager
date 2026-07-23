"""API FastAPI del VPN Manager.

Fase 1: lectura de OpenVPN (estado, clientes, conexiones).
Fase 2: escritura de OpenVPN (alta, revocación, descarga de configuración).
Autenticación: login con sesión en cookie firmada; todo protegido salvo /login
y /health.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

from .. import audit, auth, bootstrap, delivery, ha_bundle, installer, preflight, totp, users
from ..backends.base import (
    AlreadyExists,
    Forbidden,
    InvalidName,
    NotFound,
    ServerInfo,
    ServiceStatus,
    VpnClient,
    VpnConnection,
    VpnError,
)
from ..backends.openvpn import OpenVpnBackend
from ..backends.wireguard import WireGuardBackend
from ..config import settings

_UI = Path(__file__).resolve().parent.parent / "ui"
log = logging.getLogger("vpn_manager.audit")
# Persiste en fichero todo lo que se registre en el logger de auditoría.
audit.attach("vpn_manager.audit", settings.audit_file)

# Cabeceras de seguridad aplicadas a toda respuesta.
_SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",  # anti-clickjacking
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
    ),
}

# Credenciales y clave de sesión resueltas una vez al arrancar.
_ADMIN_USER, _ADMIN_HASH = auth.resolve_credentials(
    settings.admin_user, settings.admin_password_hash, settings.sandbox
)
_throttle = auth.LoginThrottle()
# Almacén de usuarios del panel (multiusuario + roles); siembra el admin de config.
_users = users.UserStore(settings.users_file, _ADMIN_USER, _ADMIN_HASH, "admin")


def _openvpn() -> OpenVpnBackend:
    return OpenVpnBackend(
        pki_index=settings.openvpn_pki_index,
        status_file=settings.openvpn_status_file,
        service=settings.openvpn_service,
        sandbox=settings.sandbox,
        log_file=settings.openvpn_log_file,
        server_conf=settings.openvpn_server_conf,
        public_endpoint=settings.openvpn_public_endpoint,
    )


def _wireguard() -> WireGuardBackend:
    return WireGuardBackend(
        conf=settings.wireguard_conf,
        show_file=settings.wireguard_show_file,
        service=f"wg-quick@{settings.wireguard_interface}",
        sandbox=settings.sandbox,
        interface=settings.wireguard_interface,
        log_file=settings.wireguard_log_file,
        public_endpoint=settings.wireguard_public_endpoint,
        dns=settings.wireguard_dns,
    )


def _http(exc: VpnError) -> HTTPException:
    code = {InvalidName: 422, NotFound: 404, AlreadyExists: 409, Forbidden: 403}.get(
        type(exc), 400
    )
    return HTTPException(status_code=code, detail=str(exc))


def require_user(request: Request) -> str:
    """Dependencia: exige sesión iniciada y que el usuario siga existiendo."""
    user = request.session.get("user")
    if not user or not _users.exists(user):
        raise HTTPException(status_code=401, detail="No autenticado")
    return user


def require_perm(perm: str):
    """Factoría de dependencia: exige sesión + un permiso concreto."""
    def dep(request: Request) -> str:
        user = require_user(request)
        if not _users.has_perm(user, perm):
            raise HTTPException(status_code=403, detail="No tienes permiso para esta acción.")
        return user
    return dep


class CreateClient(BaseModel):
    name: str = Field(min_length=1, max_length=64)


class Directive(BaseModel):
    key: str = Field(min_length=1, max_length=41)
    value: str = Field(default="", max_length=512)


class ServerConfigUpdate(BaseModel):
    directives: list[Directive] = Field(max_length=200)


class SavePath(BaseModel):
    path: str = Field(min_length=1, max_length=512)


class SendEmail(BaseModel):
    email: str = Field(min_length=3, max_length=254)


class HaBundleRequest(BaseModel):
    """Parámetros del paquete de alta disponibilidad (OpenVPN primario + WireGuard
    de respaldo) — ver `vpn_manager.ha_bundle` para el porqué de cada campo."""

    health_check_hosts: list[str] = Field(min_length=1, max_length=10)
    health_check_port: int = Field(default=443, ge=1, le=65535)
    split_dns_domain: str = Field(default="", max_length=253)
    dns_servers: list[str] = Field(default_factory=list, max_length=5)
    notify_webhook: str = Field(default="", max_length=512)
    check_interval_seconds: int = Field(default=60, ge=10, le=3600)


def _deliver_save(backend, name: str, ext: str, dest: str, user: str) -> dict:
    try:
        content = backend.client_config(name)
        path = delivery.save_to_server(
            content, f"{name}.{ext}", dest, settings.export_dir
        )
    except VpnError as e:
        raise _http(e) from e
    except delivery.DeliveryError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    log.info("config de «%s» guardada en %s por %s", name, path, user)
    return {"saved": True, "path": str(path)}


def _deliver_email(backend, name: str, ext: str, email: str, user: str) -> dict:
    try:
        content = backend.client_config(name)
        result = delivery.send_email(content, f"{name}.{ext}", email, settings, settings.sandbox)
    except VpnError as e:
        raise _http(e) from e
    except delivery.DeliveryError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    log.info("config de «%s» enviada por correo a %s por %s", name, result["to"], user)
    return result


app = FastAPI(title="VPN Manager", version="0.3.0")


class _Metrics:
    """Contadores en proceso, expuestos en /metrics (texto Prometheus, sin deps)."""

    def __init__(self) -> None:
        self._start = time.time()
        self._requests: dict[tuple[str, str], int] = {}
        self._duration_ms = 0.0

    def observe(self, method: str, status: int, ms: float) -> None:
        self._requests[(method, f"{status // 100}xx")] = (
            self._requests.get((method, f"{status // 100}xx"), 0) + 1
        )
        self._duration_ms += ms

    def render(self) -> str:
        out = [
            "# HELP vpnmanager_up 1 si el servicio responde",
            "# TYPE vpnmanager_up gauge",
            "vpnmanager_up 1",
            "# HELP vpnmanager_uptime_seconds Segundos desde el arranque",
            "# TYPE vpnmanager_uptime_seconds gauge",
            f"vpnmanager_uptime_seconds {time.time() - self._start:.0f}",
            "# HELP vpnmanager_http_requests_total Peticiones por método y clase de estado",
            "# TYPE vpnmanager_http_requests_total counter",
        ]
        for (method, status), n in sorted(self._requests.items()):
            out.append(
                f'vpnmanager_http_requests_total{{method="{method}",status="{status}"}} {n}'
            )
        out += [
            "# HELP vpnmanager_http_request_duration_ms_sum Suma de latencias (ms)",
            "# TYPE vpnmanager_http_request_duration_ms_sum counter",
            f"vpnmanager_http_request_duration_ms_sum {self._duration_ms:.0f}",
        ]
        return "\n".join(out) + "\n"


METRICS = _Metrics()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    start = time.monotonic()
    response = await call_next(request)
    # Métricas: no se contabiliza el propio scrape de /metrics.
    if request.url.path != "/metrics":
        METRICS.observe(request.method, response.status_code, (time.monotonic() - start) * 1000)
    for k, v in _SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    # HSTS solo detrás de HTTPS (cuando se sirve con cookie segura).
    if settings.cookie_secure:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    # Nunca cachear el panel ni la API (pueden contener datos sensibles).
    if request.url.path != "/health":
        response.headers["Cache-Control"] = "no-store"
    return response


app.add_middleware(
    SessionMiddleware,
    secret_key=auth.resolve_secret(settings.secret_key, settings.sandbox),
    session_cookie="vpnm_session",
    max_age=settings.session_max_age,
    same_site="strict",
    https_only=settings.cookie_secure,
)

app.mount("/assets", StaticFiles(directory=str(_UI / "assets")), name="assets")

_PROTECTED = [Depends(require_user)]


# ── Páginas ──────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def ui(request: Request):
    if not request.session.get("user"):
        return RedirectResponse("/login", status_code=303)
    return HTMLResponse((_UI / "index.html").read_text(encoding="utf-8"))


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str = ""):
    if request.session.get("user"):
        return RedirectResponse("/", status_code=303)
    step = "code" if request.session.get("pending_2fa") else "login"
    return HTMLResponse(_render_login(error, step))


@app.post("/login")
def login(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    code: str = Form(""),
):
    ip = request.client.host if request.client else "?"
    if _throttle.is_blocked(ip):
        log.warning("login bloqueado por exceso de intentos desde %s", ip)
        return HTMLResponse(_render_login("Demasiados intentos. Espera unos minutos.",
                                          "code" if request.session.get("pending_2fa") else "login"),
                            status_code=429)

    # Segundo paso: la sesión espera un código TOTP.
    pending = request.session.get("pending_2fa")
    if pending:
        if totp.verify(_users.totp_secret(pending) or "", code):
            _throttle.reset(ip)
            request.session.clear()
            request.session["user"] = pending
            log.info("login correcto (%s) [2FA] desde %s", pending, ip)
            return RedirectResponse("/", status_code=303)
        _throttle.record_failure(ip)
        log.warning("2FA incorrecto (usuario=%r) desde %s", pending[:32], ip)
        return HTMLResponse(_render_login("Código de verificación incorrecto.", "code"),
                            status_code=401)

    # Primer paso: usuario + contraseña.
    if not _users.verify(username, password):
        _throttle.record_failure(ip)
        log.warning("login fallido (usuario=%r) desde %s", username[:32], ip)
        return HTMLResponse(_render_login("Usuario o contraseña incorrectos."), status_code=401)

    if _users.totp_enabled(username):
        request.session.clear()
        request.session["pending_2fa"] = username
        return RedirectResponse("/login", status_code=303)

    _throttle.reset(ip)
    request.session.clear()
    request.session["user"] = username
    log.info("login correcto (%s) desde %s", username, ip)
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "sandbox": settings.sandbox}


@app.get("/metrics")
def metrics() -> PlainTextResponse:
    """Métricas en formato Prometheus (texto). Ruta pública (sin auth), para
    que la raspe Prometheus; el panel se sirve en red interna."""
    return PlainTextResponse(METRICS.render())


@app.get("/api/me", dependencies=_PROTECTED)
def me(user: str = Depends(require_user)) -> dict:
    role = _users.role(user)
    return {
        "user": user,
        "role": role,
        "role_label": users.ROLE_LABELS.get(role, role),
        "permissions": sorted(users.role_permissions(role)),
        "totp_enabled": _users.totp_enabled(user),
    }


class TwoFACode(BaseModel):
    code: str = Field(min_length=4, max_length=10)


@app.post("/api/me/2fa/setup")
def me_2fa_setup(user: str = Depends(require_user)) -> dict:
    secret = totp.generate_secret()
    _users.set_totp_secret(user, secret)  # pendiente de confirmar
    uri = totp.provisioning_uri(secret, user)
    import segno
    return {"secret": secret, "uri": uri, "qr": segno.make(uri, error="m").svg_inline(scale=4)}


@app.post("/api/me/2fa/enable")
def me_2fa_enable(body: TwoFACode, user: str = Depends(require_user)) -> dict:
    if not totp.verify(_users.totp_secret(user) or "", body.code):
        raise HTTPException(status_code=422, detail="Código incorrecto. Vuelve a intentarlo.")
    try:
        _users.enable_totp(user)
    except users.UserError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    log.info("2FA activado por %s", user)
    return {"totp_enabled": True}


@app.post("/api/me/2fa/disable")
def me_2fa_disable(body: TwoFACode, user: str = Depends(require_user)) -> dict:
    if not _users.totp_enabled(user):
        raise HTTPException(status_code=422, detail="La verificación en dos pasos no está activa.")
    if not totp.verify(_users.totp_secret(user) or "", body.code):
        raise HTTPException(status_code=422, detail="Código incorrecto.")
    _users.disable_totp(user)
    log.info("2FA desactivado por %s", user)
    return {"totp_enabled": False}


# ── Gestión de usuarios (rol admin) ──────────────────────────────────────────
class CreateUser(BaseModel):
    username: str = Field(min_length=2, max_length=32)
    password: str = Field(min_length=8, max_length=256)
    role: str


class UpdateUser(BaseModel):
    role: str | None = None
    password: str | None = Field(default=None, min_length=8, max_length=256)


@app.get("/api/audit", dependencies=[Depends(require_perm("audit:read"))])
def audit_log(limit: int = 200, q: str = "", level: str = "") -> dict:
    return {"entries": audit.recent(settings.audit_file, max(1, min(limit, 1000)), q, level)}


@app.get("/api/users", dependencies=[Depends(require_perm("users:manage"))])
def users_list() -> dict:
    return {
        "users": _users.list(),
        "roles": [{"id": r, "label": users.ROLE_LABELS[r]} for r in users.ROLES],
    }


@app.post("/api/users", status_code=201)
def users_create(body: CreateUser, admin: str = Depends(require_perm("users:manage"))) -> dict:
    try:
        _users.add(body.username, body.password, body.role)
    except users.UserError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    log.info("usuario «%s» (rol %s) creado por %s", body.username, body.role, admin)
    return {"created": body.username}


@app.put("/api/users/{username}")
def users_update(username: str, body: UpdateUser, admin: str = Depends(require_perm("users:manage"))) -> dict:
    try:
        _users.update(username, role=body.role, password=body.password)
    except users.UserError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    log.info("usuario «%s» modificado por %s", username, admin)
    return {"updated": username}


@app.delete("/api/users/{username}")
def users_delete(username: str, admin: str = Depends(require_perm("users:manage"))) -> dict:
    if username == admin:
        raise HTTPException(status_code=422, detail="No puedes borrar tu propia cuenta.")
    try:
        _users.delete(username)
    except users.UserError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    log.info("usuario «%s» borrado por %s", username, admin)
    return {"deleted": username}


# ── Lectura (protegida) ──────────────────────────────────────────────────────
@app.get("/api/openvpn/status", response_model=ServiceStatus, dependencies=_PROTECTED)
def openvpn_status() -> ServiceStatus:
    return _openvpn().status()


@app.get("/api/openvpn/clients", response_model=list[VpnClient], dependencies=_PROTECTED)
def openvpn_clients() -> list[VpnClient]:
    return _openvpn().clients()


@app.get(
    "/api/openvpn/connections", response_model=list[VpnConnection], dependencies=_PROTECTED
)
def openvpn_connections() -> list[VpnConnection]:
    return _openvpn().connections()


@app.get("/api/openvpn/server", response_model=ServerInfo, dependencies=_PROTECTED)
def openvpn_server() -> ServerInfo:
    return _openvpn().server_info()


@app.get("/api/openvpn/server/schema", dependencies=_PROTECTED)
def openvpn_server_schema() -> dict:
    from ..backends.openvpn_schema import FIELDS

    return {"fields": FIELDS}


@app.put("/api/openvpn/server", response_model=ServerInfo, dependencies=_PROTECTED)
def openvpn_server_update(body: ServerConfigUpdate, user: str = Depends(require_perm("server:write"))) -> ServerInfo:
    try:
        info = _openvpn().update_server_config([(d.key, d.value) for d in body.directives])
    except VpnError as e:
        raise _http(e) from e
    log.info("configuración del servidor OpenVPN modificada por %s", user)
    return info


@app.get("/api/openvpn/logs", dependencies=_PROTECTED)
def openvpn_logs(lines: int = 80) -> dict:
    return {"lines": _openvpn().logs(lines)}


@app.post(
    "/api/openvpn/service/{action}", response_model=ServiceStatus, dependencies=_PROTECTED
)
def openvpn_service_action(action: str, user: str = Depends(require_perm("service:control"))) -> ServiceStatus:
    try:
        status = _openvpn().service_action(action)
    except VpnError as e:
        raise _http(e) from e
    log.info("acción de servicio «%s» por %s -> activo=%s", action, user, status.active)
    return status


# ── Sistema / instalación de servicios ───────────────────────────────────────
@app.get("/api/system", dependencies=_PROTECTED)
def system_info() -> dict:
    return installer.system_info()


@app.get("/api/preflight", dependencies=[Depends(require_perm("users:manage"))])
def preflight_checks() -> dict:
    items = preflight.checks(settings)
    return {"checks": items, "level": preflight.summary_level(items)}


@app.get("/api/system/install/{backend}/plan", dependencies=_PROTECTED)
def system_install_plan(backend: str) -> dict:
    try:
        return installer.install_plan(backend)
    except installer.InstallError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e


@app.post("/api/system/install/{backend}")
def system_install(backend: str, admin: str = Depends(require_perm("system:install"))) -> dict:
    try:
        result = installer.install(backend, settings.sandbox, settings.allow_install)
    except installer.InstallError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    log.info("instalación de «%s» solicitada por %s (simulada=%s)", backend, admin,
             result.get("simulated"))
    return result


@app.get("/api/system/bootstrap/{backend}/plan", dependencies=_PROTECTED)
def system_bootstrap_plan(backend: str) -> dict:
    try:
        return bootstrap.plan(backend, settings)
    except bootstrap.BootstrapError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e


@app.post("/api/system/bootstrap/{backend}")
def system_bootstrap(backend: str, admin: str = Depends(require_perm("system:install"))) -> dict:
    try:
        result = bootstrap.run(backend, settings, settings.sandbox)
    except bootstrap.BootstrapError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    log.info("instalación llave en mano de «%s» por %s (simulada=%s)", backend, admin,
             result.get("simulated"))
    return result


# ── WireGuard ────────────────────────────────────────────────────────────────
@app.get("/api/wireguard/status", response_model=ServiceStatus, dependencies=_PROTECTED)
def wg_status() -> ServiceStatus:
    return _wireguard().status()


@app.get("/api/wireguard/clients", response_model=list[VpnClient], dependencies=_PROTECTED)
def wg_clients() -> list[VpnClient]:
    return _wireguard().clients()


@app.get(
    "/api/wireguard/connections", response_model=list[VpnConnection], dependencies=_PROTECTED
)
def wg_connections() -> list[VpnConnection]:
    return _wireguard().connections()


@app.get("/api/wireguard/server", response_model=ServerInfo, dependencies=_PROTECTED)
def wg_server() -> ServerInfo:
    return _wireguard().server_info()


@app.get("/api/wireguard/server/schema", dependencies=_PROTECTED)
def wg_server_schema() -> dict:
    from ..backends.wireguard_schema import FIELDS

    return {"fields": FIELDS}


@app.put("/api/wireguard/server", response_model=ServerInfo, dependencies=_PROTECTED)
def wg_server_update(body: ServerConfigUpdate, user: str = Depends(require_perm("server:write"))) -> ServerInfo:
    try:
        info = _wireguard().update_server_config([(d.key, d.value) for d in body.directives])
    except VpnError as e:
        raise _http(e) from e
    log.info("configuración del servidor WireGuard modificada por %s", user)
    return info


@app.get("/api/wireguard/logs", dependencies=_PROTECTED)
def wg_logs(lines: int = 80) -> dict:
    return {"lines": _wireguard().logs(lines)}


@app.post(
    "/api/wireguard/clients", response_model=VpnClient, status_code=201, dependencies=_PROTECTED
)
def wg_create(body: CreateClient, user: str = Depends(require_perm("clients:write"))) -> VpnClient:
    try:
        client = _wireguard().create_client(body.name)
    except VpnError as e:
        raise _http(e) from e
    log.info("alta de dispositivo WireGuard «%s» por %s", client.name, user)
    return client


@app.post(
    "/api/wireguard/clients/{name}/revoke", response_model=VpnClient, dependencies=_PROTECTED
)
def wg_revoke(name: str, user: str = Depends(require_perm("clients:write"))) -> VpnClient:
    try:
        client = _wireguard().revoke_client(name)
    except VpnError as e:
        raise _http(e) from e
    log.info("baja de dispositivo WireGuard «%s» por %s", client.name, user)
    return client


@app.get(
    "/api/wireguard/clients/{name}/config",
    response_class=PlainTextResponse,
    dependencies=_PROTECTED,
)
def wg_config(name: str, user: str = Depends(require_user)) -> Response:
    try:
        text = _wireguard().client_config(name)
    except VpnError as e:
        raise _http(e) from e
    log.info("descarga de configuración de «%s» por %s", name, user)
    return PlainTextResponse(
        text, headers={"Content-Disposition": f'attachment; filename="{name}.conf"'}
    )


@app.get("/api/wireguard/clients/{name}/qr", dependencies=_PROTECTED)
def wg_qr(name: str) -> Response:
    try:
        svg = _wireguard().client_qr_svg(name)
    except VpnError as e:
        raise _http(e) from e
    return Response(content=svg, media_type="image/svg+xml")


@app.post("/api/wireguard/clients/{name}/save", dependencies=_PROTECTED)
def wg_save(name: str, body: SavePath, user: str = Depends(require_perm("clients:write"))) -> dict:
    return _deliver_save(_wireguard(), name, "conf", body.path, user)


@app.post("/api/wireguard/clients/{name}/email", dependencies=_PROTECTED)
def wg_email(name: str, body: SendEmail, user: str = Depends(require_perm("clients:write"))) -> dict:
    return _deliver_email(_wireguard(), name, "conf", body.email, user)


@app.post(
    "/api/wireguard/service/{action}", response_model=ServiceStatus, dependencies=_PROTECTED
)
def wg_service_action(action: str, user: str = Depends(require_perm("service:control"))) -> ServiceStatus:
    try:
        status = _wireguard().service_action(action)
    except VpnError as e:
        raise _http(e) from e
    log.info("acción de servicio WireGuard «%s» por %s -> activo=%s", action, user, status.active)
    return status


# ── Escritura (protegida) ────────────────────────────────────────────────────
@app.post(
    "/api/openvpn/clients", response_model=VpnClient, status_code=201, dependencies=_PROTECTED
)
def openvpn_create(body: CreateClient, user: str = Depends(require_perm("clients:write"))) -> VpnClient:
    try:
        client = _openvpn().create_client(body.name)
    except VpnError as e:
        raise _http(e) from e
    log.info("alta de acceso «%s» por %s", client.name, user)
    return client


@app.post(
    "/api/openvpn/clients/{name}/revoke", response_model=VpnClient, dependencies=_PROTECTED
)
def openvpn_revoke(name: str, user: str = Depends(require_perm("clients:write"))) -> VpnClient:
    try:
        client = _openvpn().revoke_client(name)
    except VpnError as e:
        raise _http(e) from e
    log.info("revocación de acceso «%s» por %s", client.name, user)
    return client


@app.post(
    "/api/openvpn/clients/{name}/renew", response_model=VpnClient, dependencies=_PROTECTED
)
def openvpn_renew(name: str, user: str = Depends(require_perm("clients:write"))) -> VpnClient:
    try:
        client = _openvpn().renew_client(name)
    except VpnError as e:
        raise _http(e) from e
    log.info("renovación de acceso «%s» por %s", client.name, user)
    return client


@app.post(
    "/api/openvpn/connections/{name}/disconnect", status_code=204, dependencies=_PROTECTED
)
def openvpn_disconnect(name: str, user: str = Depends(require_perm("clients:write"))) -> Response:
    try:
        _openvpn().disconnect(name)
    except VpnError as e:
        raise _http(e) from e
    log.info("desconexión de «%s» por %s", name, user)
    return Response(status_code=204)


@app.get(
    "/api/openvpn/clients/{name}/config",
    response_class=PlainTextResponse,
    dependencies=_PROTECTED,
)
def openvpn_config(name: str, user: str = Depends(require_user)) -> Response:
    try:
        text = _openvpn().client_config(name)
    except VpnError as e:
        raise _http(e) from e
    log.info("descarga de configuración de «%s» por %s", name, user)
    return PlainTextResponse(
        text, headers={"Content-Disposition": f'attachment; filename="{name}.ovpn"'}
    )


@app.post("/api/openvpn/clients/{name}/save", dependencies=_PROTECTED)
def openvpn_save(name: str, body: SavePath, user: str = Depends(require_perm("clients:write"))) -> dict:
    return _deliver_save(_openvpn(), name, "ovpn", body.path, user)


@app.post("/api/openvpn/clients/{name}/email", dependencies=_PROTECTED)
def openvpn_email(name: str, body: SendEmail, user: str = Depends(require_perm("clients:write"))) -> dict:
    return _deliver_email(_openvpn(), name, "ovpn", body.email, user)


# ── Alta disponibilidad (OpenVPN primario + WireGuard de respaldo) ──────────
# Requiere que el cliente ya exista en AMBOS backends (dar de alta primero
# por separado en /api/openvpn/clients y /api/wireguard/clients con el mismo
# nombre) -- este endpoint solo empaqueta, no crea nada.
@app.post("/api/ha/clients/{name}/bundle", dependencies=_PROTECTED)
def ha_bundle_download(
    name: str, body: HaBundleRequest, user: str = Depends(require_user)
) -> Response:
    try:
        openvpn_conf = _openvpn().client_config(name)
        wireguard_conf = _wireguard().client_config(name)
    except VpnError as e:
        raise _http(e) from e
    cfg = ha_bundle.FailoverConfig(
        name=name,
        health_check_hosts=body.health_check_hosts,
        health_check_port=body.health_check_port,
        split_dns_domain=body.split_dns_domain,
        dns_servers=body.dns_servers,
        notify_webhook=body.notify_webhook,
        check_interval_seconds=body.check_interval_seconds,
    )
    zip_bytes = ha_bundle.build_bundle_zip(
        openvpn_conf=openvpn_conf, wireguard_conf=wireguard_conf, cfg=cfg
    )
    log.info("descarga de paquete de alta disponibilidad de «%s» por %s", name, user)
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{name}-ha-bundle.zip"'},
    )


# ── Utilidades ───────────────────────────────────────────────────────────────
def _render_login(error: str = "", step: str = "login") -> str:
    import re

    html = (_UI / "login.html").read_text(encoding="utf-8")
    err = f'<div class="error">{_escape(error)}</div>' if error else ""
    html = html.replace("<!--ERROR-->", err)
    if step == "code":
        # Paso del código: deja el bloque CODE, quita CREDS.
        html = re.sub(r"<!--CREDS-->.*?<!--/CREDS-->", "", html, flags=re.DOTALL)
        html = html.replace("<!--SUBTITLE-->", "Introduce el código de tu app de autenticación.")
        html = html.replace("<!--BUTTON-->", "Verificar")
    else:
        html = re.sub(r"<!--CODE-->.*?<!--/CODE-->", "", html, flags=re.DOTALL)
        html = html.replace("<!--SUBTITLE-->", "Introduce tus credenciales para administrar la VPN.")
        html = html.replace("<!--BUTTON-->", "Entrar")
    return html


def _escape(s: str) -> str:
    return (
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )
