import shutil

import pytest
from fastapi.testclient import TestClient

from vpn_manager.api.app import app
from vpn_manager.backends.base import AlreadyExists, Forbidden, InvalidName, NotFound
from vpn_manager.backends.openvpn import OpenVpnBackend
from vpn_manager.backends.wireguard import WireGuardBackend
from vpn_manager.config import settings


@pytest.fixture
def tmp_wg(tmp_path) -> WireGuardBackend:
    """Backend WireGuard sobre una copia temporal del wg0.conf."""
    conf = tmp_path / "wg0.conf"
    shutil.copy(settings.wireguard_conf, conf)
    show = tmp_path / "wg-show.txt"
    shutil.copy(settings.wireguard_show_file, show)
    log = tmp_path / "wireguard.log"
    shutil.copy(settings.wireguard_log_file, log)
    return WireGuardBackend(
        conf=conf, show_file=show, service="wg-quick@wg0", sandbox=True,
        interface="wg0", log_file=log, public_endpoint="vpn.miempresa.com",
    )


def _backend() -> OpenVpnBackend:
    return OpenVpnBackend(
        pki_index=settings.openvpn_pki_index,
        status_file=settings.openvpn_status_file,
        service=settings.openvpn_service,
        sandbox=True,
        log_file=settings.openvpn_log_file,
        server_conf=settings.openvpn_server_conf,
        public_endpoint=settings.openvpn_public_endpoint,
    )


@pytest.fixture
def tmp_backend(tmp_path) -> OpenVpnBackend:
    """Backend sobre una copia temporal de la PKI (no toca los fixtures)."""
    pki = tmp_path / "pki"
    pki.mkdir()
    shutil.copy(settings.openvpn_pki_index, pki / "index.txt")
    status = tmp_path / "openvpn-status.log"
    shutil.copy(settings.openvpn_status_file, status)
    log = tmp_path / "openvpn.log"
    shutil.copy(settings.openvpn_log_file, log)
    conf = tmp_path / "server.conf"
    shutil.copy(settings.openvpn_server_conf, conf)
    return OpenVpnBackend(
        pki_index=pki / "index.txt", status_file=status,
        service="x", sandbox=True, log_file=log, server_conf=conf,
    )


class TestOpenVpnParsing:
    def test_clients_excluye_servidor_y_lee_estados(self):
        clients = {c.name: c for c in _backend().clients()}
        assert "server" not in clients  # el cert del servidor no es cliente
        assert clients["alice-laptop"].status == "valid"
        assert clients["bob-phone"].status == "valid"
        assert clients["carol-old"].status == "revoked"
        assert clients["dave-expired"].status == "expired"
        assert clients["alice-laptop"].serial == "02"
        assert clients["alice-laptop"].expires_at is not None

    def test_connections_lee_status_con_bytes_y_virtual(self):
        conns = {c.name: c for c in _backend().connections()}
        assert set(conns) == {"alice-laptop", "bob-phone"}
        assert conns["alice-laptop"].bytes_received == 1048576
        assert conns["alice-laptop"].bytes_sent == 2097152
        assert conns["alice-laptop"].virtual_address == "10.8.0.2"
        assert conns["alice-laptop"].connected_since is not None

    def test_status_sandbox_no_toca_el_sistema(self):
        s = _backend().status()
        assert s.backend == "openvpn"
        assert s.active is True
        assert s.detail == "sandbox"


def _login(client: TestClient) -> None:
    r = client.post("/login", data={"username": "admin", "password": "admin"})
    assert r.status_code == 200  # sigue la redirección al panel


class TestApi:
    @pytest.fixture(autouse=True)
    def _auth(self):
        self.client = TestClient(app)
        _login(self.client)

    def test_health_es_publico(self):
        r = TestClient(app).get("/health")  # sin login
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
        assert r.json()["sandbox"] is True

    def test_clients_endpoint(self):
        r = self.client.get("/api/openvpn/clients")
        assert r.status_code == 200
        assert len(r.json()) == 4  # 4 clientes (sin el servidor)

    def test_connections_endpoint(self):
        r = self.client.get("/api/openvpn/connections")
        assert r.status_code == 200
        assert len(r.json()) == 2


class TestAuth:
    def test_api_sin_login_devuelve_401(self):
        c = TestClient(app)
        assert c.get("/api/openvpn/clients").status_code == 401
        assert c.get("/api/openvpn/status").status_code == 401
        assert c.post("/api/openvpn/clients", json={"name": "x"}).status_code == 401

    def test_panel_sin_login_redirige_a_login(self):
        c = TestClient(app)
        r = c.get("/", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/login"

    def test_login_incorrecto_devuelve_401(self):
        c = TestClient(app)
        r = c.post("/login", data={"username": "admin", "password": "malo"})
        assert r.status_code == 401

    def test_login_correcto_y_logout(self):
        c = TestClient(app)
        _login(c)
        assert c.get("/api/openvpn/clients").status_code == 200
        assert c.get("/api/me").json()["user"] == "admin"
        c.post("/logout")
        assert c.get("/api/openvpn/clients").status_code == 401


class TestOpenVpnWrite:
    def test_alta_crea_cliente_valido_y_config(self, tmp_backend):
        c = tmp_backend.create_client("nuevo-pc")
        assert c.status == "valid"
        assert c.serial == "06"  # siguiente serie tras 05
        names = {x.name: x.status for x in tmp_backend.clients()}
        assert names["nuevo-pc"] == "valid"
        cfg = tmp_backend.client_config("nuevo-pc")
        assert "nuevo-pc" in cfg
        assert (tmp_backend.client_dir / "nuevo-pc.ovpn").exists()

    def test_alta_duplicada_falla(self, tmp_backend):
        with pytest.raises(AlreadyExists):
            tmp_backend.create_client("alice-laptop")

    @pytest.mark.parametrize("bad", ["", "  ", "../etc", "con espacio", "a/b", "x;rm", "@evil"])
    def test_nombres_invalidos(self, tmp_backend, bad):
        with pytest.raises(InvalidName):
            tmp_backend.create_client(bad)

    def test_no_se_puede_crear_ni_revocar_el_servidor(self, tmp_backend):
        with pytest.raises(Forbidden):
            tmp_backend.create_client("server")
        with pytest.raises(Forbidden):
            tmp_backend.revoke_client("server")

    def test_revocar_marca_revocado_y_bloquea_config(self, tmp_backend):
        r = tmp_backend.revoke_client("alice-laptop")
        assert r.status == "revoked"
        names = {x.name: x.status for x in tmp_backend.clients()}
        assert names["alice-laptop"] == "revoked"
        with pytest.raises(Forbidden):  # ya no se descarga su config
            tmp_backend.client_config("alice-laptop")

    def test_revocar_inexistente_falla(self, tmp_backend):
        with pytest.raises(NotFound):
            tmp_backend.revoke_client("fantasma")

    def test_config_de_caducado_bloqueada(self, tmp_backend):
        with pytest.raises(Forbidden):
            tmp_backend.client_config("dave-expired")


class TestServiceAndLogs:
    def test_acciones_validas_en_sandbox(self, tmp_backend):
        for action in ("start", "restart", "reload"):
            assert tmp_backend.service_action(action).active is True
        assert tmp_backend.service_action("stop").active is False

    def test_accion_invalida_falla(self, tmp_backend):
        with pytest.raises(InvalidName):
            tmp_backend.service_action("rm -rf")

    def test_logs_devuelve_lineas(self, tmp_backend):
        out = tmp_backend.logs(5)
        assert isinstance(out, list)
        assert 1 <= len(out) <= 5
        assert any("OpenVPN" in line or "alice" in line for line in tmp_backend.logs(100))

    def test_logs_acota_el_numero(self, tmp_backend):
        assert len(tmp_backend.logs(99999)) <= 1000

    def test_renovar_caducado_lo_reactiva(self, tmp_backend):
        c = tmp_backend.renew_client("dave-expired")
        assert c.status == "valid"
        names = {x.name: x.status for x in tmp_backend.clients()}
        assert names["dave-expired"] == "valid"

    def test_no_se_renueva_un_retirado(self, tmp_backend):
        with pytest.raises(Forbidden):
            tmp_backend.renew_client("carol-old")

    def test_desconectar_quita_la_conexion(self, tmp_backend):
        assert "alice-laptop" in {c.name for c in tmp_backend.connections()}
        tmp_backend.disconnect("alice-laptop")
        assert "alice-laptop" not in {c.name for c in tmp_backend.connections()}

    def test_desconectar_sin_conexion_falla(self, tmp_backend):
        with pytest.raises(NotFound):
            tmp_backend.disconnect("dave-expired")


class TestServerInfo:
    def test_lee_configuracion_completa(self):
        info = _backend().server_info()
        assert info.port == "1194"
        assert info.proto == "udp"
        assert info.subnet == "10.8.0.0 255.255.255.0"
        assert "AES-256-GCM" in (info.cipher or "")
        assert info.auth == "SHA256"
        assert info.max_clients == "50"
        assert info.crl_enabled is True
        assert "1.1.1.1" in info.dns_servers
        assert any("192.168.1.0" in r for r in info.routes)
        assert len(info.directives) > 10  # todas las directivas, sin filtrar

    def test_endpoint_publico_configurable(self):
        b = OpenVpnBackend(
            pki_index=settings.openvpn_pki_index, status_file=settings.openvpn_status_file,
            service="x", sandbox=True, server_conf=settings.openvpn_server_conf,
            public_endpoint="vpn.miempresa.com",
        )
        assert b.server_info().public_endpoint == "vpn.miempresa.com"
        assert "vpn.miempresa.com" in b.client_config("alice-laptop")

    def test_editar_configuracion(self, tmp_backend):
        info = tmp_backend.update_server_config(
            [("port", "1195"), ("proto", "tcp"), ("server", "10.20.0.0 255.255.255.0"),
             ("persist-key", "")]
        )
        assert info.port == "1195" and info.proto == "tcp"
        assert info.subnet == "10.20.0.0 255.255.255.0"

    def test_editar_rechaza_valores_malos(self, tmp_backend):
        with pytest.raises(InvalidName):
            tmp_backend.update_server_config([("port", "noesnumero")])
        with pytest.raises(InvalidName):
            tmp_backend.update_server_config([("proto", "ftp")])  # no está en opciones
        with pytest.raises(InvalidName):
            tmp_backend.update_server_config([("mal nombre", "x")])

    def test_schema_tiene_campos_con_tipos(self):
        from vpn_manager.backends.openvpn_schema import FIELDS, FIELDS_BY_KEY

        assert FIELDS_BY_KEY["proto"]["type"] == "select"
        assert "udp" in FIELDS_BY_KEY["proto"]["options"]
        assert all("desc" in f and "label" in f for f in FIELDS)


class TestWireGuard:
    def test_clients_lee_peers(self, tmp_wg):
        names = {c.name for c in tmp_wg.clients()}
        assert names == {"ana-portatil", "luis-movil", "tablet-almacen"}
        assert all(c.status == "valid" and c.expires_at is None for c in tmp_wg.clients())

    def test_connections_solo_con_handshake(self, tmp_wg):
        conns = {c.name: c for c in tmp_wg.connections()}
        assert set(conns) == {"ana-portatil", "luis-movil"}  # tablet sin handshake
        assert conns["ana-portatil"].virtual_address == "10.9.0.2"
        assert conns["ana-portatil"].bytes_received == int(1.05 * 1024**2)
        assert conns["ana-portatil"].connected_since is not None

    def test_alta_asigna_ip_y_guarda_config(self, tmp_wg):
        c = tmp_wg.create_client("nuevo-pc")
        assert c.status == "valid"
        cfg = tmp_wg.client_config("nuevo-pc")
        assert "10.9.0.5/32" in cfg  # .2,.3,.4 ocupadas → siguiente .5
        assert "vpn.miempresa.com:51820" in cfg
        assert "nuevo-pc" in {p.name for p in tmp_wg.clients()}

    def test_alta_duplicada_falla(self, tmp_wg):
        with pytest.raises(AlreadyExists):
            tmp_wg.create_client("ana-portatil")

    def test_baja_quita_el_peer(self, tmp_wg):
        tmp_wg.revoke_client("luis-movil")
        assert "luis-movil" not in {p.name for p in tmp_wg.clients()}

    def test_server_info_no_expone_clave_privada(self, tmp_wg):
        info = tmp_wg.server_info()
        assert info.port == "51820"
        assert info.subnet == "10.9.0.1/24"
        assert info.cipher == "ChaCha20-Poly1305"
        priv = [d for d in info.directives if d.key == "PrivateKey"]
        assert priv and priv[0].value == "(oculta)"  # nunca se expone

    def test_qr_genera_svg(self, tmp_wg):
        svg = tmp_wg.client_qr_svg("ana-portatil")
        assert svg.lstrip().startswith("<svg")

    def test_nombre_invalido(self, tmp_wg):
        with pytest.raises(InvalidName):
            tmp_wg.create_client("mal nombre/..")

    def test_editar_config_preserva_clave_y_peers(self, tmp_wg):
        info = tmp_wg.update_server_config([("Address", "10.50.0.1/24"), ("ListenPort", "51999")])
        assert info.subnet == "10.50.0.1/24" and info.port == "51999"
        # los peers se conservan
        assert {c.name for c in tmp_wg.clients()} == {"ana-portatil", "luis-movil", "tablet-almacen"}
        # la clave privada del servidor sigue en el fichero (no se perdió ni se expuso "(oculta)")
        raw = tmp_wg.conf.read_text()
        assert "PrivateKey = QFXm" in raw
        assert "(oculta)" not in raw

    def test_editar_config_valida(self, tmp_wg):
        with pytest.raises(InvalidName):
            tmp_wg.update_server_config([("ListenPort", "noesnumero")])
        with pytest.raises(InvalidName):
            tmp_wg.update_server_config([("Address", "esto-no-es-una-ip")])


class TestWireGuardApi:
    @pytest.fixture(autouse=True)
    def _isolate(self, tmp_path, monkeypatch):
        conf = tmp_path / "wg0.conf"
        shutil.copy(settings.wireguard_conf, conf)
        show = tmp_path / "wg-show.txt"
        shutil.copy(settings.wireguard_show_file, show)
        monkeypatch.setattr(settings, "wireguard_conf", conf)
        monkeypatch.setattr(settings, "wireguard_show_file", show)
        self.client = TestClient(app)
        _login(self.client)

    def test_flujo_wireguard_por_api(self):
        assert len(self.client.get("/api/wireguard/clients").json()) == 3
        assert len(self.client.get("/api/wireguard/connections").json()) == 2
        r = self.client.post("/api/wireguard/clients", json={"name": "movil-jose"})
        assert r.status_code == 201
        r = self.client.get("/api/wireguard/clients/movil-jose/qr")
        assert r.status_code == 200 and "svg" in r.headers["content-type"]
        assert self.client.post("/api/wireguard/clients/movil-jose/revoke").status_code == 200

    def test_server_y_login(self):
        d = self.client.get("/api/wireguard/server").json()
        assert d["port"] == "51820" and d["cipher"] == "ChaCha20-Poly1305"
        assert TestClient(app).get("/api/wireguard/clients").status_code == 401

    def test_editar_config_wireguard_por_api(self):
        sc = self.client.get("/api/wireguard/server/schema").json()
        assert any(f["key"] == "Address" for f in sc["fields"])
        r = self.client.put("/api/wireguard/server", json={"directives": [
            {"key": "Address", "value": "10.9.0.1/24"}, {"key": "ListenPort", "value": "51820"}]})
        assert r.status_code == 200 and r.json()["port"] == "51820"
        r = self.client.put("/api/wireguard/server", json={"directives": [
            {"key": "ListenPort", "value": "abc"}]})
        assert r.status_code == 422


class TestUserStore:
    def _store(self, tmp_path):
        from vpn_manager.auth import hash_password
        from vpn_manager.users import UserStore
        return UserStore(tmp_path / "users.json", "admin", hash_password("admin123"), "admin")

    def test_alta_verificacion_y_permisos(self, tmp_path):
        s = self._store(tmp_path)
        assert s.verify("admin", "admin123") and not s.verify("admin", "malo")
        assert not s.verify("fantasma", "x")  # usuario inexistente
        s.add("ana", "operario1", "operator")
        assert s.verify("ana", "operario1")
        assert s.has_perm("ana", "clients:write")
        assert not s.has_perm("ana", "users:manage")
        assert (tmp_path / "users.json").exists()  # se persistió

    def test_validaciones(self, tmp_path):
        from vpn_manager.users import UserError
        s = self._store(tmp_path)
        with pytest.raises(UserError):
            s.add(" x", "12345678", "viewer")  # nombre inválido
        with pytest.raises(UserError):
            s.add("bob", "corta", "viewer")    # contraseña corta
        with pytest.raises(UserError):
            s.add("bob", "12345678", "jefe")   # rol inexistente

    def test_no_se_queda_sin_admin(self, tmp_path):
        from vpn_manager.users import UserError
        s = self._store(tmp_path)
        with pytest.raises(UserError):
            s.update("admin", role="viewer")   # es el último admin
        with pytest.raises(UserError):
            s.delete("admin")


class TestRolesApi:
    @pytest.fixture(autouse=True)
    def _store(self, tmp_path, monkeypatch):
        import vpn_manager.api.app as appmod
        from vpn_manager.auth import hash_password
        from vpn_manager.users import UserStore
        store = UserStore(tmp_path / "users.json", "admin", hash_password("admin123"), "admin")
        store.add("oper", "operario1", "operator")
        store.add("visor", "visor1234", "viewer")
        monkeypatch.setattr(appmod, "_users", store)

    def _login(self, u, p):
        c = TestClient(app)
        assert c.post("/login", data={"username": u, "password": p}).status_code == 200
        return c

    def test_me_incluye_rol_y_permisos(self):
        d = self._login("oper", "operario1").get("/api/me").json()
        assert d["role"] == "operator" and "clients:write" in d["permissions"]

    def test_operador_no_gestiona_usuarios_ni_edita_servidor(self):
        c = self._login("oper", "operario1")
        assert c.get("/api/openvpn/clients").status_code == 200      # lectura OK
        assert c.get("/api/users").status_code == 403                # no admin
        assert c.put("/api/openvpn/server", json={"directives": []}).status_code == 403

    def test_visor_es_solo_lectura(self):
        c = self._login("visor", "visor1234")
        assert c.get("/api/openvpn/clients").status_code == 200
        assert c.post("/api/openvpn/clients", json={"name": "x"}).status_code == 403
        assert c.post("/api/openvpn/service/restart").status_code == 403

    def test_admin_gestiona_usuarios(self):
        c = self._login("admin", "admin123")
        assert len(c.get("/api/users").json()["users"]) == 3
        assert c.post("/api/users", json={"username": "nuevo", "password": "clave1234", "role": "viewer"}).status_code == 201
        assert c.delete("/api/users/oper").status_code == 200
        assert c.delete("/api/users/admin").status_code == 422       # no a sí mismo

    def test_flujo_2fa(self):
        from vpn_manager.totp import now_code
        c = self._login("admin", "admin123")
        d = c.post("/api/me/2fa/setup").json()
        assert d["secret"] and d["uri"].startswith("otpauth://")
        # código incorrecto no activa
        assert c.post("/api/me/2fa/enable", json={"code": "000000"}).status_code == 422
        # código correcto activa
        assert c.post("/api/me/2fa/enable", json={"code": now_code(d["secret"])}).status_code == 200
        assert c.get("/api/me").json()["totp_enabled"] is True
        # nuevo login: usuario+contraseña -> queda pendiente de 2FA (no autenticado aún)
        c2 = TestClient(app)
        c2.post("/login", data={"username": "admin", "password": "admin123"}, follow_redirects=False)
        assert c2.get("/api/me").status_code == 401            # aún no autenticado
        c2.post("/login", data={"code": now_code(d["secret"])}, follow_redirects=False)
        assert c2.get("/api/me").status_code == 200            # tras el código, dentro

    def test_auditoria_solo_admin(self):
        adm = self._login("admin", "admin123")
        assert adm.get("/api/audit").status_code == 200
        assert isinstance(adm.get("/api/audit").json()["entries"], list)
        assert self._login("oper", "operario1").get("/api/audit").status_code == 403
        assert self._login("visor", "visor1234").get("/api/audit").status_code == 403

    def test_instalacion_solo_admin(self):
        # admin: simula la instalación (sandbox); operador/visor: 403
        adm = self._login("admin", "admin123")
        r = adm.post("/api/system/install/openvpn")
        assert r.status_code == 200 and r.json()["simulated"] is True
        assert self._login("oper", "operario1").post("/api/system/install/openvpn").status_code == 403
        assert self._login("visor", "visor1234").post("/api/system/install/wireguard").status_code == 403
        # ver info del sistema: cualquiera con sesión
        assert adm.get("/api/system").status_code == 200
        # preflight de seguridad: solo admin
        r = adm.get("/api/preflight")
        assert r.status_code == 200 and isinstance(r.json()["checks"], list)
        assert self._login("visor", "visor1234").get("/api/preflight").status_code == 403


class TestPreflight:
    def _s(self, **kw):
        import types
        base = {"sandbox": True, "admin_password_hash": "", "secret_key": "",
                "cookie_secure": False, "allow_install": False}
        base.update(kw)
        return types.SimpleNamespace(**base)

    def test_sandbox_avisa_de_dev(self):
        from vpn_manager.preflight import checks, summary_level
        items = checks(self._s())
        msgs = " ".join(c["message"] for c in items)
        assert "admin/admin" in msgs and "efímera" in msgs
        assert summary_level(items) == "warn"

    def test_produccion_bien_configurada_es_ok(self):
        from vpn_manager.preflight import checks, summary_level
        items = checks(self._s(sandbox=False, admin_password_hash="x", secret_key="k",
                               cookie_secure=True))
        assert summary_level(items) == "ok"
        assert all(c["level"] == "ok" for c in items)

    def test_produccion_sin_https_avisa(self):
        from vpn_manager.preflight import checks
        items = checks(self._s(sandbox=False, admin_password_hash="x", secret_key="k",
                               cookie_secure=False))
        assert any(c["level"] == "warn" and "Secure" in c["message"] for c in items)


class TestInstaller:
    def test_detecta_distro_desde_texto(self):
        from vpn_manager.installer import detect_distro
        d = detect_distro('ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 24.04 LTS"')
        assert d["id"] == "ubuntu" and d["id_like"] == "debian"
        assert "Ubuntu" in d["name"]

    def test_plan_apt(self):
        from vpn_manager.installer import install_plan
        p = install_plan("openvpn", manager="apt")
        assert p["supported"] and p["package_manager"] == "apt"
        assert "openvpn" in p["packages"] and "easy-rsa" in p["packages"]
        assert ["apt-get", "update"] in p["commands"]

    def test_plan_dnf_rhel_anade_epel(self):
        from vpn_manager.installer import install_plan
        p = install_plan("openvpn", manager="dnf")
        # En el host de pruebas (no Fedora) se añade epel-release para OpenVPN.
        assert "epel-release" in p["packages"] or "fedora" in __import__(
            "vpn_manager.installer", fromlist=["detect_distro"]).detect_distro()["id"]

    def test_plan_backend_invalido(self):
        from vpn_manager.installer import InstallError, install_plan
        with pytest.raises(InstallError):
            install_plan("ipsec")

    def test_install_sandbox_simula(self):
        from vpn_manager.installer import install
        r = install("wireguard", sandbox=True, allow_install=False)
        assert r["simulated"] is True and r["installed"] is False
        assert r["plan"]["backend"] == "wireguard"

    def test_install_deshabilitada_en_prod(self):
        from vpn_manager.installer import InstallError, install
        with pytest.raises(InstallError):
            install("openvpn", sandbox=False, allow_install=False)

    def test_system_info_tiene_claves(self):
        from vpn_manager.installer import system_info
        info = system_info()
        assert set(info) >= {"distro", "package_manager", "installed", "is_root", "supported"}
        assert set(info["installed"]) == {"openvpn", "easyrsa", "wireguard"}

    def test_uninstall_plan_apt_remove(self):
        from vpn_manager.installer import uninstall_plan
        p = uninstall_plan("openvpn", manager="apt")
        assert p["supported"] and p["package_manager"] == "apt"
        assert p["commands"] == [["apt-get", "remove", "-y", "openvpn", "easy-rsa"]]

    def test_uninstall_plan_apt_purge(self):
        from vpn_manager.installer import uninstall_plan
        p = uninstall_plan("openvpn", manager="apt", purge=True)
        assert p["commands"] == [["apt-get", "purge", "-y", "openvpn", "easy-rsa"]]

    def test_uninstall_plan_dnf_sin_purge_distinto_ni_epel(self):
        from vpn_manager.installer import uninstall_plan
        # dnf no distingue remove/purge (purge=True no cambia el comando), y
        # epel-release nunca se quita (es un repo compartido, no algo de la VPN).
        p_remove = uninstall_plan("openvpn", manager="dnf")
        p_purge = uninstall_plan("openvpn", manager="dnf", purge=True)
        assert p_remove["commands"] == p_purge["commands"]
        assert "epel-release" not in p_remove["packages"]

    def test_uninstall_plan_backend_invalido(self):
        from vpn_manager.installer import InstallError, uninstall_plan
        with pytest.raises(InstallError):
            uninstall_plan("ipsec")

    def test_uninstall_sandbox_simula(self):
        from vpn_manager.installer import uninstall
        r = uninstall("wireguard", sandbox=True, allow_install=False)
        assert r["simulated"] is True and r["uninstalled"] is False
        assert r["plan"]["backend"] == "wireguard"

    def test_uninstall_deshabilitada_en_prod(self):
        from vpn_manager.installer import InstallError, uninstall
        with pytest.raises(InstallError):
            uninstall("openvpn", sandbox=False, allow_install=False)


class TestTotp:
    def test_codigo_valido_e_invalido(self):
        from vpn_manager.totp import generate_secret, now_code, verify
        secret = generate_secret()
        t = 1_700_000_000.0
        code = now_code(secret, at=t)
        assert verify(secret, code, at=t)
        assert verify(secret, code, at=t + 25)          # dentro de la ventana
        assert not verify(secret, "000000", at=t)       # código incorrecto
        assert not verify("", code, at=t)               # sin secreto

    def test_uri_otpauth(self):
        from vpn_manager.totp import provisioning_uri
        uri = provisioning_uri("ABC234", "ana")
        assert uri.startswith("otpauth://totp/") and "secret=ABC234" in uri


class TestAudit:
    def test_persiste_y_lee(self, tmp_path):
        import logging

        from vpn_manager.audit import attach, recent
        path = tmp_path / "audit.jsonl"
        attach("vpn_manager.audit.test", path)
        logging.getLogger("vpn_manager.audit.test").info("alta de «ana» por admin")
        entries = recent(path)
        assert entries and entries[0]["message"] == "alta de «ana» por admin"
        assert "ts" in entries[0] and entries[0]["level"] == "INFO"

    def test_recent_vacio_si_no_existe(self, tmp_path):
        from vpn_manager.audit import recent
        assert recent(tmp_path / "no.jsonl") == []

    def test_filtros_busqueda_y_nivel(self, tmp_path):
        import logging

        from vpn_manager.audit import attach, recent
        path = tmp_path / "audit.jsonl"
        attach("vpn_manager.audit.test2", path)
        lg = logging.getLogger("vpn_manager.audit.test2")
        lg.info("alta de «ana» por admin")
        lg.warning("login fallido (usuario='root')")
        lg.info("revocación de «bob» por ana")
        assert len(recent(path, query="ana")) == 2          # busca «ana» en el texto
        assert len(recent(path, level="WARNING")) == 1       # solo avisos
        assert recent(path, query="login")[0]["level"] == "WARNING"


class TestBootstrap:
    def _settings(self, tmp_path, url="", sha="", allow=False, sandbox=True,
                  wg_url="", wg_sha=""):
        import types
        return types.SimpleNamespace(
            bootstrap_openvpn_url=url, bootstrap_openvpn_sha256=sha,
            bootstrap_wireguard_url=wg_url, bootstrap_wireguard_sha256=wg_sha,
            bootstrap_dir=tmp_path / "bootstrap", allow_install=allow,
            openvpn_public_endpoint="vpn.miempresa.com",
            wireguard_interface="wg0",
            wireguard_public_endpoint="vpn.miempresa.com",
            wireguard_dns="1.1.1.1",
        )

    def _served(self, tmp_path):
        import hashlib
        script = tmp_path / "install.sh"
        script.write_bytes(b"#!/bin/bash\necho hola\n")
        sha = hashlib.sha256(script.read_bytes()).hexdigest()
        return "file://" + str(script), sha

    def test_verifica_checksum_ok(self, tmp_path):
        from vpn_manager.bootstrap import fetch_and_verify
        url, sha = self._served(tmp_path)
        dest = fetch_and_verify(url, sha, tmp_path / "out.sh")
        assert dest.read_bytes().startswith(b"#!/bin/bash")

    def test_checksum_incorrecto_falla(self, tmp_path):
        from vpn_manager.bootstrap import BootstrapError, fetch_and_verify
        url, _ = self._served(tmp_path)
        with pytest.raises(BootstrapError):
            fetch_and_verify(url, "0" * 64, tmp_path / "out.sh")

    def test_sin_checksum_no_ejecuta(self, tmp_path):
        from vpn_manager.bootstrap import BootstrapError, fetch_and_verify
        url, _ = self._served(tmp_path)
        with pytest.raises(BootstrapError):
            fetch_and_verify(url, "", tmp_path / "out.sh")

    def test_run_sandbox_simula_con_origen(self, tmp_path):
        from vpn_manager.bootstrap import run
        url, sha = self._served(tmp_path)
        r = run("openvpn", self._settings(tmp_path, url, sha), sandbox=True)
        assert r["simulated"] is True and r["plan"]["checksum_configured"] is True
        assert r["plan"]["repo"] == "angristan/openvpn-install"

    def test_run_sin_configurar_falla(self, tmp_path):
        from vpn_manager.bootstrap import BootstrapError, run
        with pytest.raises(BootstrapError):
            run("openvpn", self._settings(tmp_path), sandbox=True)

    def test_detect_public_interface_parsea_ip_route(self, monkeypatch):
        import subprocess as sp

        from vpn_manager import bootstrap

        def fake_run(cmd, **kwargs):
            return sp.CompletedProcess(
                cmd, 0,
                stdout="default via 192.168.1.1 dev eth0 proto dhcp metric 100\n",
                stderr="",
            )

        monkeypatch.setattr(bootstrap.subprocess, "run", fake_run)
        assert bootstrap._detect_public_interface() == "eth0"

    def test_detect_public_interface_sin_ruta_por_defecto(self, monkeypatch):
        import subprocess as sp

        from vpn_manager import bootstrap

        monkeypatch.setattr(
            bootstrap.subprocess, "run",
            lambda cmd, **kwargs: sp.CompletedProcess(cmd, 0, stdout="", stderr=""),
        )
        assert bootstrap._detect_public_interface() is None

    def test_unattended_env_wireguard_incluye_todo_lo_necesario(self, tmp_path, monkeypatch):
        from vpn_manager import bootstrap

        monkeypatch.setattr(bootstrap, "_detect_public_interface", lambda: "eth0")
        env = bootstrap.unattended_env("wireguard", self._settings(tmp_path))

        # Todo lo protegido por un `until <regex>` en el script real debe venir ya
        # resuelto, para que ese `read` nunca llegue a ejecutarse.
        assert env["SERVER_PUB_NIC"] == "eth0"
        assert env["SERVER_WG_NIC"] == "wg0"
        assert env["CLIENT_DNS_1"] == "1.1.1.1"
        assert env["CLIENT_EXISTS"] == "0"
        assert env["CLIENT_NAME"]

    def test_unattended_env_wireguard_omite_nic_si_no_detectada(self, tmp_path, monkeypatch):
        from vpn_manager import bootstrap

        monkeypatch.setattr(bootstrap, "_detect_public_interface", lambda: None)
        env = bootstrap.unattended_env("wireguard", self._settings(tmp_path))
        assert "SERVER_PUB_NIC" not in env

    def test_wireguard_install_stdin_orden_exacto(self, tmp_path):
        from vpn_manager.bootstrap import _wireguard_install_stdin
        s = self._settings(tmp_path)
        assert _wireguard_install_stdin(s) == "vpn.miempresa.com\n\n2\n2\n"

    def test_run_wireguard_sin_interfaz_falla_antes_de_lanzar_el_script(
        self, tmp_path, monkeypatch
    ):
        # Fail-closed: sin interfaz detectada, run() no debe siquiera intentar
        # ejecutar el script (evita el `until` colgado esperando stdin).
        from vpn_manager import bootstrap
        from vpn_manager.bootstrap import BootstrapError

        url, sha = self._served(tmp_path)
        s = self._settings(tmp_path, wg_url=url, wg_sha=sha, allow=True)
        monkeypatch.setattr(bootstrap, "_detect_public_interface", lambda: None)
        monkeypatch.setattr(bootstrap.os, "geteuid", lambda: 0)

        called = []
        monkeypatch.setattr(
            bootstrap.subprocess, "run", lambda *a, **k: called.append(1)
        )
        with pytest.raises(BootstrapError, match="interfaz de red pública"):
            bootstrap.run("wireguard", s, sandbox=False)
        assert called == []  # nunca llegó a invocar el script

    def test_run_wireguard_invoca_con_env_y_stdin_completos(self, tmp_path, monkeypatch):
        import subprocess as sp

        from vpn_manager import bootstrap

        url, sha = self._served(tmp_path)
        s = self._settings(tmp_path, wg_url=url, wg_sha=sha, allow=True)
        monkeypatch.setattr(bootstrap, "_detect_public_interface", lambda: "eth0")
        monkeypatch.setattr(bootstrap.os, "geteuid", lambda: 0)
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["env"] = kwargs.get("env")
            captured["input"] = kwargs.get("input")
            return sp.CompletedProcess(cmd, 0, stdout="ok", stderr="")

        monkeypatch.setattr(bootstrap.subprocess, "run", fake_run)
        r = bootstrap.run("wireguard", s, sandbox=False)

        assert r["installed"] is True
        assert captured["env"]["SERVER_PUB_NIC"] == "eth0"
        assert captured["env"]["SERVER_WG_NIC"] == "wg0"
        assert captured["input"] == "vpn.miempresa.com\n\n2\n2\n"

    def test_uninstall_plan_openvpn_usa_subcomando_force(self, tmp_path):
        # Verifica la invocación exacta contra el commit realmente fijado en
        # config.py (935e559…): ese script ya trae `uninstall --force`
        # desatendido de fábrica, sin necesidad de variables de entorno ni stdin.
        from vpn_manager.bootstrap import uninstall_plan
        url, sha = self._served(tmp_path)
        p = uninstall_plan("openvpn", self._settings(tmp_path, url, sha))
        assert p["checksum_configured"] is True
        assert p["invocation"]["command"][-2:] == ["uninstall", "--force"]
        assert p["invocation"]["needs_stdin_confirmation"] is False

    def test_uninstall_plan_wireguard_necesita_confirmacion_por_stdin(self, tmp_path):
        # El script de WireGuard pineado (832fb98…) sigue siendo el estilo de menú
        # interactivo: MENU_OPTION=4 salta el menú, pero uninstallWg() hace un
        # `read` incondicional que SIEMPRE requiere una respuesta por stdin.
        from vpn_manager.bootstrap import uninstall_plan
        url, sha = self._served(tmp_path)
        p = uninstall_plan(
            "wireguard", self._settings(tmp_path, wg_url=url, wg_sha=sha)
        )
        assert p["checksum_configured"] is True
        assert p["invocation"]["env"] == {"MENU_OPTION": "4"}
        assert p["invocation"]["needs_stdin_confirmation"] is True

    def test_run_uninstall_sandbox_simula(self, tmp_path):
        from vpn_manager.bootstrap import run_uninstall
        url, sha = self._served(tmp_path)
        r = run_uninstall("openvpn", self._settings(tmp_path, url, sha), sandbox=True)
        assert r["simulated"] is True and r["uninstalled"] is False

    def test_run_uninstall_sin_configurar_falla(self, tmp_path):
        from vpn_manager.bootstrap import BootstrapError, run_uninstall
        with pytest.raises(BootstrapError):
            run_uninstall("openvpn", self._settings(tmp_path), sandbox=True)

    def test_run_uninstall_openvpn_invoca_subcomando_real(self, tmp_path, monkeypatch):
        # No ejecuta el script real (requiere root) — intercepta subprocess.run y
        # comprueba que la línea de comandos es exactamente la esperada.
        import subprocess as sp

        from vpn_manager import bootstrap

        url, sha = self._served(tmp_path)
        s = self._settings(tmp_path, url, sha, allow=True)
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["env"] = kwargs.get("env")
            captured["input"] = kwargs.get("input")
            return sp.CompletedProcess(cmd, 0, stdout="ok", stderr="")

        monkeypatch.setattr(bootstrap.os, "geteuid", lambda: 0)
        monkeypatch.setattr(bootstrap.subprocess, "run", fake_run)
        r = bootstrap.run_uninstall("openvpn", s, sandbox=False)

        assert r["uninstalled"] is True
        assert captured["cmd"][-2:] == ["uninstall", "--force"]
        assert captured["input"] is None

    def test_run_uninstall_wireguard_invoca_menu_y_confirma_por_stdin(self, tmp_path, monkeypatch):
        import subprocess as sp

        from vpn_manager import bootstrap

        url, sha = self._served(tmp_path)
        s = self._settings(tmp_path, wg_url=url, wg_sha=sha, allow=True)
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["env"] = kwargs.get("env")
            captured["input"] = kwargs.get("input")
            return sp.CompletedProcess(cmd, 0, stdout="ok", stderr="")

        monkeypatch.setattr(bootstrap.os, "geteuid", lambda: 0)
        monkeypatch.setattr(bootstrap.subprocess, "run", fake_run)
        r = bootstrap.run_uninstall("wireguard", s, sandbox=False)

        assert r["uninstalled"] is True
        assert captured["env"]["MENU_OPTION"] == "4"
        assert captured["input"] == "y\n"

    def test_run_uninstall_deshabilitada_en_prod(self, tmp_path):
        from vpn_manager.bootstrap import BootstrapError, run_uninstall
        url, sha = self._served(tmp_path)
        with pytest.raises(BootstrapError):
            run_uninstall("openvpn", self._settings(tmp_path, url, sha, allow=False), sandbox=False)


class TestDelivery:
    def test_guardar_dentro_del_base(self, tmp_path):
        from vpn_manager.delivery import save_to_server

        p = save_to_server("contenido", "alice.ovpn", "subcarpeta", tmp_path)
        assert p.read_text() == "contenido"
        assert tmp_path in p.parents

    def test_guardar_fuera_del_base_falla(self, tmp_path):
        from vpn_manager.delivery import DeliveryError, save_to_server

        with pytest.raises(DeliveryError):
            save_to_server("x", "a.ovpn", "../../etc", tmp_path)

    def test_email_invalido(self):
        from vpn_manager.delivery import DeliveryError, validate_email

        with pytest.raises(DeliveryError):
            validate_email("no-es-un-email")

    def test_email_simulado_en_sandbox(self, tmp_path, monkeypatch):
        from vpn_manager.delivery import send_email

        monkeypatch.setattr(settings, "export_dir", tmp_path)
        monkeypatch.setattr(settings, "smtp_host", "")
        res = send_email("config", "ana.conf", "ana@empresa.com", settings, sandbox=True)
        assert res["simulated"] is True and res["to"] == "ana@empresa.com"
        assert list((tmp_path / "outbox").glob("*.eml"))


class TestWriteApi:
    @pytest.fixture(autouse=True)
    def _isolate(self, tmp_path, monkeypatch):
        pki = tmp_path / "pki"
        pki.mkdir()
        shutil.copy(settings.openvpn_pki_index, pki / "index.txt")
        status = tmp_path / "openvpn-status.log"
        shutil.copy(settings.openvpn_status_file, status)
        conf = tmp_path / "server.conf"
        shutil.copy(settings.openvpn_server_conf, conf)
        monkeypatch.setattr(settings, "openvpn_pki_index", pki / "index.txt")
        monkeypatch.setattr(settings, "openvpn_status_file", status)
        monkeypatch.setattr(settings, "openvpn_server_conf", conf)
        monkeypatch.setattr(settings, "export_dir", tmp_path / "exports")
        self.client = TestClient(app)
        _login(self.client)

    def test_alta_revoca_y_descarga_por_api(self):
        r = self.client.post("/api/openvpn/clients", json={"name": "tablet-jose"})
        assert r.status_code == 201
        assert r.json()["status"] == "valid"

        r = self.client.get("/api/openvpn/clients/tablet-jose/config")
        assert r.status_code == 200
        assert "tablet-jose" in r.text
        assert "attachment" in r.headers["content-disposition"]

        r = self.client.post("/api/openvpn/clients/tablet-jose/revoke")
        assert r.status_code == 200
        assert r.json()["status"] == "revoked"

        # tras revocar, la descarga se bloquea
        assert self.client.get("/api/openvpn/clients/tablet-jose/config").status_code == 403

    def test_codigos_de_error(self):
        assert self.client.post("/api/openvpn/clients", json={"name": "alice-laptop"}).status_code == 409
        assert self.client.post("/api/openvpn/clients", json={"name": "a b"}).status_code == 422
        assert self.client.post("/api/openvpn/clients/server/revoke").status_code == 403
        assert self.client.post("/api/openvpn/clients/fantasma/revoke").status_code == 404

    def test_control_servicio_y_logs(self):
        assert self.client.post("/api/openvpn/service/restart").json()["active"] is True
        assert self.client.post("/api/openvpn/service/stop").json()["active"] is False
        assert self.client.post("/api/openvpn/service/bogus").status_code == 422
        r = self.client.get("/api/openvpn/logs")
        assert r.status_code == 200
        assert isinstance(r.json()["lines"], list)

    def test_servicio_requiere_login(self):
        c = TestClient(app)
        assert c.post("/api/openvpn/service/restart").status_code == 401
        assert c.get("/api/openvpn/logs").status_code == 401

    def test_renovar_y_desconectar_por_api(self):
        r = self.client.post("/api/openvpn/clients/dave-expired/renew")
        assert r.status_code == 200 and r.json()["status"] == "valid"
        r = self.client.post("/api/openvpn/connections/alice-laptop/disconnect")
        assert r.status_code == 204
        # ya no aparece como conectada
        names = [c["name"] for c in self.client.get("/api/openvpn/connections").json()]
        assert "alice-laptop" not in names

    def test_info_servidor_por_api(self):
        r = self.client.get("/api/openvpn/server")
        assert r.status_code == 200
        d = r.json()
        assert d["port"] == "1194"
        assert d["public_endpoint"]
        assert len(d["directives"]) > 10

    def test_guardar_y_enviar_config_por_api(self):
        r = self.client.post("/api/openvpn/clients/alice-laptop/save", json={"path": "equipo-ana"})
        assert r.status_code == 200 and r.json()["saved"] is True
        # ruta fuera del directorio permitido → 422
        r = self.client.post("/api/openvpn/clients/alice-laptop/save", json={"path": "/etc"})
        assert r.status_code == 422
        # email simulado en sandbox
        r = self.client.post("/api/openvpn/clients/alice-laptop/email", json={"email": "ana@empresa.com"})
        assert r.status_code == 200 and r.json()["simulated"] is True
        # email inválido → 422
        r = self.client.post("/api/openvpn/clients/alice-laptop/email", json={"email": "malo"})
        assert r.status_code == 422

    def test_editar_config_servidor_por_api(self):
        sc = self.client.get("/api/openvpn/server/schema").json()
        assert any(f["key"] == "proto" and f["type"] == "select" for f in sc["fields"])
        r = self.client.put("/api/openvpn/server", json={"directives": [
            {"key": "port", "value": "1200"}, {"key": "proto", "value": "udp"},
        ]})
        assert r.status_code == 200 and r.json()["port"] == "1200"
        # valor inválido → 422
        r = self.client.put("/api/openvpn/server", json={"directives": [
            {"key": "port", "value": "abc"}]})
        assert r.status_code == 422


class TestAuthModule:
    def test_hash_y_verify(self):
        from vpn_manager.auth import hash_password, verify_password

        h = hash_password("s3creto", iterations=1000)  # iteraciones bajas: test rápido
        assert verify_password("s3creto", h)
        assert not verify_password("otra", h)
        assert not verify_password("s3creto", "formato-malo")

    def test_produccion_sin_password_no_arranca(self):
        from vpn_manager.auth import resolve_credentials

        with pytest.raises(RuntimeError):
            resolve_credentials("admin", "", sandbox=False)

    def test_sandbox_sin_password_usa_dev(self):
        from vpn_manager.auth import resolve_credentials, verify_password

        user, h = resolve_credentials("admin", "", sandbox=True)
        assert user == "admin"
        assert verify_password("admin", h)

    def test_throttle_bloquea_tras_n_intentos(self):
        from vpn_manager.auth import LoginThrottle

        t = LoginThrottle(max_attempts=3, lock_seconds=300)
        assert not t.is_blocked("1.2.3.4")
        for _ in range(3):
            t.record_failure("1.2.3.4")
        assert t.is_blocked("1.2.3.4")
        t.reset("1.2.3.4")
        assert not t.is_blocked("1.2.3.4")

    def test_secret_key_obligatoria_en_produccion(self):
        from vpn_manager.auth import resolve_secret

        with pytest.raises(RuntimeError):
            resolve_secret("", sandbox=False)
        assert resolve_secret("una-clave", sandbox=False) == "una-clave"
        assert len(resolve_secret("", sandbox=True)) == 64  # efímera en dev


class TestSecurityHeaders:
    def test_cabeceras_de_seguridad(self):
        r = TestClient(app).get("/health")
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
        assert r.headers["referrer-policy"] == "no-referrer"

    def test_api_no_se_cachea(self):
        c = TestClient(app)
        _login(c)
        r = c.get("/api/openvpn/clients")
        assert r.headers["cache-control"] == "no-store"

    def test_hsts_solo_con_https(self, monkeypatch):
        # Sin cookie_secure (HTTP) no hay HSTS.
        assert "strict-transport-security" not in TestClient(app).get("/health").headers
        # Con cookie_secure (detrás de HTTPS) sí.
        monkeypatch.setattr(settings, "cookie_secure", True)
        r = TestClient(app).get("/health")
        assert "max-age=" in r.headers.get("strict-transport-security", "")
