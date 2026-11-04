"""Modo real (sandbox=False) contra una PKI de verdad hecha con openssl.

`tests/fixtures/fake-easyrsa.sh` imita los subcomandos de easy-rsa que usa el panel con `openssl ca`.
Cubre lo que antes fallaba en producción: el .ovpn salía sin CA/certificado/clave/clave TLS, la CRL no
llegaba a donde la lee el servidor y el certificado del servidor (server_<aleatorio>) se podía revocar.
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from vpn_manager.backends.base import Forbidden
from vpn_manager.backends.openvpn import OpenVpnBackend

FIX = Path(__file__).parent / "fixtures"
pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="requiere openssl")


def _pki(tmp_path: Path, tls: str) -> Path:
    srv = tmp_path / "server"
    er = srv / "easy-rsa"
    for d in ("issued", "private", "reqs", "newcerts"):
        (er / "pki" / d).mkdir(parents=True)
    shutil.copy(FIX / "fake-easyrsa.sh", er / "easyrsa")
    (er / "easyrsa").chmod(0o755)
    shutil.copy(FIX / "fake-easyrsa-openssl.cnf", er / "openssl.cnf")
    (er / "pki" / "index.txt").write_text("")
    (er / "pki" / "serial").write_text("1000\n")
    (er / "pki" / "crlnumber").write_text("1000\n")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-subj", "/CN=CA", "-keyout", "pki/private/ca.key", "-out", "pki/ca.crt",
                    "-days", "30"], cwd=er, check=True, capture_output=True)
    subprocess.run(["./easyrsa", "--batch", "build-server-full", "server_abc"], cwd=er, check=True)
    subprocess.run(["./easyrsa", "gen-crl"], cwd=er, check=True)
    shutil.copy(er / "pki" / "crl.pem", srv / "crl.pem")
    if tls == "tls-crypt-v2":
        subprocess.run(["openvpn", "--genkey", "tls-crypt-v2-server", "tls-crypt-v2.key"], cwd=srv, check=True)
    else:
        (srv / "tls-crypt.key").write_text("-----BEGIN OpenVPN Static key V1-----\nabc\n-----END OpenVPN Static key V1-----\n")
    (srv / "server.conf").write_text(
        f"port 1194\ncert server_abc.crt\n{tls} {tls}.key\ncrl-verify crl.pem\n"
    )
    (srv / "client-template.txt").write_text("client\nremote 203.0.113.10 1194\nverify-x509-name server_abc name\n")
    return srv


def _backend(srv: Path) -> OpenVpnBackend:
    return OpenVpnBackend(pki_index=srv / "easy-rsa/pki/index.txt", status_file=srv / "status.log",
                          service="x", sandbox=False, server_conf=srv / "server.conf")


@pytest.mark.parametrize("tls", [
    "tls-crypt",
    pytest.param("tls-crypt-v2", marks=pytest.mark.skipif(shutil.which("openvpn") is None, reason="requiere openvpn")),
])
def test_config_real_completa_y_verificable(tmp_path, tls):
    srv = _pki(tmp_path, tls)
    b = _backend(srv)
    b.create_client("portatil1")
    cfg = b.client_config("portatil1")
    for tag in ("ca", "cert", "key", tls):
        assert f"<{tag}>" in cfg and f"</{tag}>" in cfg
    assert "verify-x509-name server_abc name" in cfg            # usa la plantilla del instalador
    (tmp_path / "ca.pem").write_text(re.search(r"<ca>\n(.*?)\n</ca>", cfg, re.DOTALL).group(1) + "\n")
    (tmp_path / "c.pem").write_text(re.search(r"<cert>\n(.*?)\n</cert>", cfg, re.DOTALL).group(1) + "\n")
    ok = subprocess.run(["openssl", "verify", "-CAfile", "ca.pem", "c.pem"], check=False, cwd=tmp_path, capture_output=True, text=True)
    assert ok.returncode == 0
    assert (srv / "easy-rsa/clients/portatil1.ovpn").stat().st_mode & 0o777 == 0o600


def test_retirar_publica_la_crl_que_lee_el_servidor(tmp_path):
    srv = _pki(tmp_path, "tls-crypt")
    b = _backend(srv)
    client = b.create_client("portatil1")
    b.revoke_client("portatil1")
    crl = subprocess.run(["openssl", "crl", "-in", "crl.pem", "-noout", "-text"], cwd=srv,
                         capture_output=True, text=True, check=True).stdout
    assert client.serial.upper() in crl.upper()
    assert (srv / "crl.pem").stat().st_mode & 0o777 == 0o644
    assert not (srv / "easy-rsa/clients/portatil1.ovpn").exists()


def test_certificado_del_servidor_protegido(tmp_path):
    b = _backend(_pki(tmp_path, "tls-crypt"))
    assert "server_abc" not in [c.name for c in b.clients()]
    with pytest.raises(Forbidden):
        b.revoke_client("server_abc")


def test_renovar_toma_la_entrada_nueva_y_regenera_la_config(tmp_path):
    b = _backend(_pki(tmp_path, "tls-crypt"))
    b.create_client("movil1")
    old = b.client_config("movil1")
    assert b.renew_client("movil1").status == "valid"
    assert b.client_config("movil1") != old
    assert [(c.name, c.status) for c in b.clients()] == [("movil1", "valid")]


def test_wireguard_lee_y_escribe_el_formato_de_angristan(tmp_path):
    from vpn_manager.backends.wireguard import WireGuardBackend

    conf = tmp_path / "wg0.conf"
    conf.write_text(
        "[Interface]\nAddress = 10.66.66.1/24\nListenPort = 51820\nPrivateKey = cE8i3nqkvQtUxbJxJbu1F0xj3gJ6ePq9u0x5o4xX0kE=\n"
        "\n### Client cliente1\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs = 10.66.66.2/32\n"
    )
    b = WireGuardBackend(conf=conf, show_file=tmp_path / "show.txt", service="x", sandbox=True)
    assert [c.name for c in b.clients()] == ["cliente1"]          # antes: «Client cliente1»
    b.create_client("movil1")
    assert "### Client movil1" in conf.read_text()
    b.revoke_client("cliente1")
    assert "cliente1" not in conf.read_text() and [c.name for c in b.clients()] == ["movil1"]


def test_wireguard_real_sin_clave_guardada_da_error_claro(tmp_path):
    from vpn_manager.backends.base import VpnError
    from vpn_manager.backends.wireguard import WireGuardBackend

    conf = tmp_path / "wg0.conf"
    conf.write_text("[Interface]\nAddress = 10.66.66.1/24\n\n### Client cliente1\n[Peer]\nPublicKey = AAAA=\nAllowedIPs = 10.66.66.2/32\n")
    b = WireGuardBackend(conf=conf, show_file=tmp_path / "show.txt", service="x", sandbox=False)
    with pytest.raises(VpnError, match="clave privada"):
        b.client_config("cliente1")


def _fake_management(sock_path, password=None):
    """Servidor de management de pruebas: imita el banner, la contraseña y `kill <cn>`."""
    import socket as so
    import threading

    srv = so.socket(so.AF_UNIX, so.SOCK_STREAM)
    srv.bind(str(sock_path))
    srv.listen(1)
    seen = []

    def run():
        conn, _ = srv.accept()
        f = conn.makefile("rb")
        if password:
            conn.sendall(b"ENTER PASSWORD:")
            given = f.readline().decode().strip()
            if given != password:
                conn.sendall(b"ERROR: bad password\r\n")
                conn.close()
                return
            conn.sendall(b"SUCCESS: password is correct\r\n")
        conn.sendall(b">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n")
        cmd = f.readline().decode().strip()
        seen.append(cmd)
        cn = cmd.split(" ", 1)[1]
        if cn == "conectado":
            conn.sendall(f"SUCCESS: common name '{cn}' found, 1 client(s) killed\r\n".encode())
        else:
            conn.sendall(f"ERROR: common name '{cn}' not found\r\n".encode())
        conn.close()

    threading.Thread(target=run, daemon=True).start()
    return srv, seen


@pytest.mark.parametrize("password", [None, "secreto"])
def test_desconectar_en_produccion_por_management(tmp_path, password):
    import socket as so

    if not hasattr(so, "AF_UNIX"):
        pytest.skip("sin sockets Unix")
    srv = _pki(tmp_path, "tls-crypt")
    sock = tmp_path / "m.sock"
    extra = ""
    if password:
        (srv / "mgmt.pw").write_text(password + "\n")
        extra = " mgmt.pw"
    (srv / "server.conf").write_text((srv / "server.conf").read_text() + f"management {sock} unix{extra}\n")
    b = _backend(srv)
    server, seen = _fake_management(sock, password)
    try:
        assert b._management_kill("conectado") is True
        assert seen == ["kill conectado"]
    finally:
        server.close()


def test_desconectar_sin_management_explica_como_activarlo(tmp_path):
    from vpn_manager.backends.base import VpnError

    b = _backend(_pki(tmp_path, "tls-crypt"))
    with pytest.raises(VpnError, match="management"):
        b._management_kill("x")
