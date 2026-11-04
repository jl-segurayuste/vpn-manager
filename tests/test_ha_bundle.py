import zipfile
from io import BytesIO

import pytest

from vpn_manager.ha_bundle import (
    FailoverConfig,
    build_bundle_zip,
    render_failover_script,
    render_readme,
    render_wireguard_conf_with_dns,
)

_WG_CONF_REAL = (
    "# Configuración WireGuard para «alice»\n"
    "[Interface]\n"
    "PrivateKey = clave-privada-real\n"
    "Address = 10.9.0.5/32\n"
    "DNS = 1.1.1.1\n\n"
    "[Peer]\n"
    "PublicKey = servidor-pubkey\n"
    "Endpoint = vpn.miempresa.com:51820\n"
    "AllowedIPs = 0.0.0.0/0, ::/0\n"
    "PersistentKeepalive = 25\n"
)


class TestRenderWireguardConfWithDns:
    def test_sin_split_dns_no_toca_nada(self):
        cfg = FailoverConfig(name="alice", health_check_hosts=["10.0.0.1"])
        out = render_wireguard_conf_with_dns(_WG_CONF_REAL, cfg)
        assert out == _WG_CONF_REAL

    def test_con_split_dns_quita_dns_plano_y_anade_postup_postdown(self):
        cfg = FailoverConfig(
            name="alice",
            health_check_hosts=["10.0.0.1"],
            split_dns_domain="~miempresa.local",
            dns_servers=["10.0.0.53", "10.0.0.54"],
        )
        out = render_wireguard_conf_with_dns(_WG_CONF_REAL, cfg)
        assert "DNS = 1.1.1.1" not in out  # la línea plana desaparece
        assert 'PostUp = resolvectl dns %i 10.0.0.53 10.0.0.54' in out
        assert "resolvectl domain %i '~miempresa.local'" in out
        assert "PostDown = resolvectl revert %i" in out
        # el PostUp/PostDown va justo tras PrivateKey, dentro de [Interface]
        lines = out.splitlines()
        idx_priv = next(i for i, ln in enumerate(lines) if ln.startswith("PrivateKey"))
        assert lines[idx_priv + 1].startswith("PostUp")
        assert lines[idx_priv + 2].startswith("PostDown")

    def test_sin_dns_servers_no_activa_split_dns_aunque_haya_dominio(self):
        cfg = FailoverConfig(
            name="alice", health_check_hosts=["10.0.0.1"], split_dns_domain="~x.local",
        )
        out = render_wireguard_conf_with_dns(_WG_CONF_REAL, cfg)
        assert out == _WG_CONF_REAL

    def test_plantilla_sin_privatekey_real_no_revienta(self):
        plantilla = "[Interface]\nAddress = 10.9.0.5/32\n\n[Peer]\nPublicKey = x\n"
        cfg = FailoverConfig(
            name="alice", health_check_hosts=["10.0.0.1"],
            split_dns_domain="~x.local", dns_servers=["10.0.0.53"],
        )
        out = render_wireguard_conf_with_dns(plantilla, cfg)
        assert "PostUp = resolvectl dns %i 10.0.0.53" in out
        assert "PostDown = resolvectl revert %i" in out


class TestRenderFailoverScript:
    def test_incluye_los_hosts_y_puerto_de_salud(self):
        cfg = FailoverConfig(
            name="alice", health_check_hosts=["10.10.0.64", "10.10.0.60"],
            health_check_port=8006,
        )
        script = render_failover_script(cfg)
        assert "HEALTH_HOSTS=(10.10.0.64 10.10.0.60)" in script
        assert "HEALTH_PORT=8006" in script

    def test_limpia_interfaz_existente_antes_de_wg_quick_up(self):
        # Regresión concreta: wg-quick up falla con "already exists" si la
        # interfaz de un failover anterior no se revirtió limpiamente.
        cfg = FailoverConfig(name="alice", health_check_hosts=["10.0.0.1"])
        script = render_failover_script(cfg)
        assert "wg-quick down" in script
        assert "ip link delete dev" in script
        assert 'if ip link show "$WG_IFACE"' in script

    def test_no_vuelve_solo_a_la_primaria(self):
        cfg = FailoverConfig(name="alice", health_check_hosts=["10.0.0.1"])
        script = render_failover_script(cfg)
        assert "No vuelve a la primaria en" in script

    def test_notify_webhook_vacio_no_incluye_url(self):
        cfg = FailoverConfig(name="alice", health_check_hosts=["10.0.0.1"])
        script = render_failover_script(cfg)
        assert 'NOTIFY_URL=""' in script

    def test_notify_webhook_configurado_se_incluye(self):
        cfg = FailoverConfig(
            name="alice", health_check_hosts=["10.0.0.1"],
            notify_webhook="https://ntfy.example.com/vpn",
        )
        script = render_failover_script(cfg)
        assert "NOTIFY_URL=https://ntfy.example.com/vpn" in script


class TestRenderReadme:
    def test_menciona_los_tres_ficheros_y_el_intervalo(self):
        cfg = FailoverConfig(
            name="alice", health_check_hosts=["10.0.0.1"], check_interval_seconds=30,
        )
        readme = render_readme(cfg)
        assert "alice.ovpn" in readme
        assert "alice-backup.conf" in readme
        assert "alice-failover.sh" in readme
        assert "30 segundos" in readme


class TestBuildBundleZip:
    def test_zip_contiene_los_cuatro_ficheros_esperados(self):
        cfg = FailoverConfig(
            name="alice", health_check_hosts=["10.0.0.1"],
            split_dns_domain="~x.local", dns_servers=["10.0.0.53"],
        )
        data = build_bundle_zip(
            openvpn_conf="contenido-ovpn-de-prueba", wireguard_conf=_WG_CONF_REAL, cfg=cfg,
        )
        with zipfile.ZipFile(BytesIO(data)) as zf:
            names = set(zf.namelist())
            assert names == {
                "alice.ovpn", "alice-backup.conf", "alice-failover.sh", "README.md",
            }
            assert zf.read("alice.ovpn").decode() == "contenido-ovpn-de-prueba"
            assert "PostUp = resolvectl" in zf.read("alice-backup.conf").decode()
            assert "#!/usr/bin/env bash" in zf.read("alice-failover.sh").decode()


class TestValidacionYNombres:
    def test_nombre_largo_recorta_la_interfaz_a_15_caracteres(self):
        from vpn_manager.ha_bundle import backup_iface

        assert backup_iface("alice") == "alice-backup"
        largo = backup_iface("portatil-de-marketing")
        assert len(largo) == 15 and largo.endswith("-backup")
        cfg = FailoverConfig(name="portatil-de-marketing", health_check_hosts=["10.0.0.1"])
        data = build_bundle_zip(openvpn_conf="x", wireguard_conf=_WG_CONF_REAL, cfg=cfg)
        with zipfile.ZipFile(BytesIO(data)) as zf:
            assert f"{largo}.conf" in zf.namelist()
            assert f"WG_IFACE={largo}" in zf.read("portatil-de-marketing-failover.sh").decode()

    @pytest.mark.parametrize("campo, valor", [
        ("health_check_hosts", ["10.0.0.1; rm -rf /"]),
        ("health_check_hosts", ["$(id)"]),
        ("dns_servers", ["10.0.0.53; curl x"]),
        ("split_dns_domain", '~x.local"; id; echo "'),
        ("notify_webhook", 'https://x/"; id; echo "'),
        ("notify_webhook", "ftp://x/y"),
    ])
    def test_rechaza_valores_que_inyectarian_ordenes(self, campo, valor):
        from vpn_manager.ha_bundle import BundleError

        kwargs = {"name": "alice", "health_check_hosts": ["10.0.0.1"],
                  "dns_servers": ["10.0.0.53"], "split_dns_domain": "~x.local", campo: valor}
        with pytest.raises(BundleError):
            build_bundle_zip(openvpn_conf="x", wireguard_conf=_WG_CONF_REAL,
                             cfg=FailoverConfig(**kwargs))

    def test_admite_ipv6_y_url_con_parametros(self):
        cfg = FailoverConfig(name="alice", health_check_hosts=["fd00::1", "nas.lan"],
                             dns_servers=["fd00::53"], split_dns_domain="~.",
                             notify_webhook="https://ntfy.sh/vpn?priority=high")
        script = render_failover_script(cfg)
        assert "NOTIFY_URL='https://ntfy.sh/vpn?priority=high'" in script
        build_bundle_zip(openvpn_conf="x", wireguard_conf=_WG_CONF_REAL, cfg=cfg)
