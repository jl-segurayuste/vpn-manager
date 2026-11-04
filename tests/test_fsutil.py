from vpn_manager import delivery
from vpn_manager.fsutil import write_private


def test_fichero_nuevo_sin_permisos_para_otros(tmp_path):
    p = tmp_path / "cliente.conf"
    write_private(p, "PrivateKey = x\n")
    assert p.read_text() == "PrivateKey = x\n"
    assert p.stat().st_mode & 0o777 == 0o600
    assert list(tmp_path.iterdir()) == [p]          # sin temporales sueltos


def test_conserva_los_permisos_de_un_fichero_existente(tmp_path):
    p = tmp_path / "wg0.conf"
    p.write_text("viejo")
    p.chmod(0o640)
    write_private(p, "nuevo")
    assert p.read_text() == "nuevo" and p.stat().st_mode & 0o777 == 0o640


def test_guardar_config_en_el_servidor_es_privado(tmp_path):
    path = delivery.save_to_server("PrivateKey = x\n", "ana.conf", "equipo", tmp_path)
    assert path.stat().st_mode & 0o777 == 0o600


def test_correo_con_barras_rechazado():
    import pytest

    with pytest.raises(delivery.DeliveryError):
        delivery.validate_email("../../x@ejemplo.com")
