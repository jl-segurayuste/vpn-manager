from vpn_manager import auth, totp
from vpn_manager.users import UserStore


def _store(tmp_path):
    return UserStore(tmp_path / "users.json", "admin", auth.hash_password("x"))


def test_verify_totp_codigo_correcto_pasa(tmp_path):
    store = _store(tmp_path)
    secret = totp.generate_secret()
    store.set_totp_secret("admin", secret)
    assert store.verify_totp("admin", totp.now_code(secret)) is True


def test_verify_totp_codigo_incorrecto_no_pasa(tmp_path):
    store = _store(tmp_path)
    secret = totp.generate_secret()
    store.set_totp_secret("admin", secret)
    assert store.verify_totp("admin", "000000") is False


def test_verify_totp_sin_secreto_configurado_no_pasa(tmp_path):
    store = _store(tmp_path)
    assert store.verify_totp("admin", "000000") is False


def test_verify_totp_usuario_inexistente_no_pasa(tmp_path):
    store = _store(tmp_path)
    assert store.verify_totp("fantasma", "000000") is False


def test_verify_totp_no_deja_reutilizar_el_mismo_codigo(tmp_path):
    # Bug real encontrado 2026-08-09: sin este registro, el mismo código
    # TOTP válido se podía reenviar un número ilimitado de veces (visto en
    # un log, capturado por encima del hombro...) y siempre se aceptaba --
    # anulando la garantía anti-repetición que es la razón de ser de TOTP
    # frente a una contraseña estática.
    store = _store(tmp_path)
    secret = totp.generate_secret()
    store.set_totp_secret("admin", secret)
    code = totp.now_code(secret)

    assert store.verify_totp("admin", code) is True
    assert store.verify_totp("admin", code) is False


def test_verify_totp_permite_el_siguiente_codigo_temporal(tmp_path):
    store = _store(tmp_path)
    secret = totp.generate_secret()
    store.set_totp_secret("admin", secret)
    at = 1_700_000_000.0

    assert store.verify_totp("admin", totp.now_code(secret, at=at), at=at) is True
    at_siguiente = at + 30
    assert (
        store.verify_totp("admin", totp.now_code(secret, at=at_siguiente), at=at_siguiente)
        is True
    )
