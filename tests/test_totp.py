from vpn_manager import totp


def test_now_code_y_verify_coinciden():
    secret = totp.generate_secret()
    code = totp.now_code(secret)
    assert totp.verify(secret, code)


def test_codigo_incorrecto_no_verifica():
    secret = totp.generate_secret()
    assert not totp.verify(secret, "000000")


def test_verify_admite_espacios():
    secret = totp.generate_secret()
    code = totp.now_code(secret)
    assert totp.verify(secret, f"{code[:3]} {code[3:]}")


def test_sin_secreto_o_sin_codigo_no_verifica():
    secret = totp.generate_secret()
    assert not totp.verify("", totp.now_code(secret))
    assert not totp.verify(secret, "")


def test_verify_es_sin_estado_no_impide_reutilizar():
    # `verify()` por si sola no lleva registro de qué códigos ya se usaron --
    # eso es responsabilidad de quien la llame con estado persistente (ver
    # UserStore.verify_totp en test_users.py). Se deja constancia explícita
    # aquí porque es la trampa exacta que causó el bug real encontrado
    # 2026-08-09: se asumía que "expira a los 30s" ya bastaba como
    # protección anti-repetición.
    secret = totp.generate_secret()
    code = totp.now_code(secret)
    assert totp.verify(secret, code)
    assert totp.verify(secret, code)


def test_find_matching_step_devuelve_el_step_que_coincidio():
    secret = totp.generate_secret()
    at = 1_700_000_000.0
    code = totp.now_code(secret, at=at)
    step = totp.find_matching_step(secret, code, at=at)
    assert step == int(at // 30)


def test_find_matching_step_ninguna_coincidencia_devuelve_none():
    secret = totp.generate_secret()
    assert totp.find_matching_step(secret, "000000") is None
