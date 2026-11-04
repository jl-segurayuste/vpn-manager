"""Regenera las capturas de docs/img/ (las del README).

Arranca el panel sobre una copia temporal del sandbox (datos ficticios, sin el rastro de
sandbox/data/) y recorre cada sección con un Chrome sin interfaz. Uso:
    pip install -e ".[e2e]" && python e2e/capturas.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "docs" / "img"
SERVER_PY = sys.executable
PORT = 8233
BASE = f"http://127.0.0.1:{PORT}"

work = Path(tempfile.mkdtemp(prefix="vpnm-capturas-"))
sb = work / "sandbox"
shutil.copytree(REPO / "sandbox", sb, ignore=shutil.ignore_patterns("data", "exports"))
(sb / "data").mkdir()
ov, wg, data = sb / "openvpn", sb / "wireguard", sb / "data"
env = {
    **os.environ,
    "VPNM_HOST": "127.0.0.1", "VPNM_PORT": str(PORT), "VPNM_SANDBOX": "true",
    "VPNM_OPENVPN_PKI_INDEX": str(ov / "pki" / "index.txt"),
    "VPNM_OPENVPN_STATUS_FILE": str(ov / "openvpn-status.log"),
    "VPNM_OPENVPN_LOG_FILE": str(ov / "openvpn.log"),
    "VPNM_OPENVPN_SERVER_CONF": str(ov / "server.conf"),
    "VPNM_WIREGUARD_CONF": str(wg / "wg0.conf"),
    "VPNM_WIREGUARD_SHOW_FILE": str(wg / "wg-show.txt"),
    "VPNM_WIREGUARD_LOG_FILE": str(wg / "wireguard.log"),
    "VPNM_USERS_FILE": str(data / "users.json"),
    "VPNM_AUDIT_FILE": str(data / "audit.jsonl"),
    "VPNM_EXPORT_DIR": str(sb / "exports"),
}
proc = subprocess.Popen([SERVER_PY, "-m", "vpn_manager"], env=env, cwd=str(REPO))
try:
    for _ in range(60):
        try:
            if urllib.request.urlopen(f"{BASE}/health", timeout=2).status == 200:
                break
        except OSError:  # aún arrancando
            time.sleep(0.4)
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=True)  # Chromium de Playwright
        except Exception:  # noqa: BLE001
            browser = p.chromium.launch(channel="chrome", headless=True)  # Chrome del sistema
        ctx = browser.new_context(viewport={"width": 1280, "height": 800}, device_scale_factor=1,
                                  color_scheme="light", locale="es-ES")
        page = ctx.new_page()
        page.goto(f"{BASE}/login")
        page.wait_for_timeout(500)
        page.screenshot(path=str(OUT / "login.png"))
        page.fill("#u", "admin")
        page.fill("#p", "admin")
        page.click("button[type=submit]")
        page.wait_for_url(f"{BASE}/")
        page.wait_for_timeout(1500)
        for name in ["resumen", "clientes", "conexiones", "servidor", "servicio",
                     "registros", "sistema", "usuarios", "cuenta"]:
            page.evaluate(f"showPage('{name}')")
            page.wait_for_timeout(1200)
            page.screenshot(path=str(OUT / f"{name}.png"))
            print("ok", name)
        # Alta de un dispositivo: el diálogo con el formulario.
        page.evaluate("showPage('clientes')")
        page.wait_for_timeout(600)
        page.click("#add-btn")
        page.fill("#add-name", "portatil-nuevo")
        page.wait_for_timeout(500)
        page.screenshot(path=str(OUT / "alta-dispositivo.png"))
        page.click("button:has-text('Crear acceso')")
        page.wait_for_selector("text=portatil-nuevo", timeout=8000)
        page.wait_for_timeout(800)
        page.evaluate("showPage('actividad')")
        page.wait_for_timeout(1200)
        page.screenshot(path=str(OUT / "actividad.png"))
        # WireGuard.
        page.evaluate("setBackend('wireguard')")
        page.wait_for_timeout(1500)
        for name in ["clientes", "conexiones", "servidor"]:
            page.evaluate(f"showPage('{name}')")
            page.wait_for_timeout(1200)
            page.screenshot(path=str(OUT / f"wireguard-{name}.png"))
            print("ok wireguard", name)
        page.evaluate("setBackend('openvpn')")
        page.wait_for_timeout(1000)
        # Vista móvil.
        m = browser.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2,
                                color_scheme="light", locale="es-ES", storage_state=ctx.storage_state())
        mp = m.new_page()
        mp.goto(f"{BASE}/")
        mp.wait_for_timeout(1500)
        mp.screenshot(path=str(OUT / "movil.png"))
        mp.evaluate("showPage('clientes')")
        mp.wait_for_timeout(1200)
        mp.screenshot(path=str(OUT / "movil-dispositivos.png"))
        browser.close()
finally:
    proc.terminate()
    proc.wait(timeout=10)
