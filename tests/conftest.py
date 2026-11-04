"""Aísla la suite del sandbox de desarrollo.

La app engancha la auditoría y el almacén de usuarios al importarse; sin esto cada ejecución
escribía en `sandbox/data/` del repo (usuarios de prueba, rutas temporales, «testclient»...) y
el panel de desarrollo arrancaba con ese rastro.
"""
import os
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="vpnm-tests-"))
os.environ.setdefault("VPNM_AUDIT_FILE", str(_TMP / "audit.jsonl"))
os.environ.setdefault("VPNM_USERS_FILE", str(_TMP / "users.json"))
os.environ.setdefault("VPNM_EXPORT_DIR", str(_TMP / "exports"))
