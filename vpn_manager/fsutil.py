"""Escritura de ficheros con secretos: atómica y sin permisos de lectura para otros.

`Path.write_text` crea los ficheros con la umask del proceso (normalmente 0644): las configuraciones
de cliente, que llevan su clave privada, quedaban legibles por cualquier usuario del servidor. Además
trunca y reescribe en sitio, así que un corte a mitad dejaba el fichero (p. ej. el wg0.conf con la
clave del servidor) a medias.
"""
from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path


def write_private(path: Path, data: str | bytes, mode: int = 0o600) -> None:
    """Escribe `data` en `path` de forma atómica.

    Un fichero nuevo se crea con `mode`; uno que ya existe conserva sus permisos (quien lo haya
    ajustado a mano no los pierde).
    """
    path = Path(path)
    try:
        mode = path.stat().st_mode & 0o777
    except FileNotFoundError:
        pass
    raw = data.encode("utf-8") if isinstance(data, str) else data
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
