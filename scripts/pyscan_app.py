#!/usr/bin/env python3
"""Punto de entrada del ejecutable de escritorio de pyscan.

Arranca el servidor web local y abre el navegador automáticamente, para poder
usar pyscan con doble clic, sin activar entornos ni escribir comandos.

Se empaqueta con PyInstaller (ver pyscan.spec). Al ejecutarse como .exe, busca
la carpeta `data/` (modelo y resultados de experimentos) junto al ejecutable.
"""

from __future__ import annotations

import sys
import threading
import webbrowser
from pathlib import Path

# Rutas para el modo "desde código fuente" (en el .exe, pyscan ya va empaquetado).
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from webapp import app  # noqa: E402

HOST, PORT = "127.0.0.1", 5000


def _open_browser() -> None:
    webbrowser.open(f"http://{HOST}:{PORT}")


def main() -> None:
    print(f"pyscan  ->  http://{HOST}:{PORT}")
    print("Se abrirá el navegador. Para cerrar pyscan, cierra esta ventana.")
    threading.Timer(1.5, _open_browser).start()
    # use_reloader=False es obligatorio dentro del ejecutable empaquetado.
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
