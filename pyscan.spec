# -*- mode: python ; coding: utf-8 -*-
"""Especificación de PyInstaller para construir el ejecutable de pyscan.

Genera un único ejecutable (dist/pyscan[.exe]) que arranca la interfaz web y
abre el navegador. La carpeta `data/` (modelo + resultados) NO se empaqueta: se
coloca junto al ejecutable, para poder actualizarla sin reconstruir.

Construir:
    pip install pyinstaller
    pyinstaller --clean --noconfirm pyscan.spec
"""

from PyInstaller.utils.hooks import collect_all

datas, binaries, hiddenimports = [], [], []
hiddenimports += ["pyscan", "pyscan.cli", "webapp"]

# Recolecta por completo las librerías con extensiones/datos que PyInstaller
# no detecta solo. Si alguna no está instalada, se ignora sin romper el build.
for pkg in ("xgboost", "sklearn", "scipy", "joblib", "rapidfuzz",
            "pydantic", "pydantic_core", "flask", "werkzeug", "requests"):
    try:
        d, b, h = collect_all(pkg)
        datas += d
        binaries += b
        hiddenimports += h
    except Exception:  # noqa: BLE001
        pass

a = Analysis(
    ["scripts/pyscan_app.py"],
    pathex=["src", "scripts"],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["matplotlib", "pandas.tests", "notebook", "IPython"],
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="pyscan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,      # muestra una ventana de consola (para cerrar la app)
    icon=None,
)
