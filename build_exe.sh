#!/usr/bin/env bash
# ============================================================
#  Construye el ejecutable de pyscan en Linux (p. ej. en la VM).
#  Genera dist/pyscan (binario de Linux, no .exe).
# ============================================================
set -e
cd "$(dirname "$0")"

if [ -d ".venv" ]; then
  source .venv/bin/activate
else
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -e ".[ml,web]"
fi

pip install pyinstaller
pyinstaller --clean --noconfirm pyscan.spec

echo
echo "Listo. El ejecutable esta en: dist/pyscan"
echo "Copia la carpeta data/ junto a dist/pyscan antes de usarlo."
