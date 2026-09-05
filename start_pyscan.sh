#!/usr/bin/env bash
# ============================================================
#  Lanzador de pyscan para la VM (doble clic).
#  Activa el entorno, arranca el servidor y abre el navegador.
#  No hay que escribir comandos.
# ============================================================
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  echo "No existe .venv. Creando el entorno por primera vez..."
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -e ".[ml,web]"
else
  source .venv/bin/activate
fi

# pyscan_app.py arranca el servidor y abre el navegador automaticamente.
python scripts/pyscan_app.py
