#!/usr/bin/env bash
# ============================================================
#  Prepara una carpeta de demostración en el Escritorio con:
#   - requirements_demo.txt  (paquetes legítimos + nombres typosquat)
#   - hasta 3 muestras maliciosas reales, empaquetadas para subir a pyscan.
#  Uso (en la VM):  bash scripts/preparar_demo.sh
# ============================================================
set -e
ROOT="$HOME/Tesis"
DEST="$HOME/Desktop/pyscan_demo"
mkdir -p "$DEST"

# --- Lista de paquetes para pegar en la pestaña "Escanear" ---
cat > "$DEST/requirements_demo.txt" <<'EOF'
# --- Paquetes legitimos (deben salir "benigno") ---
requests
flask
numpy
# --- Nombres sospechosos por typosquatting (no existen en PyPI) ---
reqursts
djnago
numppy
EOF

echo "Preparando muestras maliciosas para subir..."
count=0

# 1) Muestras que ya son archivos empaquetados (.tar.gz/.whl/.zip)
while IFS= read -r f; do
  [ -z "$f" ] && continue
  cp "$f" "$DEST/"; count=$((count + 1))
  [ "$count" -ge 3 ] && break
done < <(find "$ROOT/data/malicious" -type f \
           \( -name "*.tar.gz" -o -name "*.tgz" -o -name "*.whl" -o -name "*.zip" \) 2>/dev/null)

# 2) Si las muestras son carpetas de codigo, empaquetar algunas como .tar.gz
if [ "$count" -eq 0 ]; then
  while IFS= read -r d; do
    [ -z "$d" ] && continue
    name=$(basename "$d")
    tar -czf "$DEST/mal_${name}.tar.gz" -C "$(dirname "$d")" "$name"
    count=$((count + 1))
    [ "$count" -ge 3 ] && break
  done < <(find "$ROOT/data/malicious" -mindepth 2 -maxdepth 2 -type d 2>/dev/null)
fi

echo
if [ "$count" -eq 0 ]; then
  echo "AVISO: no se encontraron muestras en $ROOT/data/malicious."
  echo "Revisa que el dataset este importado (import_datadog.py)."
else
  echo "Listo: $count muestra(s) maliciosa(s) preparada(s)."
fi
echo "Carpeta de demo: $DEST"
echo "----------------------------------------"
ls -1 "$DEST"
