@echo off
REM ============================================================
REM  Construye el ejecutable pyscan.exe (ejecutar en Windows)
REM  Requiere: Python 3.10+ y el proyecto instalado en un venv.
REM ============================================================

echo.
echo === pyscan: construccion del ejecutable ===
echo.

REM 1) Activar el entorno virtual (crealo antes si no existe)
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
) else (
    echo No se encontro .venv. Creando uno nuevo...
    python -m venv .venv
    call .venv\Scripts\activate.bat
    pip install -e ".[ml,web]"
)

REM 2) Instalar PyInstaller
pip install pyinstaller

REM 3) Construir
pyinstaller --clean --noconfirm pyscan.spec

echo.
echo ============================================================
echo  Listo. El ejecutable esta en:  dist\pyscan.exe
echo.
echo  IMPORTANTE: copia la carpeta  data\  junto a  dist\pyscan.exe
echo  (debe contener data\models\model.joblib y, si quieres el panel
echo   completo, data\analysis\*.json y data\models\metrics.json).
echo ============================================================
echo.
pause
