@echo off
REM === Instalador automatico de pyscan para Windows ===
REM Haz doble clic en este archivo para preparar el entorno.

cd /d "%~dp0"
echo.
echo ============================================
echo   Preparando el entorno de pyscan...
echo ============================================
echo.

REM Comprobar Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] No se encontro Python.
    echo Instalalo desde https://www.python.org/downloads/
    echo y marca "Add Python to PATH" durante la instalacion.
    pause
    exit /b 1
)

echo Creando entorno virtual (.venv)...
python -m venv .venv

echo Activando entorno e instalando dependencias...
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -e ".[dev,ml]"

echo.
echo ============================================
echo   Listo. Para usar pyscan:
echo   1) Abre PowerShell en esta carpeta
echo   2) Ejecuta:  .\.venv\Scripts\Activate.ps1
echo   3) Prueba:   pyscan scan requests
echo ============================================
echo.
pause
