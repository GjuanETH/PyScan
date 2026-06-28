@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ============================================
echo   Subir pyscan a Azure DevOps (Repos)
echo ============================================
echo.

REM --- 1) Comprobar Git ---
where git >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Git no esta instalado.
    echo Descargalo de https://git-scm.com/download/win e instalalo.
    pause
    exit /b 1
)

REM --- 2) Limpiar un .git parcial si quedo de una sesion anterior ---
if exist ".git\config.lock" (
    echo Limpiando repositorio git parcial...
    rmdir /s /q .git
)

REM --- 3) Inicializar repo si no existe ---
if not exist ".git" (
    git init
    git branch -M main
    git config user.name "Andres Felipe Sanguino Cubillos"
    git config user.email "anfesacu@gmail.com"
)

REM --- 4) Configurar el remoto (solo la primera vez) ---
git remote get-url origin >nul 2>&1
if errorlevel 1 (
    echo.
    echo Pega la URL de tu repositorio de Azure DevOps.
    echo  Ejemplo: https://dev.azure.com/TU_ORG/TU_PROYECTO/_git/pyscan
    set /p REPOURL="URL del repo: "
    git remote add origin "!REPOURL!"
)

REM --- 5) Mensaje del commit ---
echo.
set /p MSG="Describe brevemente este avance (mensaje del commit): "
if "!MSG!"=="" set MSG=Avance pyscan

REM --- 6) Guardar y subir ---
git add .
git commit -m "!MSG!"
git push -u origin main

echo.
echo ============================================
echo   Listo. Si te pidio usuario/contrasena, usa
echo   tu email y un Personal Access Token (PAT).
echo ============================================
pause
