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
)

REM --- 4) Identidad de los commits (se aplica siempre) ---
git config user.name "Andres Felipe Sanguino Cubillos"
git config user.email "jdgutierrez017@ucatolica.edu.co"

REM --- 5) Configurar el remoto (solo la primera vez) ---
git remote get-url origin >nul 2>&1
if errorlevel 1 (
    echo.
    echo Pega la URL de tu repositorio de Azure DevOps.
    echo  Ejemplo: https://dev.azure.com/jdgutierrez017/Tesis/_git/Tesis
    set /p REPOURL="URL del repo: "
    git remote add origin "!REPOURL!"
)

REM --- 6) Mensaje del commit ---
echo.
set /p MSG="Describe brevemente este avance (mensaje del commit): "
if "!MSG!"=="" set MSG=Avance pyscan

REM --- 7) Guardar y subir ---
git add .
git commit -m "!MSG!"
git push -u origin main

echo.
echo ============================================
echo   Listo. Si te pidio usuario/contrasena, usa
echo   el email y un Personal Access Token (PAT)
echo   de la cuenta con acceso al proyecto.
echo ============================================
pause
