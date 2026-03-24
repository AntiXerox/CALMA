@echo off
REM CALMA - Instalador Universal para Windows 10/11
REM Requer Python 3.8+ instalado

echo.
echo ==========================================
echo    CALMA - Instalador Universal
echo    Windows 10/11
echo ==========================================
echo.

where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERRO] Python nao encontrado!
    echo.
    echo Por favor, instale Python 3.8 ou superior:
    echo   https://www.python.org/downloads/windows/
    echo.
    echo Ou use o Windows Package Manager:
    echo   winget install Python.Python.3.10
    echo.
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYTHON_VERSION=%%v
echo [OK] Python %PYTHON_VERSION% encontrado
echo.

echo Iniciando instalador universal...
echo.
python "%~dp0install_universal.py"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERRO] A instalacao falhou!
    echo.
    pause
    exit /b 1
)

echo.
echo =========================================
echo    Instalacao concluida!
echo =========================================
echo.
echo Para usar o CALMA no Windows:
echo.
echo 1. Instale Git Bash ou WSL (Windows Subsystem for Linux)
echo    - Git Bash: https://git-scm.com/download/win
echo    - WSL: wsl --install
echo.
echo 2. Ative o ambiente virtual:
echo    activate_calma.bat
echo.
echo 3. Execute usando Git Bash ou WSL:
echo    bash calma.sh
echo.
pause
