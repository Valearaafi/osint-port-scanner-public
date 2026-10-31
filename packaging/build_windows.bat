@echo off
setlocal
rem Build distribusi Windows "onedir" OSINT Port Scanner.
rem Menggunakan virtual environment khusus di packaging\venv — tidak
rem menginstal dependensi build secara global.

cd /d "%~dp0"

set "VENV_DIR=%~dp0venv"
set "DIST_DIR=%~dp0..\dist"
set "BUILD_DIR=%~dp0..\build"

echo [1/4] Menyiapkan virtual environment build...
if not exist "%VENV_DIR%\Scripts\python.exe" (
    python -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo Gagal membuat virtual environment. Pastikan Python 3.12 ada di PATH.
        goto :error
    )
)

echo [2/4] Menginstal dependensi build dan runtime...
"%VENV_DIR%\Scripts\python.exe" -m pip install --upgrade pip --quiet
if errorlevel 1 goto :error
"%VENV_DIR%\Scripts\python.exe" -m pip install --quiet -r "%~dp0requirements-build.txt" -r "%~dp0..\requirements.txt"
if errorlevel 1 goto :error

echo [3/4] Membangun executable...
"%VENV_DIR%\Scripts\python.exe" -m PyInstaller --clean --noconfirm --distpath "%DIST_DIR%" --workpath "%BUILD_DIR%" "%~dp0osint_port_scanner.spec"
if errorlevel 1 goto :error

echo [4/4] Selesai.
echo Executable: %DIST_DIR%\OSINTPortScanner\OSINTPortScanner.exe
exit /b 0

:error
echo Build gagal. Periksa pesan kesalahan di atas.
exit /b 1
