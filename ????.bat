@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

REM === Fill this once: put the full path to your client.dll after the = ===
set "CS2RE_DLL="
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"

where python >nul 2>nul
if errorlevel 1 (
    echo [!] python not found. Install Python 3 and make sure it is on PATH.
    pause
    exit /b 1
)

if "%CS2RE_DLL%"=="" (
    echo [!] client.dll path is empty.
    echo     Edit the CS2RE_DLL line at the top of this .bat, or pass --dll manually.
    echo     See 怎么用.md
    pause
    exit /b 1
)

echo ============================================================
echo   CS2 Offset Auto Scanner
echo ============================================================
echo.
echo [*] Scanning, about 40 seconds. Best done after you join a match.
echo.

python -m cs2re.auto --verify --ofs out\deliver.ofs --header out\deliver.hpp --json out\deliver.json
if errorlevel 1 goto nogame
goto done

:nogame
echo.
echo [!] cs2.exe is not running, or the scan could not attach to it.
echo.
echo     Choose a mode:
echo       1 = offline  (reuse the saved signature library, ~9s)
echo       2 = static   (m_* fields only, ~1s)
echo       3 = quit
echo.
set "CH="
set /p "CH=Enter 1/2/3 then press Enter: "
if "%CH%"=="1" goto offline
if "%CH%"=="2" goto nolive
goto end

:offline
echo [*] Offline mode...
python -m cs2re.auto --offline --ofs out\offline.ofs
goto done

:nolive
echo [*] Static mode...
python -m cs2re.auto --no-live --ofs out\static.ofs
goto done

:done
echo.
echo ============================================================
echo   Done. Outputs are in the out\ folder:
echo     out\deliver.ofs   ^<-- the offsets
echo     out\deliver.hpp / out\deliver.json  (extras)
echo ============================================================
echo.
pause

:end
endlocal
