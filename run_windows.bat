@echo off
REM Windows launcher for Modpack Doctor GUI

echo Starting Modpack Doctor GUI...

REM Try py -3 first (modern Windows Python launcher)
py -3 --version >nul 2>&1
if %errorlevel% == 0 (
    echo Using py -3...
    py -3 modpack_doctor_gui.py
    goto :end
)

REM Try python3
python3 --version >nul 2>&1
if %errorlevel% == 0 (
    echo Using python3...
    python3 modpack_doctor_gui.py
    goto :end
)

REM Try python
python --version >nul 2>&1
if %errorlevel% == 0 (
    echo Using python...
    python modpack_doctor_gui.py
    goto :end
)

REM If we get here, no Python found
echo ERROR: Python not found! Please install Python 3.10+ and try again.
echo You can download Python from: https://www.python.org/downloads/
pause
goto :end

:end
if %errorlevel% neq 0 (
    echo.
    echo GUI exited with error code %errorlevel%
    pause
)