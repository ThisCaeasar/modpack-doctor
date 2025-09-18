@echo off
REM Build script for Windows GUI executable

echo Creating virtual environment...
python -m venv venv
call venv\Scripts\activate.bat

echo Installing dependencies...
pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

echo Building ModpackDoctor-GUI.exe...
pyinstaller --noconsole --onefile modpack_doctor_gui.py ^
    --name ModpackDoctor-GUI ^
    --add-data "moddoctor;moddoctor" ^
    --add-data "data_known_conflicts_Version3.json;." ^
    --add-data "data_performance_mods_Version3.json;."

echo Build complete! Executable is in dist/ folder
pause