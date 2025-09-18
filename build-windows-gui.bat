# Build script for Windows GUI executable
# Creates a one-file windowed executable using PyInstaller

# Create virtual environment
python -m venv build_env
call build_env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install pyinstaller

# Build executable
pyinstaller --onefile --windowed --name "ModpackDoctor-GUI" ^
    --add-data "data_known_conflicts_Version3.json;." ^
    --add-data "data_performance_mods_Version3.json;." ^
    --hidden-import=PIL ^
    --hidden-import=PIL._tkinter_finder ^
    --hidden-import=tomli ^
    --hidden-import=tomllib ^
    modpack_doctor_gui_new.py

# Copy result
if exist dist\ModpackDoctor-GUI.exe (
    echo Build successful!
    echo Executable: dist\ModpackDoctor-GUI.exe
) else (
    echo Build failed!
    exit /b 1
)

# Cleanup
deactivate
rmdir /s /q build_env