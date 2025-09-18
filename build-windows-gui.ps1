# Build script for Windows GUI executable (PowerShell)
# Creates a one-file windowed executable using PyInstaller

Write-Host "Creating virtual environment..."
python -m venv build_env
& "build_env\Scripts\Activate.ps1"

Write-Host "Installing dependencies..."
pip install -r requirements.txt
pip install pyinstaller

Write-Host "Building executable..."
pyinstaller --onefile --windowed --name "ModpackDoctor-GUI" `
    --add-data "data_known_conflicts_Version3.json;." `
    --add-data "data_performance_mods_Version3.json;." `
    --hidden-import=PIL `
    --hidden-import=PIL._tkinter_finder `
    --hidden-import=tomli `
    --hidden-import=tomllib `
    modpack_doctor_gui_new.py

if (Test-Path "dist\ModpackDoctor-GUI.exe") {
    Write-Host "Build successful!" -ForegroundColor Green
    Write-Host "Executable: dist\ModpackDoctor-GUI.exe"
} else {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Cleaning up..."
deactivate
Remove-Item -Recurse -Force build_env