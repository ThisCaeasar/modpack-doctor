# Build script for Windows GUI executable
# Run this in PowerShell

# Create virtual environment
Write-Host "Creating virtual environment..."
python -m venv venv
& "venv\Scripts\Activate.ps1"

# Install dependencies
Write-Host "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

# Build GUI executable
Write-Host "Building ModpackDoctor-GUI.exe..."
pyinstaller --noconsole --onefile modpack_doctor_gui.py `
    --name ModpackDoctor-GUI `
    --add-data "moddoctor;moddoctor" `
    --add-data "data_known_conflicts_Version3.json;." `
    --add-data "data_performance_mods_Version3.json;." `
    --icon=icon.ico

Write-Host "Build complete! Executable is in dist/ folder"
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")