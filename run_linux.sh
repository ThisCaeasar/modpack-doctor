#!/bin/bash
# Linux launcher for Modpack Doctor GUI

echo "Starting Modpack Doctor GUI..."

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Try python3 first
if command -v python3 &> /dev/null; then
    echo "Using python3..."
    python3 modpack_doctor_gui.py
    exit_code=$?
elif command -v python &> /dev/null; then
    # Check if python is Python 3
    python_version=$(python --version 2>&1 | grep -o "Python 3")
    if [ "$python_version" = "Python 3" ]; then
        echo "Using python..."
        python modpack_doctor_gui.py
        exit_code=$?
    else
        echo "ERROR: Found Python 2, but Python 3.10+ is required!"
        echo "Please install Python 3 and try again."
        echo "For Ubuntu/Debian: sudo apt install python3 python3-tk"
        echo "For Fedora/RHEL: sudo dnf install python3 python3-tkinter" 
        echo "For Arch: sudo pacman -S python python-tk"
        read -p "Press Enter to continue..."
        exit 1
    fi
else
    echo "ERROR: Python not found! Please install Python 3.10+ and try again."
    echo "For Ubuntu/Debian: sudo apt install python3 python3-tk"
    echo "For Fedora/RHEL: sudo dnf install python3 python3-tkinter"
    echo "For Arch: sudo pacman -S python python-tk"
    read -p "Press Enter to continue..."
    exit 1
fi

# Check exit code
if [ $exit_code -ne 0 ]; then
    echo ""
    echo "GUI exited with error code $exit_code"
    read -p "Press Enter to continue..."
fi