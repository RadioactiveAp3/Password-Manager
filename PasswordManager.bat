@echo off
title Password Manager
color 0A
echo.
echo  ========================================
echo  🔐 PASSWORD MANAGER 🔐
echo  ========================================
echo.
echo  Starting Password Manager...
echo.

cd /d "%~dp0"

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Error: Python is not installed or not in PATH
    echo.
    echo Please install Python from: https://python.org
    echo Make sure to check "Add Python to PATH" during installation
    echo.
    pause
    exit /b 1
)

REM Check if main.py exists
if not exist "main.py" (
    echo ❌ Error: main.py not found
    echo Please make sure you're running this from the Password Manager folder
    echo.
    pause
    exit /b 1
)

REM Check if requirements are installed
python -c "import cryptography, bcrypt" >nul 2>&1
if errorlevel 1 (
    echo 📦 Installing required packages...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ❌ Error: Failed to install requirements
        echo Please run: pip install -r requirements.txt
        echo.
        pause
        exit /b 1
    )
)

REM Start the application
echo ✅ Starting Password Manager...
echo.
python main.py

REM If we get here, the app was closed
echo.
echo Password Manager closed.
pause
