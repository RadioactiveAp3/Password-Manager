#!/usr/bin/env python3
"""
Create a standalone executable for the Password Manager
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def create_executable():
    """Create a standalone executable using PyInstaller"""
    print("🔧 Creating standalone executable for Password Manager...")
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
        print("✅ PyInstaller found")
    except ImportError:
        print("📦 Installing PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        print("✅ PyInstaller installed")
    
    # Create the executable
    print("🚀 Building executable...")
    
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",                    # Single file executable
        "--windowed",                   # No console window
        "--name=PasswordManager",       # Executable name
        "--icon=icon.ico",              # Icon (if exists)
        "--add-data=requirements.txt;.", # Include requirements
        "main.py"
    ]
    
    # Remove icon parameter if icon doesn't exist
    if not os.path.exists("icon.ico"):
        cmd = [c for c in cmd if not c.startswith("--icon")]
    
    try:
        subprocess.run(cmd, check=True)
        print("✅ Executable created successfully!")
        print(f"📁 Location: {os.path.join('dist', 'PasswordManager.exe')}")
        
        # Create desktop shortcut for the executable
        create_desktop_shortcut()
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error creating executable: {e}")
        return False
    
    return True

def create_desktop_shortcut():
    """Create a desktop shortcut for the executable"""
    try:
        import winshell
        from win32com.client import Dispatch
        
        desktop = winshell.desktop()
        path = os.path.join(desktop, "Password Manager.lnk")
        target = os.path.join(os.getcwd(), "dist", "PasswordManager.exe")
        
        shell = Dispatch('WScript.Shell')
        shortcut = shell.CreateShortCut(path)
        shortcut.Targetpath = target
        shortcut.WorkingDirectory = os.path.dirname(target)
        shortcut.IconLocation = target
        shortcut.Description = "Password Manager - Secure password storage with AES-256 encryption"
        shortcut.save()
        
        print("✅ Desktop shortcut created for executable!")
        
    except ImportError:
        print("⚠️  Could not create desktop shortcut (winshell not available)")
        print("   You can manually create a shortcut to dist/PasswordManager.exe")
    except Exception as e:
        print(f"⚠️  Could not create desktop shortcut: {e}")

def create_simple_launcher():
    """Create a simple launcher script"""
    launcher_content = '''@echo off
title Password Manager
echo Starting Password Manager...
cd /d "%~dp0"
python main.py
if errorlevel 1 (
    echo.
    echo Error: Python not found or main.py not found
    echo Please make sure Python is installed and main.py is in the same folder
    pause
)
'''
    
    with open("PasswordManager.bat", "w") as f:
        f.write(launcher_content)
    
    print("✅ Simple launcher created: PasswordManager.bat")

if __name__ == "__main__":
    print("🔐 Password Manager - Executable Creator")
    print("=" * 50)
    
    choice = input("""
Choose an option:
1. Create standalone executable (requires PyInstaller)
2. Create simple launcher script
3. Both

Enter choice (1-3): """).strip()
    
    if choice in ["1", "3"]:
        if create_executable():
            print("\n🎉 Executable creation completed!")
        else:
            print("\n❌ Executable creation failed!")
    
    if choice in ["2", "3"]:
        create_simple_launcher()
        print("\n🎉 Launcher creation completed!")
    
    print("\n📋 Next steps:")
    print("1. Run the created executable or launcher")
    print("2. Create your master password")
    print("3. Start adding your passwords!")
    print("\nPress Enter to exit...")
    input()
