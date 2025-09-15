@echo off
echo Creating desktop shortcut for Password Manager...
cscript create_shortcut.vbs "%~dp0"
echo.
echo Desktop shortcut created!
echo You can now find "Password Manager" on your desktop.
pause
