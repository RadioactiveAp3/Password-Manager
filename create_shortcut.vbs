Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = oWS.SpecialFolders("Desktop") & "\Password Manager.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = WScript.Arguments(0) & "\run_password_manager.bat"
oLink.WorkingDirectory = WScript.Arguments(0)
oLink.Description = "Password Manager - Secure password storage with AES-256 encryption"
oLink.IconLocation = "shell32.dll,1"
oLink.Save
WScript.Echo "Desktop shortcut created successfully!"
