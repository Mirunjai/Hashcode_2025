' start_linklens_silent.vbs
' Launches the LinkLens backend silently (no terminal window)
' Place a shortcut to this file in the Windows Startup folder

Dim shell
Set shell = CreateObject("WScript.Shell")

' Get the directory of this script
Dim scriptDir
scriptDir = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)

' Run python main.py in the backend folder, hidden window
shell.Run "cmd /c cd /d """ & scriptDir & "\backend"" && python main.py", 0, False

Set shell = Nothing
