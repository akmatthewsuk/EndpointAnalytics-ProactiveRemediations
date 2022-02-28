Set objShell = CreateObject("Wscript.Shell")

Dim RunCommand
RunCommand = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -NonInteractive -NoLogo -NoProfile -ExecutionPolicy RemoteSigned -File " & chr(34) & "c:\Program Files\Deploy\UpdateNotification\Scripts\User\UpdateToastNotify\New-UpdateToast.ps1" & chr(34) & " -Configfile " & chr(34) & "c:\Program Files\Deploy\UpdateNotification\Scripts\User\UpdateToastNotify\config.xml" & chr(34)
objShell.Run RunCommand,0,true