@echo off
echo [33m Disable Windows Defender SmartScreen Filter[0m
echo [33m Disable block downloaded files in explorer (zone infromation)[0m
echo [33m Disable Open File security warning[0m
::Disabling SmartScreen+ Disable block downloaded files in explorer (zone infromation)
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
::Delete SmartScreen
takeown /f "%WinDir%\System32\smartscreen.exe" /a
icacls "%WinDir%\System32\smartscreen.exe" /grant:r Administrators:F /c
TASKKILL /t /f /im smartscreen.exe > NUL 2>&1
del "%WinDir%\System32\smartscreen.exe" /s /f /q > NUL 2>&1
::Disable Open File security warning
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1806" /t "REG_DWORD" /d "00000000" /f 
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1806" /t "REG_DWORD" /d "00000000" /f
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Security" /v "DisableSecuritySettingsCheck" /t "REG_DWORD" /d "00000001" /f
reg add "HKCU\Software\Microsoft\Internet Explorer\Download" /v "CheckExeSignatures" /t REG_SZ /d "no" /f
reg add "HKCU\Software\Microsoft\Internet Explorer\Download" /v "RunInvalidSignatures" /t REG_DWORD /d "1" /f
pause
