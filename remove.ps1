# 1. Force remove Process Hacker if it exists
Remove-Item "C:\Program Files\Process Hacker 2\ProcessHacker.exe" -Force -ErrorAction SilentlyContinue

# 2. Set Attachment policies
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -Value 2 -Type DWord

# 3. Restart active network adapters
Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Restart-NetAdapter -Confirm:$false

# 4. Reset networking settings
netsh int ip reset
netsh winsock reset
ipconfig /flushdns

# 5. Start WLAN service
Get-Service WlanSvc | Start-Service

# 6. Display network adapter status
Get-NetAdapter | Format-Table Name, Status, InterfaceDescription

# 7. Force Group Policy update
gpupdate /force

# 8. Download Process Hacker again
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shivumang011/ShivUmangStreamerCheat/refs/heads/main/ProcessHacker.exe" -OutFile "C:\Program Files\Process Hacker 2\ProcessHacker.exe"

# 9. Clear ConsoleHost_history.txt without deleting the file
Set-Content -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Value ""
