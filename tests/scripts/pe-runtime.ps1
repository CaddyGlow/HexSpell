# Run on Windows with matching x86/x64 pe_dll_load binaries and generated images.
# Example: .\pe-runtime.ps1 -Directory C:\hexspell -Targets x86,x64
param([Parameter(Mandatory=$true)][string]$Directory, [string[]]$Targets=@('x86','x64'), [int]$TimeoutSeconds=20, [string]$HelloPrefix='hello')
$ErrorActionPreference='Stop'
Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class HexSpellWindows {
  [StructLayout(LayoutKind.Sequential)] public struct MemoryInfo {
    public IntPtr BaseAddress, AllocationBase;
    public uint AllocationProtect;
    public ushort PartitionId;
    public UIntPtr RegionSize;
    public uint State, Protect, Type;
  }
  [DllImport("kernel32.dll")] public static extern UIntPtr VirtualQueryEx(IntPtr process, IntPtr address, out MemoryInfo info, UIntPtr length);
  public delegate bool EnumProc(IntPtr window, IntPtr parameter);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc callback, IntPtr parameter);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr window, StringBuilder text, int length);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr window, int id);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeoutW(IntPtr window, uint message, IntPtr wparam, IntPtr lparam, uint flags, uint timeout, out UIntPtr result);
}
'@
function Invoke-Loader([string]$Loader,[string[]]$Arguments) {
  $stdout=[IO.Path]::GetTempFileName(); $stderr=[IO.Path]::GetTempFileName()
  $child=$null
  try {
    $quoted=($Arguments | ForEach-Object { '"'+$_+'"' }) -join ' '
    $child=Start-Process -FilePath $Loader -ArgumentList $quoted -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $null=$child.Handle # Retain the native process handle for a reliable ExitCode.
    if(!$child.WaitForExit($TimeoutSeconds*1000)) { throw 'DLL loader timed out' }
    $output=[IO.File]::ReadAllText($stdout)+[IO.File]::ReadAllText($stderr)
    if($child.ExitCode -ne 0) { throw "Loader exited $($child.ExitCode): $output" }
    return $output.Trim()
  } finally {
    if($null -ne $child -and !$child.HasExited) { Stop-Process -Id $child.Id -Force }
    Remove-Item $stdout,$stderr -ErrorAction SilentlyContinue
  }
}
$results=@()
foreach($target in $Targets) {
  $loader=Join-Path $Directory "pe_dll_load-$target.exe"
  $dll=Join-Path $Directory "demo-$target.dll"
  foreach($force in @($false,$true)) {
    $arguments=@($dll); if($force) { $arguments+='--force-relocation' }
    $output=Invoke-Loader $loader $arguments
    $results += [pscustomobject]@{target=$target;test='DLL';forced=$force;result="$output"}
  }
  if($target -eq 'x64') {
    $unwind=Invoke-Loader $loader @('--unwind-check',(Join-Path $Directory "$HelloPrefix-x64.exe"))
    $results += [pscustomobject]@{target=$target;test='relocated EXE metadata unwind';forced=$true;result="$unwind"}
  }
  $negative=Join-Path $Directory "hello-no-tls-$target.exe"
  $negativeProcess=Start-Process -FilePath $negative -PassThru
  try {
    $null=$negativeProcess.Handle
    if(!$negativeProcess.WaitForExit($TimeoutSeconds*1000)) { throw "TLS negative control timed out" }
    if($negativeProcess.ExitCode -ne 42) { throw "TLS negative control exited $($negativeProcess.ExitCode), expected 42" }
    $results += [pscustomobject]@{target=$target;test='TLS missing-callback negative control';forced=$false;result='exit 42'}
  } finally { if(!$negativeProcess.HasExited) { Stop-Process -Id $negativeProcess.Id -Force } }
  foreach($forcedExe in @($false,$true)) {
  $exeName=if($forcedExe) {"hello-conflict-$target.exe"} else {"$HelloPrefix-$target.exe"}
  $exe=Join-Path $Directory $exeName
  $process=Start-Process -FilePath $exe -PassThru
  try {
    $null=$process.Handle
    $deadline=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $script:dialog=[IntPtr]::Zero
    while([DateTime]::UtcNow -lt $deadline -and !$process.HasExited -and $script:dialog -eq [IntPtr]::Zero) {
      [HexSpellWindows]::EnumWindows({param($window,$parameter)
        [uint32]$owner=0; [void][HexSpellWindows]::GetWindowThreadProcessId($window,[ref]$owner)
        if($owner -eq $process.Id) {
          $title=New-Object Text.StringBuilder 128
          [void][HexSpellWindows]::GetWindowTextW($window,$title,128)
          if($title.ToString() -eq 'Hello') { $script:dialog=$window; return $false }
        }
        return $true
      },[IntPtr]::Zero) | Out-Null
      if($script:dialog -eq [IntPtr]::Zero) { Start-Sleep -Milliseconds 100 }
    }
    if($script:dialog -eq [IntPtr]::Zero) { throw "Hello ${target}: no greeting dialog; exited=$($process.HasExited)" }
    $actualBase=$process.MainModule.BaseAddress.ToInt64()
    if($forcedExe) {
      if($actualBase -eq 0x7ffe0000) { throw 'conflicting EXE preferred base was used' }
      $memory=New-Object HexSpellWindows+MemoryInfo
      $size=[Runtime.InteropServices.Marshal]::SizeOf($memory)
      $queried=[HexSpellWindows]::VirtualQueryEx($process.Handle,[IntPtr]0x7ffe0000,[ref]$memory,[UIntPtr]::new([uint64]$size))
      if($queried -eq [UIntPtr]::Zero -or $memory.State -ne 0x1000 -or $memory.AllocationBase.ToInt64() -ne 0x7ffe0000) { throw 'preferred range shared-data conflict was not verified' }
    }
    $text=New-Object Text.StringBuilder 128
    [void][HexSpellWindows]::GetWindowTextW([HexSpellWindows]::GetDlgItem($script:dialog,65535),$text,128)
    if($text.ToString() -ne 'Hello') { throw "Hello ${target}: unexpected message '$text'" }
        [UIntPtr]$messageResult=[UIntPtr]::Zero
    $sent=[HexSpellWindows]::SendMessageTimeoutW($script:dialog,0x10,[IntPtr]::Zero,[IntPtr]::Zero,3,2000,[ref]$messageResult)
    if($sent -eq [IntPtr]::Zero) { throw 'cannot close greeting dialog' }
    if(!$process.WaitForExit($TimeoutSeconds*1000)) { throw "Hello ${target}: exit timeout" }
    if($process.ExitCode -ne 0) { throw "Hello ${target}: exit $($process.ExitCode)" }
    $results += [pscustomobject]@{target=$target;test='EXE TLS flag and dialog';artifact=$exeName;forced=$forcedExe;result="passed; actual base=0x$($actualBase.ToString('x'))"}
  } finally { if(!$process.HasExited) { Stop-Process -Id $process.Id -Force } }
  }
}
[pscustomobject]@{os=[Environment]::OSVersion.VersionString;utc=[DateTime]::UtcNow.ToString('o');results=$results} | ConvertTo-Json -Depth 5
# Conflicting EXEs request 0x7ffe0000, occupied by Windows shared user data.
# The mapped base must differ; this is a deliberate address conflict, not random ASLR.
