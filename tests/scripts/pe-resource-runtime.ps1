param([Parameter(Mandatory=$true)][string[]]$Paths, [string]$ExpectedString = 'Hello resource', [int]$ExpectedVersionMajor = 1)
$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class HexSpellResourceCheck {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern IntPtr LoadLibraryExW(string path,IntPtr file,uint flags);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool FreeLibrary(IntPtr module);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr FindResourceExW(IntPtr module,IntPtr type,IntPtr name,ushort language);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint SizeofResource(IntPtr module,IntPtr resource);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr LoadResource(IntPtr module,IntPtr resource);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr LockResource(IntPtr resource);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern int LoadStringW(IntPtr module,uint id,StringBuilder text,int capacity);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern IntPtr LoadImageW(IntPtr module,IntPtr name,uint type,int width,int height,uint flags);
 [DllImport("user32.dll")] public static extern bool DestroyIcon(IntPtr icon);
 [DllImport("version.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern uint GetFileVersionInfoSizeW(string path,out uint handle);
 [DllImport("version.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool GetFileVersionInfoW(string path,uint handle,uint len,byte[] bytes);
 [DllImport("version.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool VerQueryValueW(byte[] bytes,string subblock,out IntPtr value,out uint len);
 public static byte[] Read(IntPtr module,int type,int name,ushort language) {
   IntPtr resource=FindResourceExW(module,(IntPtr)type,(IntPtr)name,language);
   if(resource==IntPtr.Zero) throw new Exception("FindResourceEx failed: "+Marshal.GetLastWin32Error());
   uint size=SizeofResource(module,resource); IntPtr loaded=LoadResource(module,resource); IntPtr address=LockResource(loaded);
   if(address==IntPtr.Zero) throw new Exception("Load/LockResource failed");
   byte[] bytes=new byte[size];Marshal.Copy(address,bytes,0,bytes.Length);return bytes;
 }
}
'@
$results = foreach ($inputPath in $Paths) {
 $path = (Resolve-Path $inputPath).Path
 $module = [HexSpellResourceCheck]::LoadLibraryExW($path,[IntPtr]::Zero,0x22)
 if ($module -eq [IntPtr]::Zero) { throw "LoadLibraryEx failed for $path : $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
 try {
  $manifest = [Text.Encoding]::UTF8.GetString([HexSpellResourceCheck]::Read($module,24,1,1033))
  if (-not $manifest.Contains('<assembly')) { throw 'Manifest content mismatch' }
  $rcdata = [Text.Encoding]::UTF8.GetString([HexSpellResourceCheck]::Read($module,10,1,1033))
  if ($rcdata -ne 'HexSpell generated resource') { throw 'RCDATA content mismatch' }
  $text = [Text.StringBuilder]::new(256)
  $length = [HexSpellResourceCheck]::LoadStringW($module,1,$text,256)
  if ($length -eq 0 -or $text.ToString() -ne $ExpectedString) { throw 'LoadStringW content mismatch' }
  $icon = [HexSpellResourceCheck]::LoadImageW($module,[IntPtr]1,1,1,1,0)
  if ($icon -eq [IntPtr]::Zero) { throw "LoadImageW failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
  if (-not [HexSpellResourceCheck]::DestroyIcon($icon)) { throw 'DestroyIcon failed' }
  $ignored = [uint32]0
  $size = [HexSpellResourceCheck]::GetFileVersionInfoSizeW($path,[ref]$ignored)
  if ($size -eq 0) { throw 'GetFileVersionInfoSizeW failed' }
  $bytes = [byte[]]::new($size)
  if (-not [HexSpellResourceCheck]::GetFileVersionInfoW($path,0,$size,$bytes)) { throw 'GetFileVersionInfoW failed' }
  $value = [IntPtr]::Zero; $valueSize = [uint32]0
  if (-not [HexSpellResourceCheck]::VerQueryValueW($bytes,'\',[ref]$value,[ref]$valueSize)) { throw 'VerQueryValueW failed' }
  if ($valueSize -lt 52 -or [Runtime.InteropServices.Marshal]::ReadInt32($value) -ne [int32]-17890115) { throw 'VS_FIXEDFILEINFO signature mismatch' }
  $versionMS = [Runtime.InteropServices.Marshal]::ReadInt32($value,8)
  $versionLS = [Runtime.InteropServices.Marshal]::ReadInt32($value,12)
  if ($versionMS -ne ($ExpectedVersionMajor -shl 16) -or $versionLS -ne 0) { throw 'File version mismatch' }
  $value = [IntPtr]::Zero; $valueSize = [uint32]0
  if (-not [HexSpellResourceCheck]::VerQueryValueW($bytes,'\StringFileInfo\040904B0\FileDescription',[ref]$value,[ref]$valueSize)) { throw 'Version FileDescription query failed' }
  if ([Runtime.InteropServices.Marshal]::PtrToStringUni($value) -ne 'HexSpell generated Hello') { throw 'Version FileDescription mismatch' }
  $value = [IntPtr]::Zero; $valueSize = [uint32]0
  if (-not [HexSpellResourceCheck]::VerQueryValueW($bytes,'\VarFileInfo\Translation',[ref]$value,[ref]$valueSize)) { throw 'Version Translation query failed' }
  if ($valueSize -ne 4 -or [Runtime.InteropServices.Marshal]::ReadInt32($value) -ne 0x04b00409) { throw 'Version Translation mismatch' }
  [pscustomobject]@{path=$path;manifest=$true;rcdata=$rcdata;string=$text.ToString();icon=$true;version="$ExpectedVersionMajor.0.0.0";sha256=(Get-FileHash $path -Algorithm SHA256).Hash}
 } finally { if (-not [HexSpellResourceCheck]::FreeLibrary($module)) { throw 'FreeLibrary failed' } }
}
$results | ConvertTo-Json -Depth 4
