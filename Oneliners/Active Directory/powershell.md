# Active Directory Post-Exploitation Findings

## Cuentas genericas como administradores de Dominio

```powershell
Get-ADGroupMember -Identity "Domain Admins" | Get-ADUser -Properties samaccountname, Name, Enabled | Select-Object samaccountname, Name, Enabled
```

## Cuentas de administradores de dominio no cumplen con las mejores practicas

```powershell
Get-ADGroupMember -Identity "Domain Admins" | Get-ADUser -Properties samaccountname, Name, PasswordLastSet, PasswordNeverExpires, Enabled | Select-Object samaccountname, Name, PasswordLastSet, PasswordNeverExpires, Enabled
```


## Contrasenas de usuarios de dominio que no expiran y estan habilitadas

```powershell
Get-ADGroupMember -Identity "Domain Users" | Get-ADUser -Properties samaccountname, Name, Enabled, PasswordNeverExpires | Select-Object samaccountname, Name, Enabled, PasswordNeverExpires | Export-Csv -Path .\users_expirepass.csv -NoTypeInformation 
```