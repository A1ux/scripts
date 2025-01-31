# Custom Powershell Commands

## Powerview finding

```powershell
$GroupMembers = Get-DomainGroupMember -Identity "GrupoObjetivo"

$GroupMembers | ForEach-Object {
    $user = Get-DomainUser -Identity $_.SamAccountName -Properties SamAccountName, DisplayName, userAccountControl
    [PSCustomObject]@{
        SamAccountName = $user.SamAccountName
        DisplayName    = $user.DisplayName
        Enabled        = -not ($user.userAccountControl -band 2) # Si el bit 2 está activado, la cuenta está deshabilitada
    }
}
```

## Password Policy Exceptions

```powershell
Get-DomainUser -Properties SamAccountName, DisplayName, userAccountControl, pwdLastSet | 
Where-Object { $_.userAccountControl -notmatch "ACCOUNTDISABLE" } | 
Select-Object SamAccountName, DisplayName, pwdLastSet
```