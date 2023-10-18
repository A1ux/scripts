# Enumeracion de Active Directory

## Reconocimiento

### Enumerar AD

```bash
nslookup -type=SRV _ldap._tcp.dc._msdcs.alux.cc
```

### Enumerar SMBs

```bash
crackmapexec smb <ip_range>
```

## Enumeracion de Usuarios

### Null session

```bash
rpcclient -U "" -N $ip
crackmapexec smb $ip --users
net rpc group members 'Domain Users' -W 'alux.cc' -I $ip -u '%'
enum4linux -U $ip | grep 'user:'
```

### OSINT | Username Anarchy | Kerbrute (Pendiente)

https://github.com/urbanadventurer/username-anarchy

```bash
kerbrute userenum -d alux.cc usernames.txt
```