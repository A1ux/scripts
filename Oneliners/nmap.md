# Nmap CheatSheet

## Sondeo Ping

```bash
nmap -vvv -sP $ip -oA $ip
```


## SN

```bash
nmap -vvv -sn $ip -oA $ip
```


## PN Top ports

```bash
nmap -vvv -Pn --top-ports 10 $ip -oA $ip
```