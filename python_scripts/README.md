# Scripts

## genJSON_gnmap.py

Genera el JSON en base a los .gnmap dentro de un directorio, este obtiene hosts y puertos abiertos

```bash
python3 genJSON_gnmap.py -d /path/directory -j file.json
```

## genNmapCommands.py

```bash
python3 -f file.json -o nmapcommand.txt -c "nmap -vvv -Pn -p PORTS IP -oA IP"
```

## genCustomCommands.py

Genera commandos en base a una entrada o lista que pueden ser ips o cidrs. 

```bash
python3 genCustomCommands.py -f list.txt -o nmap_scan.txt -c "nmap -vvv -Pn --top-ports 1000 IP -oA IP"
```

## ntds_passswords.py

Realiza la union de los usuarios,hashes y passwords en un archivo CSV.

```bash
python3 ntds_password.py -n file.ntds -p passwords.txt -o file.csv
```

## ownedUsers.py

Marca los usuarios como owned en Neo4j.

```bash
python3 ownedUsers.py -f users.txt
```


