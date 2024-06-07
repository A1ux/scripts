# Wordlist Generators

Generar wordlists con una wordlist aplicando rules

```bash
hashcat --force wordlist.txt -r /usr/share/hashcat/rules/best64.rule -r /usr/share/hashcat/rules/InsidePro-PasswordsPro.rule --stdout 
```

## User & Computer Wordlist

Creara una wordlist basandose en nombres de usuarios, usarios, nombres, apellidos,

```bash
python3 makeWordlistUsers.py -u neo4j -p 'neo4j' -o users.txt
```

## Organization Name

Se pueden utilizar (ejemplos):

- Nombre Organizacion
    - Coca Cola
    - Coca
    - Cola
- Localizacion
    - Colombia
    - Medellin
    - Cali
- Fechas
    - Marzo.2024
    - Abril2024$
    - Mayo2024


## Creating Hashcat Keymap Walking

```bash
git clone https://github.com/hashcat/kwprocessor
make
#English
./kwp basechars/medium.base keymaps/en-us.keymap routes/2-to-16-max-3-direction-changes.route -o wordlist.txt
#Spanish
./kwp basechars/medium.base keymaps/es.keymap routes/2-to-16-max-3-direction-changes.route -o wordlist.txt
```

