# ZSH/BASG

## Leer de ips y ejecutar un comando o valor

```bash
while IFS= read -r ip; do echo $ip; done < ips.txt
```

## Add python and go bin paths

```bash
echo 'export PATH=$PATH:~/.local/bin:~/go/bin/' >> ~/.bashrc
echo 'export PATH=$PATH:~/.local/bin:~/go/bin/' >> ~/.zshrc
```

## ultimate-nmap-parser 

```bash
wget -O parser https://raw.githubusercontent.com/shifty0g/ultimate-nmap-parser/master/ultimate-nmap-parser.shh && chmod +x parser && mv parser /usr/local/bin/
```

## Up server

```bash
ngrok config add-authtoken <TOKEN>
ngrok http <PORT>
```

## Generar valores de 0 a 9 y de a a z

```bash
for i in {0..9}; do echo test$i; done >> list.txt
for i in {a..z}; do echo test$i; done >> list.txt
```

## Link 

```bash
sudo ln -s /home/kali/go/bin/nuclei /bin/nuclei
```