# ZSH/BASG

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