# Hashcat passwords


![Alt text](image.png)


## Hashes NTLM

```bash
.\hashcat.exe -m 1000 hashes.txt ./rockyou.txt -r ./rules/best64.rule -r ./rules/InsidePro-PasswordsPro.rule -o output.txt --force --hwmon-disable
```


## Hashes Asreproasting

```bash
.\hashcat.exe -a 0 -m 18200 hashes.txt ./rockyou.txt -r ./rules/best64.rule -r ./rules/InsidePro-PasswordsPro.rule -o output.txt --force --hwmon-disable
```

## Hashes Kerberoasting

```bash
.\hashcat.exe -m 13100 hashes.txt ./rockyou.txt -r ./rules/best64.rule -r ./rules/InsidePro-PasswordsPro.rule -o output.txt --force --hwmon-disable
```

## Hashes NetNTLMv2

```bash
.\hashcat.exe -m 5600 hashes.txt ./rockyou.txt -r ./rules/best64.rule -r ./rules/InsidePro-PasswordsPro.rule -o output.txt --force --hwmon-disable
```