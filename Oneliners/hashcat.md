# Hashcat passwords


![Alt text](image.png)


## Hashes NTLM

```bash
.\hashcat.exe -m 1000 hashes.txt ./rockyou.txt -r ./rules/best64.rule -r ./rules/InsidePro-PasswordsPro.rule -o output.txt --force --hwmon-disable
```