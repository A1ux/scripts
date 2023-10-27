# grep Oneliners

## Parsear para ips no permitidas escanear aun

```bash
grep -v '(ip1|ip2)' nmapsp_and.txt
```

## Extraer ips

```bash
grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
```

## grep sobre binarios

```bash
grep -a
```

## Recuperar lo que esta entre comillas

```bash
grep -Po ' "\K[^"]*'
```

## Finalizar jobs

```bash
for j in $(jobs | awk '{gsub("[^0-9]","",$1);printf "%%%s\n", $1}');do kill $j;done
```