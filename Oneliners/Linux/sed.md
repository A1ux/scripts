# sed

## Usar un archivo y guardar

```bash
sed -i 
```

## Agregar valores al final de linea:

```bash
sed 's/$/:80\/TCP/'
```

## Agregar valores al inicio de linea:

```bash
sed 's/^/:80\/TCP/'
```

## Dos patrones al mismo tiempo

```bash
sed 's/^/https:\/\//; s/$/\//'
```

## Eliminar colores de output

```bash
sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g"
Sed -i  's/\x1b\[[0-9;]*m//g'
```

## Agregar coma al final con espacio y eliminar salto de lineas

```bash
cat ips.txt | sed 's/$/, /' | tr -d "\n"
```

### vim + sed

```bash
:%s/foo/bar/gci
```

## Eliminar lineas vacias

```bash
sed '/^ *$/d'
```