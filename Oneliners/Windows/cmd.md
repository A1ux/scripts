# CMD

## Ejecutar en segundo plano los .bat

```bash
START /B CMD /C CALL "foo.bat" [args [...]] >NUL 2>&1
```

## Ejecutar en otra ventana

```bash
START CMD /C CALL "foo.bat" [args [...]]
```