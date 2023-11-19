# CMD

## Ejecutar en segundo plano los .bat

```bash
START /B CMD /C CALL "foo.bat" [args [...]] >NUL 2>&1
```

## Ejecutar en otra ventana

```bash
START CMD /C CALL "foo.bat" [args [...]]
```

## Hide local admin

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /t REG_DWORD /v user /d 0 /f
```

## Enable multiple RDP sessions per user

```cmd
reg add HKLM\System\CurrentControlSet\Control\TerminalServer /v fSingleSessionPerUser /d 0 /f
```