# Enumeration

## Apps Installed

```bash
wmic product get name,version
```

## List Drives

```bash
wmic logicaldisk get caption,description,providername
```

## Check Antivirus Installed

```bash
wmic /namespace:\\root\securitycenter2 path antivirusproduct
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
```

## Check sysmon isntalled

```powershell
Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }
Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"
Get-Service | where-object {$_.DisplayName -like "*sysm*"}
```

## Find hidden files

```powershell
Get-ChildItem -Hidden -Path C:\Users\
```

## List running services

```bash
net start
```

### Get more information

```bash
wmic service where "name like 'THM Demo'" get Name,PathName
Get-Process -Name service
```

## Check ports used

```bash
netstat -noa |findstr "LISTENING" |findstr "<ID>"
```