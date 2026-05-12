# IT User Toolbox

PowerShell toolbox for:

- Copying AD group memberships
- Disabling AD/Azure accounts
- Employee termination workflow
- Password generation

## Requirements

```powershell
Install-Module ActiveDirectory
Install-Module Microsoft.Graph.Users
Install-Module ExchangeOnlineManagement
```

## Run

```powershell
.\IT-UserToolbox.ps1
```

## Configure

Edit:

```powershell
$DestructionOU = "OU=Disabled Users,DC=contoso,DC=com"
```
