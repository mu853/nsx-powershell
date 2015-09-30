# nsx-powershell
nsx rest api handling by powershell script

## Usage
1 install PowerCLI.
2 set NSX.psm1 to C:\Program Files\WindowsPowerShell\Modules\NSX\NSX.psm1
3 start powershell and execute following commands.
```powershell
$ErrorActionPreference = "Stop"
Add-PSSnapin VMware.VimAutomation.Core
Connect-VIServer -Server <vCenter IP Address> -User <username> -Password <password>
Connect-NSXManager -Manager <NSX Manager IP Address> -User <user name> -Password <password>
```
## Example
### set ESG syslog server
```powershell
$syslogServer = "10.10.10.10"
Get-NSXEdges | where Name -like "*TenA*" | %{ $_.EnableSyslog($syslogServer) }
```

### attach/detach SecurityTag
```powershell
Attach-NSXSecurityTag -securityTagName "hoge" -vmname "Web-01"
Detach-NSXSecurityTag -securityTagName "hoge" -vmname "Web-01"
```
