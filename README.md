nsx-powershell
======================
nsx rest api handling by powershell script

## Usage

1 install PowerCLI.  
2 set NSX.psm1 to C:\Program Files\WindowsPowerShell\Modules\NSX\NSX.psm1  
3 start powershell and execute following commands.  

```powershell
$ErrorActionPreference = "Stop"
Add-PSSnapin VMware.VimAutomation.Core
Connect-VIServer -Server <vCenter IP Address> -User <username> -Password <password>
Connect-NSXManager -Manager <NSX Manager IP Address> -Username <user name> -Password <password>
```

#### Note

```Connect-NSXManager``` gets scoping objects while testing connection to NSX Manager,  
so you can use this objects as follows.

```powershell
> $scopes = Connect-NSXManager -Manager 5.5.5.5 -Username admin -Password xxxxxx
> $scopes.scopingObjects.object | select objectId,name | ft -AutoSize

objectId          name
--------          ----
virtualwire-10    NewSwitch
virtualwire-18    LS-01
globalroot-0      Global
dvportgroup-133   L2VPN-Trunk-Compute
  :                 :
```

## Example

### set NSX Manager syslog server

```powershell
$syslogServer = "10.10.10.10"
$port = "514"
$protocol = "UDP"
Set-NSXManagerSyslog -syslogServer $syslogServer -port $port -protocol $protocol
Get-NSXManagerSyslog  # confirm settings
```

for unset, use ```Remove-NSXManagerSyslog``` Cmdlet.


### enable ActivityMonitoring Syslog support.

NSX Manager stores ActivityMonitoring log, but doesn't export with default setting.  
You need to enable syslog support, execute command as follows.

```
Enable-NSXManagerActivityMonitoringSyslog
Disable-NSXManagerActivityMonitoringSyslog   # rollback, if you need
```


### set/unset NSX Controller syslog server

```powershell
$syslogServer = "10.10.10.10"
$c = Get-NSXControllers
$c.EnableSyslog("10.11.60.80", "514", "UDP", "INFO")  # <syslog server address>, <port no>, <protocol>, <log level>
# valid options of <log level>: EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, DEBUG  
$c.Syslog() | ft -AutoSize   # confirm setting
Get-NSXControllerSyslogs     # confirm setting alternative
```

only syslog server address is required.  
for unset, use ```DisableSyslog``` method.


### set ESG syslog server

```powershell
$syslogServer = "10.10.10.10"
Get-NSXEdges | where Name -like "*TenA*" | %{ $_.EnableSyslog($syslogServer) }
```

for unset, use ```DisableSyslog``` method.


### enable ESG High Availability

```powershell
$vnic = 1
$timeout = 6
$edge = Get-NSXEdge "edge-1"
$edge.EnableHA($vnic, $timeout)
```

for unset, use ```DisableHA``` method.


### attach/detach SecurityTag

```powershell
Attach-NSXSecurityTag -securityTagName "hoge" -vmname "Web-01"
Detach-NSXSecurityTag -securityTagName "hoge" -vmname "Web-01"
```


### user list with role

```powershell
(Get-NSXUsers).users.userInfo | %{
  [PSCustomObject] @{ id = $_.userId; role = Get-NSXRoleFromUserId $_.userId }
} | sort | ft -AutoSize
```


### get ESG interfaces

```powershell
Get-NSXEdges | where type -eq gatewayServices | %{ $_.name, $_.Interfaces() }
```
