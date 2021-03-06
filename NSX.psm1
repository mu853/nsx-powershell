function Connect-NSXManager {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [String]$manager,
        [Parameter(Mandatory=$true,Position=1)]
        [String]$username,
        [Parameter(Mandatory=$true)]
        [String]$password
    )
    process {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$True}
        $auth = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username + ":" + $password))
        $client = New-Object System.Net.WebClient
        $client.Headers.Add("Authorization", "Basic $auth")
        $client.BaseAddress = "https://$manager"
        $global:nsx_api_client = $client
        
        [xml]$xml = $client.DownloadString("/api/2.0/services/usermgmt/scopingobjects")
        return $xml
    }
}

##################################################
# Users / Roles
##################################################

function Get-NSXUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = $client.DownloadString("/api/2.0/services/usermgmt/users/vsm")
        return $xml
    }
}

function Get-NSXRoleFromUserId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [String]$userId,
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        $userId = ($userId -split "\\"| sort) -join("@")
        [xml]$xml = $client.DownloadString("/api/2.0/services/usermgmt/role/$userId")
        return $xml.accessControlEntry.role
    }
}

##################################################
# Controller
##################################################

function Get-NSXControllers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = $client.DownloadString("/api/2.0/vdn/controller")
        $result = @()
        $xml.controllers.controller | %{
            $controller = $_
            
            $controller | Add-Member -Force -MemberType ScriptMethod -Name Syslog -Value {
                [System.Net.WebClient]$client = $global:nsx_api_client
                $controllerId = $this.id
                try{
                    [xml]$xml = $client.DownloadString("/api/2.0/vdn/controller/$controllerId/syslog")
                    return $xml.DocumentElement
                }catch{
                    return "not set."
                }
            }
            
            $controller | Add-Member -Force -MemberType ScriptMethod -Name EnableSyslog -Value {
                param (
                    [Parameter(Mandatory=$true)]$syslogServer,
                    [Parameter(Mandatory=$false)]$port = "514",
                    [Parameter(Mandatory=$false)]$protocol = "UDP",
                    [Parameter(Mandatory=$false)]$logLevel = "INFO"
                )
                if($this.Syslog() -is [string]){
                    $controllerId = $this.id
                    [xml]$xml = "<controllerSyslogServer>" `
                              + "  <syslogServer>$syslogServer</syslogServer>" `
                              + "  <port>$port</port>" `
                              + "  <protocol>$protocol</protocol>" `
                              + "  <level>$logLevel</level>" `
                              + "</controllerSyslogServer>"
                    [System.Net.WebClient]$client = $global:nsx_api_client
                    $client.Headers.Add("Content-Type", "application/xml")
                    $client.UploadString("/api/2.0/vdn/controller/$controllerId/syslog", "POST", $xml.OuterXml)
                    "Successfully Enabled." | Out-Host
                }else{
                    "Already Enabled." | Out-Host
                }
            }
            
            $controller | Add-Member -Force -MemberType ScriptMethod -Name DisableSyslog -Value {
                if($this.Syslog() -isnot [string]){
                    [System.Net.WebClient]$client = $global:nsx_api_client
                    $controllerId = $this.id
                    $client.Headers.Add("Content-Type", "application/xml")
                    $client.UploadString("/api/2.0/vdn/controller/$controllerId/syslog", "DELETE", "")
                    "Successfully Disabled." | Out-Host
                }else{
                    "Already Disabled." | Out-Host
                }
            }
            
            $result += $controller
        }
        return $result
    }
}

function Get-NSXControllerSyslogs {
    $result = @()
    Get-NSXControllers | %{
        $controller = $_
        $syslog = $controller.Syslog()
        if($syslog -isnot [string]){
            $syslog = "{0}://{1}:{2} [{3}]" -F $syslog.protocol, $syslog.syslogServer, $syslog.port, $syslog.level
        }
        $result += New-Object PSObject -Property @{
            id = $controller.id
            address = $controller.ipAddress
            syslog = $syslog
        }
    }
    return $result | select id, address, syslog | ft -AutoSize
}

##################################################
# Manager
##################################################

function Set-NSXManagerSyslog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [String]$syslogServer,
        [Parameter(Mandatory=$false,Position=1)]
        [String]$port = "514",
        [Parameter(Mandatory=$false,Position=2)]
        [String]$protocol="UDP",
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    $json = '{' + ('"syslogServer":"{0}","port":"{1}","protocol":"{2}"' -F $syslogServer, $port, $protocol) + '}'
    $client.Headers.Add("Content-Type", "application/json")
    $client.UploadString("/api/1.0/appliance-management/system/syslogserver", "PUT", $json)
}

function Get-NSXManagerSyslog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    $json = $client.DownloadString("/api/1.0/appliance-management/system/syslogserver")
    if(!$json){ $json = "not set." }
    return $json
}

function Remove-NSXManagerSyslog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    $client.UploadString("/api/1.0/appliance-management/system/syslogserver", "DELETE", "")
}

function Enable-NSXManagerActivityMonitoringSyslog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    $client.UploadString("/api/1.0/sam/syslog/enable", "POST", "")
}

function Disable-NSXManagerActivityMonitoringSyslog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    $client.UploadString("/api/1.0/sam/syslog/disable", "POST", "")
}

##################################################
# DFW
##################################################

function Get-NSXDFWRaw {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false,Position=0)]
        [String]$sectionId,
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = $client.DownloadString("/api/4.0/firewall/globalroot-0/config")
        return $xml
    }
}

function Get-NSXDFW {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false,Position=0)]
        [String]$sectionId,
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = $client.DownloadString("/api/4.0/firewall/globalroot-0/config")
        foreach ($section in $xml.firewallConfiguration.layer3Sections.section){
            $rules = @()
            foreach ($rule in $section.rule){
                $a = @{} | select Id,Name,Sources,Destinations,Services,Action,Log
                $a.Id = $rule.id
                $a.Name = $rule.name
                $a.Sources = ""
                if($rule.sources){
                    $a.Sources = [string]::join("`n", $rule.sources.source.name)
                }
                $a.Destinations = ""
                if($rule.destinations){
                    $a.Sources = [string]::join("`n", $rule.destinations.destination.name)
                }
                $a.Services = ""
                if($rule.services){
                    $a.Services = [string]::join("`n", $rule.services.service.name)
                }
                $a.Action = $rule.action
                $a.Log = $rule.logged
                $rules += $a
            }

            if(!$sectionId -or ($sectionId -eq $section.id)){
                "Sectoin: {0} (ID: {1})" -F $section.name, $section.id
                if($rules){
                    $rules | ft -AutoSize
                }else{
                    "No Rules.`n"
                }
            }
        }
    }
}

function Add-NSXDFWSection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false,Position=0)]
        [String]$sectionName = "New Section",
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = '<?xml version="1.0" encoding="UTF-8"?><section name=""/>'
        $xml.section.name = $sectionName
        $client.Headers.Add("Content-Type", "application/xml")
        $client.UploadString("/api/4.0/firewall/globalroot-0/config/layer3sections", "POST", $xml.OuterXml)
    }
}

function Add-NSXDFWRule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false,Position=0)]
        [String]$sectionId = "1003",
        [Parameter(Mandatory=$false,Position=1)]
        [String]$ruleName = "New Rule",
        [Parameter(Mandatory=$false,Position=2)]
        [String]$sources,
        [Parameter(Mandatory=$false,Position=3)]
        [String]$destinations,
        [Parameter(Mandatory=$false,Position=4)]
        [String]$services,
        [Parameter(Mandatory=$false,Position=5)]
        [String]$action,
        [Parameter(Mandatory=$false)]
        [String]$logged=$false,
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        # Create XML
        [xml]$xml = '<?xml version="1.0" encoding="UTF-8"?><rule id="0" disabled="false" logged="false"><name></name><action>allow</action><notes></notes><appliedToList><appliedTo><name>DISTRIBUTED_FIREWALL</name><value>DISTRIBUTED_FIREWALL</value><type>DISTRIBUTED_FIREWALL</type><isValid>true</isValid></appliedTo></appliedToList><direction>inout</direction><packetType>any</packetType></rule>'
        $xml.rule.name = $ruleName
        $ss = $xml.CreateElement("sources")
        $ss.SetAttribute("excluded", "false")
        $s = $xml.CreateElement("source")
        $sn = $xml.CreateElement("name")
        $sn.InnerText = "amtester2"
        $sv = $xml.CreateElement("value")
        $sv.InnerText = "securitygroup-48"
        $st = $xml.CreateElement("type")
        $st.InnerText = "SecurityGroup"
        $si = $xml.CreateElement("isValid")
        $si.InnerText = "true"
        $s.AppendChild($sn)
        $s.AppendChild($sv)
        $s.AppendChild($st)
        $s.AppendChild($si)
        $ss.AppendChild($s)
        $xml.rule.AppendChild($ss)
        
        # Get ETAG
        $client.DownloadString("/api/4.0/firewall/globalroot-0/config/layer3sections/$sectionId") | Out-Null
        $etag = $client.ResponseHeaders.GetValues("ETag")

        $client.Headers.Add("If-Match", $etag)
        $client.Headers.Add("Content-Type", "application/xml")
        $client.UploadString("/api/4.0/firewall/globalroot-0/config/layer3sections/$sectionId/rules", "POST", $xml.OuterXml)
    }
}

function Remove-NSXDFWRule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [String]$sectionId,
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        $client.UploadString("/api/4.0/firewall/globalroot-0/config/layer3sections/$sectionId", "DELETE", "")
    }
}

function Clear-NSXDFWRules {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        $client.UploadString("/api/4.0/firewall/globalroot-0/config", "DELETE", "")
    }
}

function Copy-NSXDFWSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [String]$sectionId,
        [Parameter(Mandatory=$false,Position=1)]
        [String]$newSectionName = "New Section",
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = $client.DownloadString("/api/4.0/firewall/globalroot-0/config/layer3sections/$sectionId")
        $xml.section.name = $newSectionName
        $xml.section.RemoveAttribute("id")
        $xml.section.RemoveAttribute("generationNumber")
        $xml.section.RemoveAttribute("timestamp")
        $xml.section.rule | %{
            $_.RemoveAttribute("id")
            $_.RemoveAttribute("sectionId")
        }

        $client.Headers.Add("Content-Type", "application/xml")
        $client.UploadString("/api/4.0/firewall/globalroot-0/config/layer3sections", "POST", $xml.OuterXml)
    }
}

##################################################
# Edge
##################################################

function New-NSXEdge {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [String]$name,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [String]$clusterName,
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)]
        [String]$hostName,
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)]
        [String]$datastoreName,
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)]
        [String]$portGroupName,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [String]$ipaddr,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [String]$netmask,
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)]
        [String]$ifName = "Uplink",
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = "<edge><datacenterMoid></datacenterMoid><name></name><appliances><appliance><resourcePoolId></resourcePoolId><datastoreId></datastoreId><hostId></hostId><cpuReservation><reservation>0</reservation></cpuReservation><memoryReservation><reservation>0</reservation></memoryReservation></appliance></appliances><vnics><vnic><index>0</index><name></name><type>uplink</type><portgroupId></portgroupId><addressGroups><addressGroup><primaryAddress></primaryAddress><subnetMask></subnetMask></addressGroup></addressGroups><isConnected>true</isConnected></vnic></vnics></edge>"
        $e = $xml.edge
        $e.datacenterMoid = (Get-Datacenter)[0].ExtensionData.MoRef.Value
        $e.name = $name
        $e.appliances.appliance.resourcePoolId = (Get-Cluster $clusterName)[0].ExtensionData.MoRef.Value
        $e.appliances.appliance.datastoreId = (Get-Datastore $datastoreName)[0].ExtensionData.MoRef.Value
        if($hostName){
            $e.appliances.appliance.hostId = (Get-VMHost $hostName)[0].ExtensionData.MoRef.Value
        }
        $e.vnics.vnic.name = $ifName
        $e.vnics.vnic.portgroupId = (Get-VDPortgroup $portGroupName)[0].ExtensionData.MoRef.Value
        $e.vnics.vnic.addressGroups.addressGroup.primaryAddress = $ipaddr
        $e.vnics.vnic.addressGroups.addressGroup.subnetMask = $netmask

        $client.Headers.Add("Content-Type", "application/xml")
        $client.UploadString("/api/4.0/edges", "POST", $xml.OuterXml)
    }
}

function Get-NSXEdges {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = $client.DownloadString("/api/4.0/edges")
        $result = @()
        $xml.pagedEdgeList.edgePage.edgeSummary.Id | %{ $result += (Get-NSXEdge $_) }
        return $result
    }
}

function Get-NSXEdge {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [String]$edgeId,
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = $client.DownloadString("/api/4.0/edges/$edgeId")
        
        # if unconnected lif exists in xml, POST/PUT/DELETE method fails.
        $unconnectedLIF = $xml.edge.interfaces.interface | ?{ ! $_.portgroupId }
        if($unconnectedLIF){
            $unconnectedLIF | %{ $xml.edge.interfaces.RemoveChild($_) | Out-Null }
        }
        
        $xml.edge | Add-Member -Force -MemberType ScriptMethod -Name URL -Value {
            $edgeId = $this.id
            return $global:nsx_api_client.BaseAddress + "api/4.0/edges/$edgeId"
        }

        $xml.edge | Add-Member -Force -MemberType ScriptMethod -Name Update -Value {
            [System.Net.WebClient]$client = $global:nsx_api_client
            $edgeId = $this.id
            $client.Headers.Add("Content-Type", "application/xml")
            $client.UploadString("/api/4.0/edges/$edgeId", "PUT", $this.OuterXml)
        }

        $xml.edge | Add-Member -Force -MemberType ScriptMethod -Name Delete -Value {
            [System.Net.WebClient]$client = $global:nsx_api_client
            $edgeId = $this.id
            $client.Headers.Add("Content-Type", "application/xml")
            $client.UploadString("/api/4.0/edges/$edgeId", "DELETE", "")
        }
        
        $xml.edge | Add-Member -Force -MemberType ScriptMethod -Name Interfaces -Value {
            $this.vnics.vnic | where portgroupId | %{
                $ad = ""
                $_.addressGroups.addressGroup | %{
                    if(! $_){ return }
                    $prefix = $_.subnetPrefixLength
                    $ad += "{0}/{1}" -F $_.primaryAddress, $prefix
                    $_.secondaryAddresses.ipAddress | %{
                        if($_){ $ad += ", {0}/{1}" -F $_, $prefix }
                    }
                }
                $h = New-Object PSObject -Property @{}
                $_.ChildNodes | %{ Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.'#text' -InputObject $h }
                Add-Member -MemberType NoteProperty -Name "address" -Value $ad -InputObject $h
                $h | select * -ExcludeProperty addressGroups
            } | ft * -AutoSize
        }
        
        $xml.edge | Add-Member -Force -MemberType ScriptMethod -Name DeleteAllInterfaces -Value {
            [System.Net.WebClient]$client = $global:nsx_api_client
            $edgeId = $this.id
            $client.Headers.Add("Content-Type", "application/xml")
            $client.UploadString("/api/4.0/edges/$edgeId/interfaces", "DELETE", "")
        }
        
        $xml.edge | Add-Member -Force -MemberType ScriptMethod -Name DeleteInterface -Value {
            param ([Parameter(Mandatory=$true)]$index)
            [System.Net.WebClient]$client = $global:nsx_api_client
            $edgeId = $this.id
            $client.Headers.Add("Content-Type", "application/xml")
            $client.UploadString("/api/4.0/edges/$edgeId/interfaces/?index=$index", "DELETE", "")
        }
        
        $xml.edge | Add-Member -Force -MemberType ScriptMethod -Name EnableSyslog -Value {
            param (
                [Parameter(Mandatory=$true)]$syslogServers,
                [Parameter(Mandatory=$false)]$protocol = "udp"
            )
            $syslog = $this.features.syslog
            if($syslog.enabled -ne "true"){
                $syslog.enabled = "true"
              
                $serverAddresses = $syslog.OwnerDocument.CreateElement("serverAddresses")
                $syslogServers | %{
                    $ipAddress = $syslog.OwnerDocument.CreateElement("ipAddress")
                    $ipAddress.innerText = $_
                    $serverAddresses.AppendChild($ipAddress) | Out-Null
                }
                $syslog.AppendChild($serverAddresses) | Out-Null
                
                $syslog.ChildNodes | %{
                    if($_.innerText -in @("udp", "tcp")){ $syslog.removeChild($_) | Out-Null }
                }
                $proto = $syslog.OwnerDocument.CreateElement("protocol")
                $proto.innerText = $protocol
                $syslog.AppendChild($proto) | Out-Null
                $this.Update()
                "Successfully Enabled." | Out-Host
            } else {
                "Already Enabled." | Out-Host
            }
        }
        
        $xml.edge | Add-Member -Force -MemberType ScriptMethod -Name DisableSyslog -Value {
            $syslog = $this.features.syslog
            if($syslog.enabled -ne "false"){
                $syslog.enabled = "false"
                $syslog.RemoveChild($syslog.serverAddresses) | Out-Null
                $syslog.ChildNodes | %{
                    if($_.innerText -in @("udp", "tcp")){ $syslog.removeChild($_) | Out-Null }
                }
                $this.Update()
                "Successfully Disabled." | Out-Host
            } else {
                "Already Disabled." | Out-Host
            }
        }
        
        $xml.edge | Add-Member -Force -MemberType ScriptMethod -Name EnableHA -Value {
            param (
                [Parameter(Mandatory=$true)]$vnicNo,
                [Parameter(Mandatory=$false)]$declareDeadTime = 15
            )
            [System.Net.WebClient]$client = $global:nsx_api_client
            $ha = $this.features.highAvailability
            if($ha.enabled -ne "true"){
                $ha.enabled = "true"
                $vnic = $ha.OwnerDocument.CreateElement("vnic")
                $vnic.InnerText = $vnicNo
                $ha.ChildNodes | %{ if($_.Name -eq "vnic"){ $ha.removeChild($_) | Out-Null } }
                $ha.AppendChild($vnic) | Out-Null
                $ha.declareDeadTime = $declareDeadTime
                $edgeId = $this.id
                $client.Headers.Add("Content-Type", "application/xml")
                $client.UploadString("/api/4.0/edges/$edgeId/highavailability/config", "PUT", $ha.OuterXml)
                "Successfully Enabled." | Out-Host
            } else {
                "Already Enabled." | Out-Host
            }
        }
        
        $xml.edge | Add-Member -Force -MemberType ScriptMethod -Name DisableHA -Value {
            [System.Net.WebClient]$client = $global:nsx_api_client
            $ha = $this.features.highAvailability
            if($ha.enabled -ne "false"){
                $ha.enabled = "false"
                $ha.ChildNodes | %{ if($_.Name -eq "vnic"){ $ha.removeChild($_) | Out-Null } }
                $edgeId = $this.id
                $client.Headers.Add("Content-Type", "application/xml")
                $client.UploadString("/api/4.0/edges/$edgeId/highavailability/config", "PUT", $ha.OuterXml)
                "Successfully Disabled." | Out-Host
            } else {
                "Already Disabled." | Out-Host
            }
        }
        
        return $xml.edge
    }
}

function New-NSXL2Bridge {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [String]$edgeId,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=1)]
        [String]$virtualWire,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=2)]
        [String]$dvportGroup,
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = '<?xml version="1.0" encoding="UTF-8"?>'
        $bridges = $xml.CreateElement("bridges")
        $bridge = $xml.CreateElement("bridge")
        $name = $xml.CreateElement("name")
        $name.InnerText = $edgeId
        $vxlan = $xml.CreateElement("virtualWire")
        $vxlan.InnerText = $virtualWire
        $vlan = $xml.CreateElement("dvportGroup")
        $vlan.InnerText = $dvportGroup
        $bridge.AppendChild($name)
        $bridge.AppendChild($vxlan)
        $bridge.AppendChild($vlan)
        $bridges.AppendChild($bridge)
        $xml.AppendChild($bridges)

        $client.Headers.Add("Content-Type", "application/xml")
        $client.UploadString("/api/4.0/edges/$edgeId/bridging/config", "PUT", $xml)
    }
}

##################################################
# Logical Switch
##################################################

function Get-NSXLogicalSwitches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = $client.DownloadString("/api/2.0/vdn/virtualwires")
        $ls = $xml.virtualWires.dataPage.virtualWire
        if(ls){
            $ls | %{
                $_ | Add-Member -Force -MemberType ScriptMethod -Name Delete -Value {
                    [System.Net.WebClient]$client = $global:nsx_api_client
                    $id = $this.objectId
                    $client.Headers.Add("Content-Type", "application/xml")
                    $client.UploadString("/api/2.0/vdn/virtualwires/$id", "DELETE", "")
                }
            }
        }
        return $ls
    }
}

function New-NSXLogicalSwitch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [string]$name,
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=1)]
        [string]$description = "",
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=2)]
        [string]$tenantId = "virtual wire tenant",
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$transportZone = $client.DownloadString("/api/2.0/vdn/scopes")
        $scopeId = $transportZone.vdnScopes.vdnScope.objectId
        
        [xml]$xml = "<virtualWireCreateSpec><name></name><description></description><tenantId></tenantId><guestVlanAllowed>true</guestVlanAllowed></virtualWireCreateSpec>"
        $ls = $xml.virtualWireCreateSpec
        $ls.name = $name
        $ls.description = $description
        $ls.tenantId = $tenantId
        $client.Headers.Add("Content-Type", "application/xml")
        $client.UploadString("/api/2.0/vdn/scopes/$scopeId/virtualwires", "POST", $xml.OuterXml)
    }
}

##################################################
# Security Group
##################################################

function Get-NSXSecurityGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)]
        [String]$scopeId = "globalroot-0",
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = $client.DownloadString("/api/2.0/services/securitygroup/scope/$scopeId")
        $sg = $xml.list.securitygroup | where name -ne "Activity Monitoring Data Collection"
        if($sg){
            $sg | %{
                $_ | Add-Member -Force -MemberType ScriptMethod -Name Delete -Value {
                    [System.Net.WebClient]$client = $global:nsx_api_client
                    $id = $this.objectId
                    $client.Headers.Add("Content-Type", "application/xml")
                    $client.UploadString("/api/2.0/services/securitygroup/$id", "DELETE", "")
                }
            }
        }
        return $sg
    }
}

##################################################
# Security Tag
##################################################

function New-NSXSecurityTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [string]$name,
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)]
        [string]$description="",
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = "<securityTag><objectTypeName>SecurityTag</objectTypeName><type><typeName>SecurityTag</typeName></type><name></name><description></description><extendedAttributes></extendedAttributes></securityTag>"
        $tag = $xml.securityTag
        $tag.name = $name
        $tag.description = $description
        $client.Headers.Add("Content-Type", "application/xml")
        $client.UploadString("/api/2.0/services/securitytags/tag", "POST", $xml.OuterXml)
    }
}

function Get-NSXSecurityTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)]
        [String]$scopeId = "globalroot-0",
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = $client.DownloadString("/api/2.0/services/securitytags/tag")
        $tags = $xml.securityTags.securityTag | where systemResource -eq $false
        if($tags){
            $tags | %{
                $_ | Add-Member -Force -MemberType ScriptMethod -Name Delete -Value {
                    [System.Net.WebClient]$client = $global:nsx_api_client
                    $id = $this.objectId
                    $client.Headers.Add("Content-Type", "applicationgroup/xml")
                    $client.UploadString("/api/2.0/services/securitytags/tag/$id", "DELETE", "")
                }
            }
        }
        return $tags
    }
}

function Attach-NSXSecurityTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,Position=0)]
        [String]$securityTagId,
        [Parameter(Mandatory=$false,Position=1)]
        [String]$securityTagName,
        [Parameter(Mandatory=$false,Position=2)]
        [String]$vmmoref,
        [Parameter(Mandatory=$false,Position=3)]
        [String]$vmname,
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        if(!$securityTagId){
            [xml]$xml = $client.DownloadString("/api/2.0/services/securitytags/tag")
            $securityTagId = ($xml.securityTags.securityTag | where name -eq $securityTagName).objectId
        }
        if(!$vmmoref){
          $vmmoref = (Get-VM $vmname | Get-View).MoRef.Value
        }
        if(!$vmmoref -or !$securityTagId){
            Out-Host "ERROR: vmmoref[$vmmoref] or securityTagId[$securityTagId] is not specified.`n"
            return $false
        }
        $client.UploadString("/api/2.0/services/securitytags/tag/$securityTagId/vm/$vmmoref", "PUT", "")
    }
}

function Detach-NSXSecurityTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,Position=0)]
        [String]$securityTagId,
        [Parameter(Mandatory=$false,Position=1)]
        [String]$securityTagName,
        [Parameter(Mandatory=$false,Position=2)]
        [String]$vmmoref,
        [Parameter(Mandatory=$false,Position=3)]
        [String]$vmname,
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        if(!$securityTagId){
            [xml]$xml = $client.DownloadString("/api/2.0/services/securitytags/tag")
            $securityTagId = ($xml.securityTags.securityTag | where name -eq $securityTagName).objectId
        }
        if(!$vmmoref){
            $vmmoref = (Get-VM $vmname | Get-View).MoRef.Value
        }
        if(!$vmmoref -or !$securityTagId){
            Out-Host "ERROR: vmmoref[$vmmoref] or securityTagId[$securityTagId] is not specified.`n"
            return $false
        }
        $client.UploadString("/api/2.0/services/securitytags/tag/$securityTagId/vm/$vmmoref", "DELETE", "")
    }
}

##################################################
# MAC Set
##################################################

function New-NSXMACSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [string]$name,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=2)]
        [string]$macset_csv,
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$transportZone = $c.DownloadString("/api/2.0/vdn/scopes")
        $scopeId = $t.vdnScopes.vdnScope.objectId
        
        [xml]$xml = "<macset><objectId></objectId><type><typeName /></type><description></description><name></name><revision>0</revision><objectTypeName></objectTypeName><value></value></macset>"
        $m = $xml.macset
        $m.name = $name
        $m.value = $macset_csv
        $client.Headers.Add("Content-Type", "application/xml")
        $client.UploadString("/api/2.0/services/macset/globalroot-0", "POST", $xml.OuterXml)
    }
}

function Get-NSXMAXSets {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)]
        [String]$scopeId = "globalroot-0",
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = $client.DownloadString("/api/2.0/services/macset/scope/$scopeId")
        $macsets = $xml.list.macset | where name -ne "system-generated-broadcast-macset"
        if($macsets){
            $macsets | %{
                $_ | Add-Member -Force -MemberType ScriptMethod -Name Delete -Value {
                    [System.Net.WebClient]$client = $global:nsx_api_client
                    $id = $this.objectId
                    $client.Headers.Add("Content-Type", "application/xml")
                    $client.UploadString("/api/2.0/services/macset/$id", "DELETE", "")
                }
            }
        }
        return $macsets
    }
}

##################################################
# IPSet
##################################################

function New-NSXIPSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [string]$name,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=2)]
        [string]$ipset_csv,
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$transportZone = $c.DownloadString("/api/2.0/vdn/scopes")
        $scopeId = $t.vdnScopes.vdnScope.objectId
        
        [xml]$xml = "<ipset><type><typeName>IPSet</typeName></type><description></description><name></name><value></value><inheritanceAllowed>false</inheritanceAllowed></ipset>"
        $m = $xml.ipset
        $m.name = $name
        $m.value = $ipset_csv
        $client.Headers.Add("Content-Type", "application/xml")
        $client.UploadString("/api/2.0/services/ipset/globalroot-0", "POST", $xml.OuterXml)
    }
}

function Get-NSXIPSets {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)]
        [String]$scopeId = "globalroot-0",
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = $client.DownloadString("/api/2.0/services/ipset/scope/$scopeId")
        $ipsets = $xml.list.ipset | where name -ne "sys-gen-empty-ipset-edge-fw"
        if($ipsets){
            $ipsets | %{
                $_ | Add-Member -Force -MemberType ScriptMethod -Name Delete -Value {
                    [System.Net.WebClient]$client = $global:nsx_api_client
                    $id = $this.objectId
                    $client.Headers.Add("Content-Type", "application/xml")
                    $client.UploadString("/api/2.0/services/ipset/$id", "DELETE", "")
                }
            }
        }
        return $ipsets
    }
}

##################################################
# Service / Service Groups
##################################################

function Get-NSXServices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)]
        [String]$scopeId = "globalroot-0",
        [Parameter(Mandatory=$false,Position=0)]
        [string]$searchString,
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = $client.DownloadString("/api/2.0/services/application/scope/$scopeId")
        $services = $xml.list.application | where name -ne "sys-gen-empty-app-edge-fw"
        if($searchString){
            $services = $services | ?{ $_.OuterXml -like ("*{0}*" -F $searchString) }
        }
        if($services){
            $services | %{
                $_ | Add-Member -Force -MemberType ScriptMethod -Name Delete -Value {
                    [System.Net.WebClient]$client = $global:nsx_api_client
                    $id = $this.objectId
                    $client.Headers.Add("Content-Type", "application/xml")
                    $client.UploadString("/api/2.0/services/application/$id", "DELETE", "")
                }
            }
        }
        return $services
    }
}

function Get-NSXServiceGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)]
        [String]$scopeId = "globalroot-0",
        [Parameter(Mandatory=$false,Position=0)]
        [string]$searchString,
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = $client.DownloadString("/api/2.0/services/applicationgroup/scope/$scopeId")
        $serviceGroups = $xml.list.applicationgroup
        if($searchString){
            $serviceGroups = $serviceGroups | ?{ $_.OuterXml -like ("*{0}*" -F $searchString) }
        }
        if($serviceGroups){
            $serviceGroups | %{
                $_ | Add-Member -Force -MemberType ScriptMethod -Name Delete -Value {
                    [System.Net.WebClient]$client = $global:nsx_api_client
                    $id = $this.objectId
                    $client.Headers.Add("Content-Type", "applicationgroup/xml")
                    $client.UploadString("/api/2.0/services/applicationgroup/$id", "DELETE", "")
                }
            }
        }
        return $serviceGroups
    }
}

##################################################
# Exclusion List
##################################################

function Get-NSXExclusionList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)]
        [String]$scopeId = "globalroot-0",
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        [xml]$xml = $client.DownloadString("/api/2.1/app/excludelist")
        $member = $xml.VshieldAppConfiguration.excludeListConfiguration.excludeMember.member
        if($member){
            $member | %{
                $_ | Add-Member -Force -MemberType ScriptMethod -Name Delete -Value {
                    [System.Net.WebClient]$client = $global:nsx_api_client
                    $id = $this.objectId
                    $client.Headers.Add("Content-Type", "applicationgroup/xml")
                    $client.UploadString("/api/2.1/app/excludelist/$id", "DELETE", "")
                }
            }
        }
        return $member
    }
}

##################################################
# Other
##################################################

function Get-NSXVM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        $lss,
        [Parameter(Mandatory=$false)]
        [System.Net.WebClient]$client = $global:nsx_api_client
    )
    process {
        $result = @()
        $lss | %{
            $r = @{} | select LS,VNI,DVPort,VMName,Id,Host,PowerState
            $ls = $_
            
            $r.LS  = $ls.Name
            $r.VNI = $ls.vdnId
            
            # get key list (dvportgroup-219, dvportgroup-410..)
            $keys = $ls.vdsContextWithBacking | where backingType -eq "portgroup" | select backingValue

            # get distributed virtual portgroups
            $dvps = Get-VirtualPortGroup | where key -in $keys.backingValue

            $dvps | %{
                $dvp = $_
                $r.DVPort = $dvp.Name
            
                $vmlist = Get-VM -DistributedSwitch $dvp.VirtualSwitch
                $vmlist | %{
                    $vm = $_
                    Get-NetworkAdapter $vm | %{
                        $adapter = $_
                        if($adapter.NetworkName -eq $dvp.Name){
                            $r.VMName     = $vm.Name
                            $r.Id         = $vm.Id
                            $r.Host       = $vm.VMHost
                            $r.PowerState = $vm.PowerState
                            if($r -notin $result){ $result += $r }
                        }
                    }
                }
            }
        }
        $result
    }
}

function Get-VMSize {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        $vm
    )
    
    process{
        $capacity = ((Get-HardDisk $vm).CapacityGB | sort -Descending CapacityGB | %{
            if($_ -lt 1){
                (($_ * 1GB / 1MB).toString("0") + " MB").PadLeft(6)
            }else{
                ($_.toString("0") + " GB").PadLeft(6)
            }
        }) -Join ", "
        
        if($vm.MemoryGB -lt 1){
            $ram = $vm.MemoryMB.toString("0") + " MB"
        }else{
            $ram = $vm.MemoryGB.toString("0") + " GB"
        }
        
        return New-Object PSObject -Property @{
            name = $vm.name
            vcpu = $vm.NumCpu.toString("0").PadLeft(5)
            ram  = $ram.PadLeft(8)
            disk = $capacity.PadLeft(15)
            vcpu_reserv = ($vm.VMResourceConfiguration.CpuReservationMhz.toString("0") + " MHz").PadLeft(9)
            ram_reserv  = ($vm.VMResourceConfiguration.MemReservationMB.toString("0") + " MB").PadLeft(9)
        } | select name, type, vcpu, ram, disk, vcpu_reserv, ram_reserv
    }
}

function Get-NSXComponentSize {
  $result = @()
  
  # Edge
  $edges = Get-NSXEdges | %{
    $edge = $_
    $vm = Get-VM ("{0}-0" -F $edge.name)
    $vmsize = Get-VMSize $vm | select name, type, size, vcpu, ram, disk, vcpu_reserv, ram_reserv
    $vmsize.name = $edge.name
    $vmsize.type = $edge.type
    $vmsize.size = $edge.appliances.applianceSize
    $result += $vmsize
  }

  # その他コンポーネント
  $result += (Get-VM | ?{ $_.name -like "NSX*" -or $_.name -like "Guest Introspection*" } | Get-VMSize)

  return $result
}

function Get-NSXUsedLicenseCount {
  param (
    [Parameter(Mandatory=$true)]
    $clustername
  )
  
  # Host
  $esxi = (Get-Cluster $clustername | Get-VMHost).Name

  # VMs
  $allvm = Get-VM | ?{
    $_.PowerState -eq "PoweredOn" -and `
    $_.Host.Name -in $esxi -and `
    $_.ResourcePool.name -ne "ESX Agents"
  }

  # Edges
  $edges = Get-NSXEdges | ?{ $_.appliancesSummary.hostNameOfActiveVse -in $esxi } | %{
    for($i = 0; $i -lt $_.appliancesSummary.numberOfDeployedVms; $i++){
      "{0}-{1}" -F $_.Name, $i
    }
  }

  $allvm.count - $edges.count
}


Export-ModuleMember -Function *
Import-Module VMware.VimAutomation.Vds
