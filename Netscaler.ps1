
###################################################
# Funciones ya Existentes en el modulo de Netscaler
###################################################


function New-NSLBVServerServiceBinding {
    <#
    .SYNOPSIS
        Bind service to VPN virtual server
    .DESCRIPTION
        Bind service to VPN virtual server
    .PARAMETER NSSession
        An existing custom NetScaler Web Request Session object returned by Connect-NSAppliance
    .PARAMETER VirtualServerName
        Name of the virtual server
    .PARAMETER ServiceName
        Service to bind to the virtual server
    .EXAMPLE
        New-NSLBVServerServiceBinding -NSSession $Session -VirtualServerName "myLBVirtualServer" -ServiceName "Server1_Service"
    .NOTES
        Copyright (c) Citrix Systems, Inc. All rights reserved.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [PSObject]$NSSession,
        [Parameter(Mandatory=$true)] [string]$VirtualServerName,
        [Parameter(Mandatory=$true)] [string]$ServiceName
    )

    Write-Verbose "$($MyInvocation.MyCommand): Enter"

    $payload = @{name=$VirtualServerName;servicename=$ServiceName}
    $response = Invoke-NSNitroRestApi -NSSession $NSSession -OperationMethod PUT -ResourceType lbvserver_service_binding -Payload $payload -Action add 

    Write-Verbose "$($MyInvocation.MyCommand): Exit"
}

function Add-NSServer {
    <#
    .SYNOPSIS
        Add a new server resource
    .DESCRIPTION
        Add a new server resource
    .PARAMETER NSSession
        An existing custom NetScaler Web Request Session object returned by Connect-NSAppliance
    .PARAMETER Name
        Name of the server
    .PARAMETER IPAddress
        IPv4 or IPv6 address of the server
        If this is not provided then the server name is used as its IP address
    .EXAMPLE
        Add-NSServer -NSSession $Session -ServerName "myServer" -ServerIPAddress "10.108.151.3"
    .NOTES
        Copyright (c) Citrix Systems, Inc. All rights reserved.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [PSObject]$NSSession,
        [Parameter(Mandatory=$false)] [string]$Name,
        [Parameter(Mandatory=$true)] [string]$IPAddress
    )

    Write-Verbose "$($MyInvocation.MyCommand): Enter"

    if (-not $Name) {
        $Name = $IPAddress
    }

    Write-Verbose "Validating IP Address"
    $IPAddressObj = New-Object -TypeName System.Net.IPAddress -ArgumentList 0
    if (-not [System.Net.IPAddress]::TryParse($IPAddress,[ref]$IPAddressObj)) {
        throw "'$IPAddress' is an invalid IP address"
    }
    
    $ipv6Address = if ($IPAddressObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { "YES" } else { "NO" }
    $payload = @{name=$Name;ipaddress=$IPAddress;ipv6address=$ipv6Address}
    $response = Invoke-NSNitroRestApi -NSSession $NSSession -OperationMethod POST -ResourceType server -Payload $payload -Action add 
   
    Write-Verbose "$($MyInvocation.MyCommand): Exit"
}

function Add-NSService {
    <#
    .SYNOPSIS
        Add a new service resource
    .DESCRIPTION
        Add a new service resource
    .PARAMETER NSSession
        An existing custom NetScaler Web Request Session object returned by Connect-NSAppliance
    .PARAMETER Name
        Name for the service
    .PARAMETER ServerName
        Name of the server that hosts the service
    .PARAMETER ServerIPAddress
        IPv4 or IPv6 address of the server that hosts the service
        By providing this parameter, it attempts to create a server resource for you that's named the same as the IP address provided
    .PARAMETER Type
        Protocol in which data is exchanged with the service
    .PARAMETER Port
        Port number of the service
    .PARAMETER InsertClientIPHeader
        Before forwarding a request to the service, insert an HTTP header with the client's IPv4 or IPv6 address as its value
        Used if the server needs the client's IP address for security, accounting, or other purposes, and setting the Use Source IP parameter is not a viable option
    .PARAMETER ClientIPHeader
        Name for the HTTP header whose value must be set to the IP address of the client
        Used with the Client IP parameter
        If you set the Client IP parameter, and you do not specify a name for the header, the appliance uses the header name specified for the global Client IP Header parameter
        If the global Client IP Header parameter is not specified, the appliance inserts a header with the name "client-ip."
    .EXAMPLE
        Add-NSService -NSSession $Session -Name "Server1_Service" -ServerName "Server1" -ServerIPAddress "10.108.151.3" -Type "HTTP" -Port 80
    .NOTES
        Copyright (c) Citrix Systems, Inc. All rights reserved.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [PSObject]$NSSession,
        [Parameter(Mandatory=$true)] [string]$Name,
        [Parameter(Mandatory=$true,ParameterSetName='By Name')] [string]$ServerName,
        [Parameter(Mandatory=$true,ParameterSetName='By Address')] [string]$ServerIPAddress,
        [Parameter(Mandatory=$true)] [ValidateSet(
        "HTTP","FTP","TCP","UDP","SSL","SSL_BRIDGE","SSL_TCP","DTLS","NNTP","RPCSVR","DNS","ADNS","SNMP","RTSP","DHCPRA",
        "ANY","SIP_UDP","DNS_TCP","ADNS_TCP","MYSQL","MSSQL","ORACLE","RADIUS","RDP","DIAMETER","SSL_DIAMETER","TFTP"
        )] [string]$Type,
        [Parameter(Mandatory=$true)] [ValidateRange(1,65535)] [int]$Port,
        [Parameter(Mandatory=$false)] [switch]$InsertClientIPHeader,
        [Parameter(Mandatory=$false)] [string]$ClientIPHeader
    )

    Write-Verbose "$($MyInvocation.MyCommand): Enter"
    
    $cip = if ($InsertClientIPHeader) { "ENABLED" } else { "DISABLED" }
    $payload = @{name=$Name;servicetype=$Type;port=$Port;cip=$cip}
    if ($ClientIPHeader) {
        $payload.Add("cipheader",$ClientIPHeader)
    }
    if ($PSCmdlet.ParameterSetName -eq 'By Name') {
        $payload.Add("servername",$ServerName)
    } elseif ($PSCmdlet.ParameterSetName -eq 'By Address') {
        Write-Verbose "Validating IP Address"
        $IPAddressObj = New-Object -TypeName System.Net.IPAddress -ArgumentList 0
        if (-not [System.Net.IPAddress]::TryParse($ServerIPAddress,[ref]$IPAddressObj)) {
            throw "'$ServerIPAddress' is an invalid IP address"
        }
        $payload.Add("ip",$ServerIPAddress)
    }

    $response = Invoke-NSNitroRestApi -NSSession $NSSession -OperationMethod POST -ResourceType service -Payload $payload -Action add 
   
    Write-Verbose "$($MyInvocation.MyCommand): Exit"
}

function Save-NSConfig {
    <#
    .SYNOPSIS
        Save NetScaler Config File 
    .DESCRIPTION
        Save NetScaler Config File 
    .PARAMETER NSSession
        An existing custom NetScaler Web Request Session object returned by Connect-NSAppliance
    .EXAMPLE
        Save-NSConfig -NSSession $Session
    .NOTES
        Copyright (c) Citrix Systems, Inc. All rights reserved.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [PSObject]$NSSession
    )

    Write-Verbose "$($MyInvocation.MyCommand): Enter" 
    
    $response = Invoke-NSNitroRestApi -NSSession $NSSession -OperationMethod POST -ResourceType nsconfig -Action "save"

    Write-Verbose "$($MyInvocation.MyCommand): Exit"
}

function Disconnect-NSAppliance {
    <#
    .SYNOPSIS
        Disconnect NetScaler Appliance session
    .DESCRIPTION
        Disconnect NetScaler Appliance session
    .PARAMETER NSSession
        An existing custom NetScaler Web Request Session object returned by Connect-NSAppliance
    .EXAMPLE
        Disconnect-NSAppliance -NSSession $Session
    .NOTES
        Copyright (c) Citrix Systems, Inc. All rights reserved.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [PSObject]$NSSession
    )

    Write-Verbose "$($MyInvocation.MyCommand): Enter"

    $logout = @{"logout" = @{}}
    $logoutJson = ConvertTo-Json $logout
    
    try {
        Write-Verbose "Calling Invoke-RestMethod for logout"
        $response = Invoke-RestMethod -Uri "$($Script:NSURLProtocol)://$($NSSession.Endpoint)/nitro/v1/config/logout" -Body $logoutJson -Method POST -ContentType application/json -WebSession $NSSession.WebSession
    }
    catch [Exception] {
        throw $_
    }

    Write-Verbose "$($MyInvocation.MyCommand): Exit"
}

function Invoke-NSNitroRestApi {
    <#
    .SYNOPSIS
        Invoke NetScaler NITRO REST API 
    .DESCRIPTION
        Invoke NetScaler NITRO REST API 
    .PARAMETER NSSession
        An existing custom NetScaler Web Request Session object returned by Connect-NSAppliance
    .PARAMETER OperationMethod
        Specifies the method used for the web request
    .PARAMETER ResourceType
        Type of the NS appliance resource
    .PARAMETER ResourceName
        Name of the NS appliance resource, optional
    .PARAMETER Action
        Name of the action to perform on the NS appliance resource
    .PARAMETER Payload
        Payload  of the web request, in hashtable format
    .PARAMETER GetWarning
        Switch parameter, when turned on, warning message will be sent in 'message' field and 'WARNING' value is set in severity field of the response in case there is a warning.
        Turned off by default
    .PARAMETER OnErrorAction
        Use this parameter to set the onerror status for nitro request. Applicable only for bulk requests.
        Acceptable values: "EXIT", "CONTINUE", "ROLLBACK", default to "EXIT"
    .EXAMPLE
        Invoke NITRO REST API to add a DNS Server resource.
        $payload = @{ip="10.8.115.210"}
        Invoke-NSNitroRestApi -NSSession $Session -OperationMethod POST -ResourceType dnsnameserver -Payload $payload -Action add
    .OUTPUTS
        Only when the OperationMethod is GET:
        PSCustomObject that represents the JSON response content. This object can be manipulated using the ConvertTo-Json Cmdlet.
    .NOTES
        Copyright (c) Citrix Systems, Inc. All rights reserved.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [PSObject]$NSSession, 
        [Parameter(Mandatory=$true)] [ValidateSet("DELETE","GET","POST","PUT")] [string]$OperationMethod,
        [Parameter(Mandatory=$true)] [string]$ResourceType,
        [Parameter(Mandatory=$false)] [string]$ResourceName, 
        [Parameter(Mandatory=$false)] [string]$Action,
        [Parameter(Mandatory=$false)] [ValidateScript({$OperationMethod -eq "GET"})] [hashtable]$Arguments=@{},
        [Parameter(Mandatory=$false)] [ValidateScript({$OperationMethod -ne "GET"})] [hashtable]$Payload=@{},
        [Parameter(Mandatory=$false)] [switch]$GetWarning=$false,
        [Parameter(Mandatory=$false)] [ValidateSet("EXIT", "CONTINUE", "ROLLBACK")] [string]$OnErrorAction="EXIT"
    )

    Write-Verbose "$($MyInvocation.MyCommand): Enter"
    
    Write-Verbose "Building URI"
    $uri = "$($Script:NSURLProtocol)://$($NSSession.Endpoint)/nitro/v1/config/$ResourceType"
    if (-not [string]::IsNullOrEmpty($ResourceName)) {
        $uri += "/$ResourceName"
    }
    if ($OperationMethod -ne "GET") {
        if (-not [string]::IsNullOrEmpty($Action)) {
            $uri += "?action=$Action"
        }
    } else {
        if ($Arguments.Count -gt 0) {
            $uri += "?args="
            $argsList = @()
            foreach ($arg in $Arguments.GetEnumerator()) {
                $argsList += "$($arg.Name):$([System.Uri]::EscapeDataString($arg.Value))"
            }
            $uri += $argsList -join ','
        }
        #TODO: Add filter, view, and pagesize
    }
    Write-Verbose "URI: $uri"

    if ($OperationMethod -ne "GET") {
        Write-Verbose "Building Payload"
        $warning = if ($GetWarning) { "YES" } else { "NO" }
        $hashtablePayload = @{}
        $hashtablePayload."params" = @{"warning"=$warning;"onerror"=$OnErrorAction;<#"action"=$Action#>}
        $hashtablePayload.$ResourceType = $Payload
        $jsonPayload = ConvertTo-Json $hashtablePayload -Depth ([int]::MaxValue)
        Write-Verbose "JSON Payload:`n$jsonPayload"
    }

    try {
        Write-Verbose "Calling Invoke-RestMethod"
        $restParams = @{
            Uri = $uri
            ContentType = "application/json"
            Method = $OperationMethod
            WebSession = $NSSession.WebSession
            ErrorVariable = "restError"
        }
        
        if ($OperationMethod -ne "GET") {
            $restParams.Add("Body",$jsonPayload)
        }

        $response = Invoke-RestMethod @restParams
        
        if ($response) {
            if ($response.severity -eq "ERROR") {
                throw "Error. See response: `n$($response | fl * | Out-String)"
            } else {
                Write-Verbose "Response:`n$(ConvertTo-Json $response | Out-String)"
            }
        }
    }
    catch [Exception] {
        if ($ResourceType -eq "reboot" -and $restError[0].Message -eq "The underlying connection was closed: The connection was closed unexpectedly.") {
            Write-Verbose "Connection closed due to reboot"
        } else {
            throw $_
        }
    }

    Write-Verbose "$($MyInvocation.MyCommand): Exit"

    if ($OperationMethod -eq "GET") {
        return $response
    }
}

function Set-NSMgmtProtocol {
    <#
    .SYNOPSIS
        Set $Script:NSURLProtocol, this will be used for all subsequent invocation of NITRO APIs
    .DESCRIPTION
        Set $Script:NSURLProtocol
    .PARAMETER Protocol
        Protocol, acceptable values are "http" and "https"
    .EXAMPLE
        Set-Protocol -Protocol https
    .NOTES
        Copyright (c) Citrix Systems, Inc. All rights reserved.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [ValidateSet("http","https")] [string]$Protocol
    )

    Write-Verbose "$($MyInvocation.MyCommand): Enter"

    $Script:NSURLProtocol = $Protocol

    Write-Verbose "$($MyInvocation.MyCommand): Exit"
}

function Connect-NSAppliance {
    <#
    .SYNOPSIS
        Connect to NetScaler Appliance
    .DESCRIPTION
        Connect to NetScaler Appliance. A custom web request session object will be returned
    .PARAMETER NSAddress
        NetScaler Management IP address
    .PARAMETER NSName
        NetScaler DNS name or FQDN
    .PARAMETER NSUserName
        UserName to access the NetScaler appliance
    .PARAMETER NSPassword
        Password to access the NetScaler appliance
    .PARAMETER Timeout
        Timeout in seconds to for the token of the connection to the NetScaler appliance. 900 is the default admin configured value.
    .EXAMPLE
         $Session = Connect-NSAppliance -NSAddress 10.108.151.1
    .EXAMPLE
         $Session = Connect-NSAppliance -NSName mynetscaler.mydomain.com
    .OUTPUTS
        CustomPSObject
    .NOTES
        Copyright (c) Citrix Systems, Inc. All rights reserved.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ParameterSetName='Address')] [string]$NSAddress,
        [Parameter(Mandatory=$true,ParameterSetName='Name')] [string]$NSName,
        [Parameter(Mandatory=$false)] [string]$NSUserName="usuario", 
        [Parameter(Mandatory=$false)] [string]$NSPassword="password",
        [Parameter(Mandatory=$false)] [int]$Timeout=900
    )
    Write-Verbose "$($MyInvocation.MyCommand): Enter"

    if ($PSCmdlet.ParameterSetName -eq 'Address') {
        Write-Verbose "Validating IP Address"
        $IPAddressObj = New-Object -TypeName System.Net.IPAddress -ArgumentList 0
        if (-not [System.Net.IPAddress]::TryParse($NSAddress,[ref]$IPAddressObj)) {
            throw "'$NSAddress' is an invalid IP address"
        }
        $nsEndpoint = $NSAddress
    } elseif ($PSCmdlet.ParameterSetName -eq 'Name') {
        $nsEndpoint = $NSName
    }


    $login = @{"login" = @{"username"=$NSUserName;"password"=$NSPassword;"timeout"=$Timeout}}
    $loginJson = ConvertTo-Json $login
    
    try {
        Write-Verbose "Calling Invoke-RestMethod for login"
        $response = Invoke-RestMethod -Uri "$($Script:NSURLProtocol)://$nsEndpoint/nitro/v1/config/login" -Body $loginJson -Method POST -SessionVariable saveSession -ContentType application/json
                
        if ($response.severity -eq "ERROR") {
            throw "Error. See response: `n$($response | fl * | Out-String)"
        } else {
            Write-Verbose "Response:`n$(ConvertTo-Json $response | Out-String)"
        }
    }
    catch [Exception] {
        throw $_
    }


    $nsSession = New-Object -TypeName PSObject
    $nsSession | Add-Member -NotePropertyName Endpoint -NotePropertyValue $nsEndpoint -TypeName String
    $nsSession | Add-Member -NotePropertyName WebSession  -NotePropertyValue $saveSession -TypeName Microsoft.PowerShell.Commands.WebRequestSession

    Write-Verbose "$($MyInvocation.MyCommand): Exit"

    return $nsSession
}

###########################################################################################################
# Funciones Nuevas para el modulo de Netscaler
###########################################################################################################


#import-module NetScalerConfigurationPart5

function sendMail($body, $subject) {

     #SMTP server name
     $smtpServer = "smtp_server_fqdn"

     #Creating a Mail object
     $msg = new-object Net.Mail.MailMessage

     #Creating SMTP server object
     $smtp = new-object Net.Mail.SmtpClient($smtpServer)
     
     $Receiver = "example@DOMAIN.COM"
     
      
#     $ManagerAddress = $Receiver.mail
   
     #Email structure 
     $msg.From = "no-reply-Netscaler@DOMAIN.COM"
     $msg.ReplyTo = "no-reply-Netscaler@DOMAIN.COM"
     $msg.To.Add($Receiver)
     $msg.subject = $subject
     $msg.IsBodyHTML = $true 
     $msg.body = $body
     
         
     #Sending email  
     $smtp.Send($msg)
     Write-Host "Mail enviado a la dirección $Receiver"
  
}

function Add-NSLBVServer2 {
    <#
    .SYNOPSIS
        Add a new LB virtual server
    .DESCRIPTION
        Add a new LB virtual server
    .PARAMETER NSSession
        An existing custom NetScaler Web Request Session object returned by Connect-NSAppliance
    .PARAMETER Name
        Name of the virtual server
    .PARAMETER IPAddress
        IPv4 or IPv6 address to assign to the virtual server
        Usually a public IP address. User devices send connection requests to this IP address
    .PARAMETER ServiceType
        Protocol used by the service (also called the service type)
    .PARAMETER Port
        Port number for the virtual server
    .PARAMETER PersistenceType
        Type of persistence for the virtual server
    .EXAMPLE
        Add-NSLBVServer -NSSession $Session -Name "myLBVirtualServer" -IPAddress "10.108.151.3" -ServiceType "SSL" -Port 443 -PersistenceType "SOURCEIP"
    .NOTES
        Copyright (c) Citrix Systems, Inc. All rights reserved.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [PSObject]$NSSession,
        [Parameter(Mandatory=$true)] [string]$Name,
        [Parameter(Mandatory=$false)] [string]$IPAddress,
        [Parameter(Mandatory=$false)] [ValidateSet(
        "HTTP","FTP","TCP","UDP","SSL","SSL_BRIDGE","SSL_TCP","DTLS","NNTP","DNS","DHCPRA","ANY","SIP_UDP","DNS_TCP",
        "RTSP","PUSH","SSL_PUSH","RADIUS","RDP","MYSQL","MSSQL","DIAMETER","SSL_DIAMETER","TFTP","ORACLE"
        )] [string]$ServiceType="SSL",
        [Parameter(Mandatory=$false)] [ValidateRange(1,65535)] [int]$Port=443,
        [Parameter(Mandatory=$false)] [ValidateSet(
        "SOURCEIP","COOKIEINSERT","SSLSESSION","RULE","URLPASSIVE","CUSTOMSERVERID","DESTIP","SRCIPDESTIP","CALLID","RTSPSID","DIAMETER","NONE"
        )] [string]$PersistenceType="SOURCEIP"
    )

    Write-Verbose "$($MyInvocation.MyCommand): Enter"

    Write-Verbose "Validating IP Address"
    <#
    
    $IPAddressObj = New-Object -TypeName System.Net.IPAddress -ArgumentList 0
    if (-not [System.Net.IPAddress]::TryParse($IPAddress,[ref]$IPAddressObj)) {
        throw "'$IPAddress' is an invalid IP address"
    }

    #>

    $payload = @{name=$Name;servicetype=$ServiceType;persistencetype=$PersistenceType}
    $response = Invoke-NSNitroRestApi -NSSession $NSSession -OperationMethod POST -ResourceType lbvserver -Payload $payload -Action add 
   
    Write-Verbose "$($MyInvocation.MyCommand): Exit"

}

function Add-CSPolicy {
    <#
    .SYNOPSIS
        Add a new LB virtual server
    .DESCRIPTION
        Add a new LB virtual server
    .PARAMETER NSSession
        An existing custom NetScaler Web Request Session object returned by Connect-NSAppliance
    .PARAMETER Name
        Name of the virtual server
    .PARAMETER IPAddress
        IPv4 or IPv6 address to assign to the virtual server
        Usually a public IP address. User devices send connection requests to this IP address
    .PARAMETER ServiceType
        Protocol used by the service (also called the service type)
    .PARAMETER Port
        Port number for the virtual server
    .PARAMETER PersistenceType
        Type of persistence for the virtual server
    .EXAMPLE
        Add-NSLBVServer -NSSession $Session -Name "myLBVirtualServer" -IPAddress "10.108.151.3" -ServiceType "SSL" -Port 443 -PersistenceType "SOURCEIP"
    .NOTES
        Copyright (c) Citrix Systems, Inc. All rights reserved.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [PSObject]$NSSession,
        [Parameter(Mandatory=$true)] [string]$Name,
        [Parameter(Mandatory=$true)] [string]$RuleExpression
    )

    Write-Verbose "$($MyInvocation.MyCommand): Enter"

    Write-Verbose "Validating IP Address"
    <#
    
    $IPAddressObj = New-Object -TypeName System.Net.IPAddress -ArgumentList 0
    if (-not [System.Net.IPAddress]::TryParse($IPAddress,[ref]$IPAddressObj)) {
        throw "'$IPAddress' is an invalid IP address"
    }

    #>
    
    $payload = @{policyname=$Name;rule="HTTP.REQ.HOSTNAME.eq(`"$PublicNameToPublish`")"}
    $response = Invoke-NSNitroRestApi -NSSession $NSSession -OperationMethod POST -ResourceType cspolicy -Payload $payload -Action add 
   
    Write-Verbose "$($MyInvocation.MyCommand): Exit"

}

function New-NSCSVServerPolicyBinding {
    <#
    .SYNOPSIS
        Bind service to VPN virtual server
    .DESCRIPTION
        Bind service to VPN virtual server
    .PARAMETER NSSession
        An existing custom NetScaler Web Request Session object returned by Connect-NSAppliance
    .PARAMETER VirtualServerName
        Name of the virtual server
    .PARAMETER ServiceName
        Service to bind to the virtual server
    .EXAMPLE
        New-NSLBVServerServiceBinding -NSSession $Session -VirtualServerName "myLBVirtualServer" -ServiceName "Server1_Service"
    .NOTES
        Copyright (c) Citrix Systems, Inc. All rights reserved.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [PSObject]$NSSession,
        [Parameter(Mandatory=$true)] [string]$CSVirtualServerName,
        [Parameter(Mandatory=$true)] [string]$CSPolicyNameToBind,
        [Parameter(Mandatory=$true)] [string]$LBVServerNameToBind,
        [Parameter(Mandatory=$true)] [string]$CSPolicyPriority
         )

    Write-Verbose "$($MyInvocation.MyCommand): Enter"

    $payload = @{name=$CSVirtualServerName;policyname=$CSPolicyNameToBind;targetlbvserver=$LBVServerNameToBind;priority=$CSPolicyPriority}
    $response = Invoke-NSNitroRestApi -NSSession $NSSession -OperationMethod PUT -ResourceType csvserver_cspolicy_binding -Payload $payload -Action add 

    Write-Verbose "$($MyInvocation.MyCommand): Exit"
}

function Get-NSCSVServerPolicyBinding {
    <#
    .SYNOPSIS
        Bind service to VPN virtual server
    .DESCRIPTION
        Bind service to VPN virtual server
    .PARAMETER NSSession
        An existing custom NetScaler Web Request Session object returned by Connect-NSAppliance
    .PARAMETER VirtualServerName
        Name of the virtual server
    .PARAMETER ServiceName
        Service to bind to the virtual server
    .EXAMPLE
        New-NSLBVServerServiceBinding -NSSession $Session -VirtualServerName "myLBVirtualServer" -ServiceName "Server1_Service"
    .NOTES
        Copyright (c) Citrix Systems, Inc. All rights reserved.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)] [PSObject]$NSSession,
        [Parameter(Mandatory=$false)] [string]$CSVirtualServerName,
        [Parameter(Mandatory=$false)] [string]$CSPolicyNameToBind,
        [Parameter(Mandatory=$false)] [string]$LBVServerNameToBind,
        [Parameter(Mandatory=$false)] [string]$CSPolicyPriority
         )

    Write-Verbose "$($MyInvocation.MyCommand): Enter"

    $response = Invoke-NSNitroRestApi -NSSession $myNSSession -OperationMethod GET -ResourceType "csvserver_cspolicy_binding/"$CSVirtualServerName 
    #$response.csvserver_cspolicy_binding.policyname
    Write-host $args
    if ($CSPolicyPriority)
    {   
    ##### ORDENAR VALORES ##############
    $maxpriority = ($response.csvserver_cspolicy_binding.priority) | Measure-Object -Maximum
    $maxpriorityString=$maxpriority.Maximum
    ######################
    return $maxpriorityString 
    }

    if ($CSPolicyNameToBind)
    { $policyMatch = $response.csvserver_cspolicy_binding.policyname -contains $CSPolicyNameToBind
      return $policyMatch
    }

    if ($Args[0] -eq $Null)
    { 
      return $response.csvserver_cspolicy_binding
    }
    Write-Verbose "$($MyInvocation.MyCommand): Exit"
}

function Get-NSServer {
    <#
    .SYNOPSIS
        Add a new server resource
    .DESCRIPTION
        Add a new server resource
    .PARAMETER NSSession
        An existing custom NetScaler Web Request Session object returned by Connect-NSAppliance
    .PARAMETER Name
        Name of the server
    .PARAMETER IPAddress
        IPv4 or IPv6 address of the server
        If this is not provided then the server name is used as its IP address
    .EXAMPLE
        Add-NSServer -NSSession $Session -ServerName "myServer" -ServerIPAddress "10.108.151.3"
    .NOTES
        Copyright (c) Citrix Systems, Inc. All rights reserved.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)] [PSObject]$NSSession,
        [Parameter(Mandatory=$true)] [string]$Name,
        [Parameter(Mandatory=$false)] [string]$IPAddress
    )

    Write-Verbose "$($MyInvocation.MyCommand): Enter"

    $response = Invoke-NSNitroRestApi -NSSession $myNSSession -OperationMethod GET -ResourceType server 
    $servers = $response.server.name

    $servers -contains $Name
   
    Write-Verbose "$($MyInvocation.MyCommand): Exit"
}

function Get-NSService {
    <#
    .SYNOPSIS
        Add a new server resource
    .DESCRIPTION
        Add a new server resource
    .PARAMETER NSSession
        An existing custom NetScaler Web Request Session object returned by Connect-NSAppliance
    .PARAMETER Name
        Name of the server
    .PARAMETER IPAddress
        IPv4 or IPv6 address of the server
        If this is not provided then the server name is used as its IP address
    .EXAMPLE
        Add-NSServer -NSSession $Session -ServerName "myServer" -ServerIPAddress "10.108.151.3"
    .NOTES
        Copyright (c) Citrix Systems, Inc. All rights reserved.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)] [PSObject]$NSSession,
        [Parameter(Mandatory=$true)] [string]$Name        
    )

    Write-Verbose "$($MyInvocation.MyCommand): Enter"

    $response = Invoke-NSNitroRestApi -NSSession $myNSSession -OperationMethod GET -ResourceType service 
    $services = $response.service.name

    $services -contains $Name
   
    Write-Verbose "$($MyInvocation.MyCommand): Exit"
}

function Get-NSLBVServer2 {
    <#
    .SYNOPSIS
        Add a new server resource
    .DESCRIPTION
        Add a new server resource
    .PARAMETER NSSession
        An existing custom NetScaler Web Request Session object returned by Connect-NSAppliance
    .PARAMETER Name
        Name of the server
    .PARAMETER IPAddress
        IPv4 or IPv6 address of the server
        If this is not provided then the server name is used as its IP address
    .EXAMPLE
        Add-NSServer -NSSession $Session -ServerName "myServer" -ServerIPAddress "10.108.151.3"
    .NOTES
        Copyright (c) Citrix Systems, Inc. All rights reserved.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)] [PSObject]$NSSession,
        [Parameter(Mandatory=$true)] [string]$Name        
    )

    Write-Verbose "$($MyInvocation.MyCommand): Enter"

    $response = Invoke-NSNitroRestApi -NSSession $myNSSession -OperationMethod GET -ResourceType lbvserver
    
    $lbvservers = $response.lbvserver.name

    $lbvservers -contains $Name
   
    Write-Verbose "$($MyInvocation.MyCommand): Exit"
}

function Get-NSLBVServerServiceBinding {
    <#
    .SYNOPSIS
        Bind service to VPN virtual server
    .DESCRIPTION
        Bind service to VPN virtual server
    .PARAMETER NSSession
        An existing custom NetScaler Web Request Session object returned by Connect-NSAppliance
    .PARAMETER VirtualServerName
        Name of the virtual server
    .PARAMETER ServiceName
        Service to bind to the virtual server
    .EXAMPLE
        New-NSLBVServerServiceBinding -NSSession $Session -VirtualServerName "myLBVirtualServer" -ServiceName "Server1_Service"
    .NOTES
        Copyright (c) Citrix Systems, Inc. All rights reserved.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [PSObject]$NSSession,
        [Parameter(Mandatory=$true)] [string]$VirtualServerName,
        [Parameter(Mandatory=$true)] [string]$ServiceName
    )

    Write-Verbose "$($MyInvocation.MyCommand): Enter"

    $response = Invoke-NSNitroRestApi -NSSession $NSSession -OperationMethod GET -ResourceType "lbvserver_service_binding/$VirtualServerName"
    $servicebinded = $response.lbvserver_service_binding.servicename
    $servicebinded -contains $ServiceName

    Write-Verbose "$($MyInvocation.MyCommand): Exit"
}

function Get-CSPolicy {
    <#
    .SYNOPSIS
        Add a new LB virtual server
    .DESCRIPTION
        Add a new LB virtual server
    .PARAMETER NSSession
        An existing custom NetScaler Web Request Session object returned by Connect-NSAppliance
    .PARAMETER Name
        Name of the virtual server
    .PARAMETER IPAddress
        IPv4 or IPv6 address to assign to the virtual server
        Usually a public IP address. User devices send connection requests to this IP address
    .PARAMETER ServiceType
        Protocol used by the service (also called the service type)
    .PARAMETER Port
        Port number for the virtual server
    .PARAMETER PersistenceType
        Type of persistence for the virtual server
    .EXAMPLE
        Add-NSLBVServer -NSSession $Session -Name "myLBVirtualServer" -IPAddress "10.108.151.3" -ServiceType "SSL" -Port 443 -PersistenceType "SOURCEIP"
    .NOTES
        Copyright (c) Citrix Systems, Inc. All rights reserved.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [PSObject]$NSSession,
        [Parameter(Mandatory=$true)] [string]$Name,
        [Parameter(Mandatory=$false)] [string]$RuleExpression
    )

    Write-Verbose "$($MyInvocation.MyCommand): Enter"

    Write-Verbose "Validating IP Address"
    <#
    
    $IPAddressObj = New-Object -TypeName System.Net.IPAddress -ArgumentList 0
    if (-not [System.Net.IPAddress]::TryParse($IPAddress,[ref]$IPAddressObj)) {
        throw "'$IPAddress' is an invalid IP address"
    }

    #>
    
    $payload = @{policyname=$Name;rule="HTTP.REQ.HOSTNAME.eq(`"$PublicNameToPublish`")"}
    $response = Invoke-NSNitroRestApi -NSSession $myNSSession -OperationMethod GET -ResourceType cspolicy

    $policy = $response.cspolicy.policyname
    
    $policyrule = $response.cspolicy.rule

    $policy -contains $Name
   
    Write-Verbose "$($MyInvocation.MyCommand): Exit"

}


Set-NSMgmtProtocol -Protocol http

$netscaler1 = "NetscalerIpaddress"
$myNSSession = Connect-NSAppliance -NSAddress $netscaler1 -NSUserName "username" -NSPassword "password"


<# 

Wrapping the NITRO REST API configuration calls (Invoke-NSNitroRestApi example)
The NetScaler NITRO REST API is extremely useful by itself. However, when we wrap it with a general purpose function, 
we can reuse and derive additional functions for specific configuration actions. These actions can then be combined 
into tasks that complete the configuration of different use cases. This wrapper function takes care of the connection and data manipulation. 
Please keep in mind that this wrapper function is just an example and it isn’t meant to take care of absolutely every use case, but can be expanded to accommodate additional API functionality. 
An example call to this function is as follows:


The call above will save the NetScaler configuration on the NetScaler appliance that corresponds to the $myNSSession custom web request session object.

Invoke-NSNitroRestApi -NSSession $myNSSession -OperationMethod POST -ResourceType nsconfig -Action save

#>


$PublicNameToPublish="external.domain.com"
$ServerToPublish="internal.domainlocal.com" # FQDN form internal server name
$ServerToPublishIP="192.168.0.10" # internal server IP Address
$ServiceType ="SSL"



<#
$PublicNameToPublish=$($env:InternetDNS)
$ServerToPublish=$($env:InternalServer)
$ServerToPublishIP=$($env:InternalIP)
$ServiceType =$($env:PublishBy)
#>
$pos = $ServerToPublish.IndexOf(".")
$leftPart = $ServerToPublish.Substring(0, $pos)
$NSserviceName="SV_Webs_" + $leftPart
$ServicePort=443
$NSLBVServer="lb_" + $PublicNameToPublish
$CSPolicyName="cs-pol-" + $PublicNameToPublish + " - " + $ServiceType
$CSServerName="CS-Web-Publishing-"+ $ServiceType

if ( Get-NSServer -Name $ServerToPublish )
{ Write-host "ya existe el server"$ServerToPublish -ForegroundColor yellow } else {
Add-NSServer -NSSession $myNSSession -Name $ServerToPublish -IPAddress $ServerToPublishIP
Write-host "Creando el Server"$ServerToPublish -ForegroundColor green
}


if ( Get-NSService -Name $NSserviceName )
{ Write-host "ya existe el servicio"$NSserviceName -ForegroundColor yellow } else {

Add-NSService -NSSession $myNSSession -Name $NSserviceName -ServerName $ServerToPublish -Type $ServiceType -Port $ServicePort `
                                             -InsertClientIPHeader -ClientIPHeader "X-Forwarded-For"
Write-host "Creando el service"$NSserviceName -ForegroundColor green
}

if ( Get-NSLBVServer2 -Name $NSLBVServer )
{ Write-host "ya existe el Virtual Server"$NSLBVServer -ForegroundColor yellow } else {

Add-NSLBVServer2 -NSSession $myNSSession -Name $NSLBVServer -ServiceType "HTTP" -PersistenceType "SOURCEIP"
Write-host "Creando el Load Balance Virtual Server"$NSLBVServer -ForegroundColor green

}

if ( Get-NSLBVServerServiceBinding -NSSession $myNSSession -VirtualServerName $NSLBVServer -ServiceName $NSserviceName)
{ Write-host "ya existe el Bind del Servicio"$NSserviceName "en el Virtual Server" $NSLBVServer -ForegroundColor yellow } else {

New-NSLBVServerServiceBinding -NSSession $myNSSession -VirtualServerName $NSLBVServer -ServiceName $NSserviceName
Write-host "haciendo el Binding de"$NSLBVServer "con el servicio" $NSserviceName -ForegroundColor green
}

if ( Get-CSPolicy -NSSession $myNSSession -Name $CSPolicyName )
{ Write-host "ya existe la policy"$CSPolicyName -ForegroundColor yellow } else {
Add-CSPolicy -NSSession $myNSSession -Name $CSPolicyName -RuleExpression $PublicNameToPublish
Write-host "creando la policy"$CSPolicyName "para el site" $PublicNameToPublish -ForegroundColor green
}

$a = Get-NSCSVServerPolicyBinding -CSVirtualServerName $CSServerName -CSPolicyPriority $true
[string]$CSPolicyPriorityValue = ([convert]::ToInt32($a, 10) ) + 5

if ( Get-NSCSVServerPolicyBinding -CSVirtualServerName $CSServerName -CSPolicyNameToBind $CSPolicyName)
{ Write-host "ya existe el bind de la policy"$CSPolicyName "para el CS Virtual Server" $CSServerName -ForegroundColor yellow } else {

New-NSCSVServerPolicyBinding -NSSession $myNSSession -CSVirtualServerName $CSServerName -CSPolicyNameToBind $CSPolicyName `
                                        -LBVServerNameToBind $NSLBVServer -CSPolicyPriority $CSPolicyPriorityValue
Write-host "Bind final de CS"$CSServerName "con la policy" $CSPolicyName "con prioridad"  $CSPolicyPriorityValue -ForegroundColor green
}
########################################
# Save Netscaler Config
########################################

Save-NSConfig -NSSession $myNSSession

#########################################
# Exit Netscaler Session
#########################################

Disconnect-NSAppliance -NSSession $myNSSession


            $body="Nuevo Sitio Publicado en Netscaler"
            $body+=" "
            #$body+= "&nbsp;</b></p>"
            #$body+= "&nbsp;$newAdminName</b></p>"
            $body+= "<p style= 'text-indent: 5em;'><b>Internet Public DNS name:&nbsp;&nbsp;$PublicNameToPublish</b></p>"
            $body+= "<p style= 'text-indent: 5em;'><b>Internal Server Name:&nbsp;&nbsp;$ServerToPublish</b></p>"
            $body+= "<p style= 'text-indent: 5em;'><b>Internal IP Server Address:&nbsp;&nbsp;$ServerToPublishIP</b></p>"
            $body+= "<p style= 'text-indent: 5em;'><b>Publish By:&nbsp;&nbsp;$ServiceType</b></p>"
            $body+= "Recuerde que deberá Habilitar el ACL del Firewall para permitir trafico desde el netscaler hacia el server: $leftPart por el port: $ServiceType .</br></br>"
            $body+= "Cualquier duda que tenga, puede contactar a la mesa de ayuda.</br></br>"
            $body+= "------------------------------------------------------------</br></br>" 
            $subject = "Netscaler - New Site Published" 
            try{ 
                sendMail $body $subject
            }
            catch
            {
                $ErrExiste += "Error en el envio de mail al manager" 
            }


