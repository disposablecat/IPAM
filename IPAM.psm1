#Powershell API wrapper for EfficientIP's IPAM solution.
#Helper Function
function Get-PlainText{
<#
.SYNOPSIS
    Get plaintext version of system.security.securestring
.DESCRIPTION
    Get plaintext version of system.security.securestring. Helper function for API authentication header in IPAM
.PARAMETER Securestring
    Input SecureString
.NOTES
    Version:        1.0
    Author:         disposablecat
    Purpose/Change: Initial script development
.EXAMPLE
    Get-PlainText -SecureString $Credentials
#>
    [CmdletBinding()]
    [OutputType([string])]
    
    #Define parameters
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [System.Security.SecureString]$SecureString

    )
    Process
    {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString);
 
		try
		{
			return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr);
		}
		finally
		{
			[Runtime.InteropServices.Marshal]::FreeBSTR($bstr);
		}
    }
}

#Helper Function
function Get-Base64{
<#
.SYNOPSIS
    Convert to base64. Helper function for API authentication header in IPAM
.DESCRIPTION
    Convert to base64. Helper function for API authentication header in IPAM
.PARAMETER String
    Input String to convert to base64
.NOTES
    Version:        1.0
    Author:         Christopher Grant
    Creation Date:  8/24/17
    Purpose/Change: Initial script development
.EXAMPLE
    Get-Base64 -String $String
#>
    [CmdletBinding()]
    [OutputType([string])]
    
    #Define parameters
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$String

    )
    Process
    {
        #Convert UserName to Base64 and set Global
        $Bytes = [System.Text.Encoding]::ASCII.GetBytes($String)
        $Result = [Convert]::ToBase64String($Bytes)
        return $Result
    }
}

#Helper Function
function Set-CryptoBypass{
<#
.SYNOPSIS
    Accept all SSL crypto to bypass errors
.DESCRIPTION
    Accept all SSL crypto to bypass errors
.NOTES
    Version:        1.0
    Author:         Christopher Grant
    Creation Date:  12/6/17
    Purpose/Change: Initial script development
.EXAMPLE
    Get-CryptoBypass
#>
    [CmdletBinding()]
    [OutputType([string])]
    
    #Define parameters
    Param
    (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string]$String

    )
    Process
    {
            if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type)
            {
                Add-Type @"
                using System.Net;
                using System.Security.Cryptography.X509Certificates;
                public class TrustAllCertsPolicy : ICertificatePolicy {
                    public bool CheckValidationResult(
                        ServicePoint srvPoint, X509Certificate certificate,
                        WebRequest request, int certificateProblem) {
                        return true;
                    }
                }
"@
}
        $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    }
}


function Set-EipCredentials{
<#
.SYNOPSIS
    Set IPAM Credentials and URL
.DESCRIPTION
    Set IPAM Credentials and URL 
.PARAMETER URL
    Set IPAN URL
.PARAMETER UserName
    Set IPAM UserName
.PARAMETER Password
    Set IPAM Password
.NOTES
    Version:        1.0
    Author:         Christopher Grant
    Creation Date:  8/24/17
    Purpose/Change: Initial script development
.EXAMPLE
    Set-EipCredentials -URL ipam.net.ucf.edu -UserName joe -Password password123
.EXAMPLE
    Another example of how to use this cmdlet
#>
    [CmdletBinding()]
    [OutputType([int])]
    
    #Define parameters
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$URL,

        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$false)]
        [PSCredential]$Credential
    )


    Process
    {       
        #Store IPAM URL in plaintext
        $URL | Out-File "$pwd\IPAMURL.txt" 
        
        $Credential.GetNetworkCredential().UserName | Out-File "$pwd\IPAMUsername.txt"
        
        $Credential.GetNetworkCredential().SecurePassword | ConvertFrom-SecureString| Out-File "$pwd\IPAMPassword.txt"
    }

}


function Get-EipAllBlockSubnetFromSpace{
<#
.SYNOPSIS
    Get Ipam
.DESCRIPTION
    Set IPAM Credentials and URL 
.PARAMETER Space
    Specify IPAM space to retrieve all blocks and subnets from
.NOTES
    Version:        1.0
    Author:         Christopher Grant
    Creation Date:  8/24/17
    Purpose/Change: Initial script development
.EXAMPLE
    Get-IpamAllBlockSubnetFromSpace -Space "Space Name"
#>
    [CmdletBinding()]
    [OutputType([System.Array])]
    
    #Define parameters
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$Space

    )
    Begin
    {
        #Add System.Web assembly for UrlEncode
        Add-Type -AssemblyName System.Web
        #Read in URL from file
        $IPAMURL = Get-Content "$pwd\IPAMURL.txt"

        #Read in Username from file and encode
        $IPAMUserNameTemp = Get-Content "$pwd\IPAMUsername.txt"
        $IPAMUserName = Get-Base64 -String $IPAMUserNameTemp

        #Read in Password from file, convert, and encode
        $IPAMPasswordTemp = Get-Content "$pwd\IPAMPassword.txt" | ConvertTo-SecureString
        $IPAMPasswordTempPlain = Get-PlainText -SecureString $IPAMPasswordTemp
        $IPAMPassword = Get-Base64 -String $IPAMPasswordTempPlain
        Set-CryptoBypass
    }
    Process
    {
        #Set URL To Encode
        $UrlToEncode = "site_name='$Space'"
        #Encode end of URL
        $Encoding = [System.Web.HttpUtility]::UrlEncode($UrlToEncode)
        #Set full URL after encoding
        $ServiceUrl = "$IPAMURL/rest/ip_block_subnet_list/WHERE/$Encoding"
        #Set header object type
        $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        #Set Username and Password Headers
        $Headers.Add("X-IPM-Username","$IPAMUserName")
        $Headers.Add("X-IPM-Password","$IPAMPassword")
        #Invoke Rest and capture
        $Response = Invoke-RestMethod "$ServiceUrl" -Headers $Headers -Method Get
        #Return response
        return $Response
    }
}

function Get-EipSubnet{
<#
.SYNOPSIS
    Get specific subnet information
.DESCRIPTION
    Get all information about a specific subnet
.PARAMETER SubnetName
    Specify subnet that you would like to retrieve information about
.NOTES
    Version:        1.0
    Author:         Christopher Grant
    Creation Date:  8/24/17
    Purpose/Change: Initial script development
.EXAMPLE
    Get-IpamSubnet -SubnetName "Subnet Name"
#>
    [CmdletBinding()]
    [OutputType([System.Array])]
    
    #Define parameters
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$SubnetName

    )
    Begin
    {
        #Add System.Web assembly for UrlEncode
        Add-Type -AssemblyName System.Web

        #Read in URL from file
        $IPAMURL = Get-Content "$pwd\IPAMURL.txt"

        #Read in Username from file and encode
        $IPAMUserNameTemp = Get-Content "$pwd\IPAMUsername.txt"
        $IPAMUserName = Get-Base64 -String $IPAMUserNameTemp

        #Read in Password from file, convert, and encode
        $IPAMPasswordTemp = Get-Content "$pwd\IPAMPassword.txt" | ConvertTo-SecureString
        $IPAMPasswordTempPlain = Get-PlainText -SecureString $IPAMPasswordTemp
        $IPAMPassword = Get-Base64 -String $IPAMPasswordTempPlain
        Set-CryptoBypass
    }
    Process
    {
        #Set URL To Encode
        $UrlToEncode = "subnet_name='$SubnetName'"
        #Encode end of URL
        $Encoding = [System.Web.HttpUtility]::UrlEncode($UrlToEncode)
        #Set full URL after encoding
        $ServiceUrl = "$IPAMURL/rest/ip_block_subnet_list/WHERE/$Encoding"
        #Set header object type
        $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        #Set Username and Password Headers
        $Headers.Add("X-IPM-Username","$IPAMUserName")
        $Headers.Add("X-IPM-Password","$IPAMPassword")
        #Invoke Rest and capture
        $Response = Invoke-RestMethod "$ServiceUrl" -Headers $Headers -Method Get
        #Return response
        return $Response
    }
}

function Get-EipGroups{
<#
.SYNOPSIS
    Retrieve attributes of all Ipam groups or a specific group
.DESCRIPTION
    Retrieve attributes of all Ipam groups or a specific group
.PARAMETER GroupName
    Specify Group that you would like to retrieve information about. If left blank all groups will be retrieved. 
.NOTES
    Version:        1.0
    Author:         Christopher Grant
    Creation Date:  8/24/17
    Purpose/Change: Initial script development
.EXAMPLE
    Get-IpamGroups -GroupName "Group Name"
#>
    [CmdletBinding()]
    [OutputType([System.Array])]
    
    #Define parameters
    Param
    (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string]$GroupName

    )
    Begin
    {
        #Add System.Web assembly for UrlEncode
        Add-Type -AssemblyName System.Web

        #Read in URL from file
        $IPAMURL = Get-Content "$pwd\IPAMURL.txt"

        #Read in Username from file and encode
        $IPAMUserNameTemp = Get-Content "$pwd\IPAMUsername.txt"
        $IPAMUserName = Get-Base64 -String $IPAMUserNameTemp

        #Read in Password from file, convert, and encode
        $IPAMPasswordTemp = Get-Content "$pwd\IPAMPassword.txt" | ConvertTo-SecureString
        $IPAMPasswordTempPlain = Get-PlainText -SecureString $IPAMPasswordTemp
        $IPAMPassword = Get-Base64 -String $IPAMPasswordTempPlain
        Set-CryptoBypass
    }
    Process
    {
        #if GroupName was set search for specific group
        if(-not ([string]::IsNullOrEmpty($GroupName)))
        {
            #Set URL to encode
            $UrlToEncode = "grp_name='$GroupName'"
            #Encode end of URL
            $Encoding = [System.Web.HttpUtility]::UrlEncode($UrlToEncode)
            #Set full URL after encoding
            $ServiceUrl = "$IPAMURL/rest/group_admin_list/WHERE/$Encoding"
        }
        #If GroupName was not set search all
        else
        {
            $ServiceUrl = "$IPAMURL/rest/group_admin_list/"
        }
        
        #Set header object type
        $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        #Set Username and Password Headers
        $Headers.Add("X-IPM-Username","$IPAMUserName")
        $Headers.Add("X-IPM-Password","$IPAMPassword")
        #Invoke Rest and capture
        $Response = Invoke-RestMethod "$ServiceUrl" -Headers $Headers -Method Get
        #Return response
        return $Response
    }
}

function Get-EipUserInGroup{
<#
.SYNOPSIS
    Retrieve all users in a specific group
.DESCRIPTION
    Retrieve all users in a specific group
.PARAMETER GroupName
    Specify Group that you would like to retrieve all users from. 
.NOTES
    Version:        1.0
    Author:         Christopher Grant
    Creation Date:  8/24/17
    Purpose/Change: Initial script development
.EXAMPLE
    Get-IpamUsersInGroup -GroupName "Group Name"
#>
    [CmdletBinding()]
    [OutputType([System.Array])]
    
    #Define parameters
    Param
    (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string]$GroupName

    )
    Begin
    {
        #Add System.Web assembly for UrlEncode
        Add-Type -AssemblyName System.Web

        #Read in URL from file
        $IPAMURL = Get-Content "$pwd\IPAMURL.txt"

        #Read in Username from file and encode
        $IPAMUserNameTemp = Get-Content "$pwd\IPAMUsername.txt"
        $IPAMUserName = Get-Base64 -String $IPAMUserNameTemp

        #Read in Password from file, convert, and encode
        $IPAMPasswordTemp = Get-Content "$pwd\IPAMPassword.txt" | ConvertTo-SecureString
        $IPAMPasswordTempPlain = Get-PlainText -SecureString $IPAMPasswordTemp
        $IPAMPassword = Get-Base64 -String $IPAMPasswordTempPlain
        Set-CryptoBypass
    }
    Process
    {
        #if GroupName was set search for specific group
        if(-not ([string]::IsNullOrEmpty($GroupName)))
        {
            #Set URL to encode
            $UrlToEncode = "grp_name='$GroupName'"
            #Encode end of URL
            $Encoding = [System.Web.HttpUtility]::UrlEncode($UrlToEncode)
            #Set full URL after encoding
            $ServiceUrl = "$IPAMURL/rest/group_admin_user_list/WHERE/$Encoding"
        }
        #If GroupName was not set search all
        else
        {
            $ServiceUrl = "$IPAMURL/rest/group_admin_user_list/"
        }
        
        #Set header object type
        $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        #Set Username and Password Headers
        $Headers.Add("X-IPM-Username","$IPAMUserName")
        $Headers.Add("X-IPM-Password","$IPAMPassword")
        #Invoke Rest and capture
        $Response = Invoke-RestMethod "$ServiceUrl" -Headers $Headers -Method Get
        #Return response
        return $Response
    }
}

function Get-EipCurrentGroups{
<#
.SYNOPSIS
    Retrieve all the groups a user is a part of
.DESCRIPTION
    Retrieve all the groups a user is a part of
.PARAMETER UserName
    Specify user that you would like to retrieve all the groups for. 
.NOTES
    Version:        1.0
    Author:         Christopher Grant
    Creation Date:  8/24/17
    Purpose/Change: Initial script development
.EXAMPLE
    Get-IpamCurrentGroups -UserName "joe"
#>
    [CmdletBinding()]
    [OutputType([System.Array])]
    
    #Define parameters
    Param
    (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string]$UserName

    )
    Begin
    {
        #Add System.Web assembly for UrlEncode
        Add-Type -AssemblyName System.Web

        #Read in URL from file
        $IPAMURL = Get-Content "$pwd\IPAMURL.txt"

        #Read in Username from file and encode
        $IPAMUserNameTemp = Get-Content "$pwd\IPAMUsername.txt"
        $IPAMUserName = Get-Base64 -String $IPAMUserNameTemp

        #Read in Password from file, convert, and encode
        $IPAMPasswordTemp = Get-Content "$pwd\IPAMPassword.txt" | ConvertTo-SecureString
        $IPAMPasswordTempPlain = Get-PlainText -SecureString $IPAMPasswordTemp
        $IPAMPassword = Get-Base64 -String $IPAMPasswordTempPlain
        Set-CryptoBypass
    }
    Process
    {
        #if GroupName was set search for specific group
        if(-not ([string]::IsNullOrEmpty($UserName)))
        {
            #Set URL to encode
            $UrlToEncode = "login='$UserName'"
            #Encode end of URL
            $Encoding = [System.Web.HttpUtility]::UrlEncode($UrlToEncode)
            #Set full URL after encoding
            $ServiceUrl = "$IPAMURL/rest/group_list/WHERE/$Encoding"
        }
        #If GroupName was not set search all
        else
        {
            $ServiceUrl = "$IPAMURL/rest/group_list/"
        }
        
        #Set header object type
        $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        #Set Username and Password Headers
        $Headers.Add("X-IPM-Username","$IPAMUserName")
        $Headers.Add("X-IPM-Password","$IPAMPassword")
        #Invoke Rest and capture
        $Response = Invoke-RestMethod "$ServiceUrl" -Headers $Headers -Method Get
        #Return response
        return $Response
    }
}

function Get-EipDHCPStatic{
<#
.SYNOPSIS
    Get a list of DHCP statics
.DESCRIPTION
    Get a list of DHCP statics
.PARAMETER Scope
    Specify scope that you would like to retrieve statics from
.NOTES
    Version:        1.0
    Author:         Christopher Grant
    Creation Date:  2/22/18
    Purpose/Change: Initial script development
.EXAMPLE
    Get-EipDHCPStatic -Scope "Scope Name"
#>
    [CmdletBinding()]
    [OutputType([System.Array])]
    
    #Define parameters
    Param
    (
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string]$Scope,

        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string]$IP

    )
    Begin
    {
        #Add System.Web assembly for UrlEncode
        Add-Type -AssemblyName System.Web

        #Read in URL from file
        $IPAMURL = Get-Content "$pwd\IPAMURL.txt"

        #Read in Username from file and encode
        $IPAMUserNameTemp = Get-Content "$pwd\IPAMUsername.txt"
        $IPAMUserName = Get-Base64 -String $IPAMUserNameTemp

        #Read in Password from file, convert, and encode
        $IPAMPasswordTemp = Get-Content "$pwd\IPAMPassword.txt" | ConvertTo-SecureString
        $IPAMPasswordTempPlain = Get-PlainText -SecureString $IPAMPasswordTemp
        $IPAMPassword = Get-Base64 -String $IPAMPasswordTempPlain
        Set-CryptoBypass
    }
    Process
    {
        #if Scope name was set search for specific scope
        if(-not ([string]::IsNullOrEmpty($Scope)))
        {
            #Set URL to encode
            $UrlToEncode = "dhcpscope_name='$Scope'"
            #Encode end of URL
            $Encoding = [System.Web.HttpUtility]::UrlEncode($UrlToEncode)
            #Set full URL after encoding
            $ServiceUrl = "$IPAMURL/rest/dhcp_static_list/WHERE/$Encoding"
        }
        elseif (-not ([string]::IsNullOrEmpty($IP)))
        {
            #Set URL to encode
            $UrlToEncode = "dhcphost_addr='$IP'"
            #Encode end of URL
            $Encoding = [System.Web.HttpUtility]::UrlEncode($UrlToEncode)
            #Set full URL after encoding
            $ServiceUrl = "$IPAMURL/rest/dhcp_static_list/WHERE/$Encoding"
        }
        #If GroupName was not set search all
        else
        {
            $ServiceUrl = "$IPAMURL/rest/dhcp_static_list/"
        }
        #Set header object type
        $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        #Set Username and Password Headers
        $Headers.Add("X-IPM-Username","$IPAMUserName")
        $Headers.Add("X-IPM-Password","$IPAMPassword")
        #Invoke Rest and capture
        $Response = Invoke-RestMethod "$ServiceUrl" -Headers $Headers -Method Get
        #Return response
        return $Response
    }
}

function Set-EipDHCPStatic {
    <#
.SYNOPSIS
    Set a DHCP static
.DESCRIPTION
    Set a DHCP static
.PARAMETER ID
    The database identifier (ID) of the DHCP static
.PARAMETER Name
    The name of the DHCP static
.PARAMETER ClassParams
    The class parameters to apply to the static
    
.NOTES
    Version:        1.0
    Author:         Christopher Grant
    Creation Date:  2/22/18
    Purpose/Change: Initial script development
.EXAMPLE
    Set-EipDHCPStatic -Scope "Scope Name"
#>
    [CmdletBinding()]
    [OutputType([System.Array])]
    
    #Define parameters
    Param
    (
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$Scope

    )
    Begin {
        #Add System.Web assembly for UrlEncode
        Add-Type -AssemblyName System.Web

        #Read in URL from file
        $IPAMURL = Get-Content "$pwd\IPAMURL.txt"

        #Read in Username from file and encode
        $IPAMUserNameTemp = Get-Content "$pwd\IPAMUsername.txt"
        $IPAMUserName = Get-Base64 -String $IPAMUserNameTemp

        #Read in Password from file, convert, and encode
        $IPAMPasswordTemp = Get-Content "$pwd\IPAMPassword.txt" | ConvertTo-SecureString
        $IPAMPasswordTempPlain = Get-PlainText -SecureString $IPAMPasswordTemp
        $IPAMPassword = Get-Base64 -String $IPAMPasswordTempPlain
        Set-CryptoBypass
    }
    Process {
        #if Scope name was set search for specific scope
        if (-not ([string]::IsNullOrEmpty($Scope))) {
            #Set URL to encode
            $UrlToEncode = "dhcpscope_name='$Scope'"
            #Encode end of URL
            $Encoding = [System.Web.HttpUtility]::UrlEncode($UrlToEncode)
            #Set full URL after encoding
            $ServiceUrl = "$IPAMURL/rest/dhcp_static_list/WHERE/$Encoding"
        }
        #If GroupName was not set search all
        else {
            $ServiceUrl = "$IPAMURL/rest/dhcp_static_list/"
        }

        #Set header object type
        $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        #Set Username and Password Headers
        $Headers.Add("X-IPM-Username", "$IPAMUserName")
        $Headers.Add("X-IPM-Password", "$IPAMPassword")
        #Invoke Rest and capture
        $Response = Invoke-RestMethod "$ServiceUrl" -Headers $Headers -Method Get
        #Return response
        return $Response
    }
}

function Get-EipDHCPScopeList {
    <#
.SYNOPSIS
    Get list of DHCP scopes
.DESCRIPTION
    Get list of DHCP scopes
    
.NOTES
    Version:        1.0
    Author:         Christopher Grant
    Creation Date:  9/4/18
    Purpose/Change: Initial script development
.EXAMPLE
    Get-EipDHCPScopeList
#>
    [CmdletBinding()]
    [OutputType([System.Array])]
    
    #Define parameters
    Param
    (
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$Scope
    )
    Begin {
        #Add System.Web assembly for UrlEncode
        Add-Type -AssemblyName System.Web

        #Read in URL from file
        $IPAMURL = Get-Content "$pwd\IPAMURL.txt"

        #Read in Username from file and encode
        $IPAMUserNameTemp = Get-Content "$pwd\IPAMUsername.txt"
        $IPAMUserName = Get-Base64 -String $IPAMUserNameTemp

        #Read in Password from file, convert, and encode
        $IPAMPasswordTemp = Get-Content "$pwd\IPAMPassword.txt" | ConvertTo-SecureString
        $IPAMPasswordTempPlain = Get-PlainText -SecureString $IPAMPasswordTemp
        $IPAMPassword = Get-Base64 -String $IPAMPasswordTempPlain
        Set-CryptoBypass
    }
    Process {
        #if Scope name was set search for specific scope
        if (-not ([string]::IsNullOrEmpty($Scope))) {
            #Set URL to encode
            #$UrlToEncode = "dhcpscope_name='$Scope'"
            $UrlToEncode = "dhcpscope_net_addr='$Scope'"
            #Encode end of URL
            $Encoding = [System.Web.HttpUtility]::UrlEncode($UrlToEncode)
            #Set full URL after encoding
            $ServiceUrl = "$IPAMURL/rest/dhcp_scope_list/WHERE/$Encoding"
        }
        #If GroupName was not set search all
        else {
            $ServiceUrl = "$IPAMURL/rest/dhcp_scope_list/"
        }

        #Set header object type
        $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        #Set Username and Password Headers
        $Headers.Add("X-IPM-Username", "$IPAMUserName")
        $Headers.Add("X-IPM-Password", "$IPAMPassword")
        #Invoke Rest and capture
        $Response = Invoke-RestMethod "$ServiceUrl" -Headers $Headers -Method Get
        #Return response
        return $Response
    }
}

function Set-EipDHCPScopeDescript {
    <#
.SYNOPSIS
    Set DHCP scope
.DESCRIPTION
    Set DHCP scopes within IPAM
    
.NOTES
    Version:        1.0
    Author:         Christopher Grant
    Creation Date:  9/4/18
    Purpose/Change: Initial script development
.EXAMPLE
    Set-EipDHCPScope
#>
    [CmdletBinding()]
    [OutputType([System.Array])]
    
    #Define parameters
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$DhcpScopeId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$DhcpScopeDescript
    )
    Begin {
        #Add System.Web assembly for UrlEncode
        Add-Type -AssemblyName System.Web

        #Read in URL from file
        $IPAMURL = Get-Content "$pwd\IPAMURL.txt"

        #Read in Username from file and encode
        $IPAMUserNameTemp = Get-Content "$pwd\IPAMUsername.txt"
        $IPAMUserName = Get-Base64 -String $IPAMUserNameTemp

        #Read in Password from file, convert, and encode
        $IPAMPasswordTemp = Get-Content "$pwd\IPAMPassword.txt" | ConvertTo-SecureString
        $IPAMPasswordTempPlain = Get-PlainText -SecureString $IPAMPasswordTemp
        $IPAMPassword = Get-Base64 -String $IPAMPasswordTempPlain
        Set-CryptoBypass
    }
    Process {
        #if Scope ID was provided, edit scope
        if (-not ([string]::IsNullOrEmpty($DhcpScopeId))) {
            #Set URL to encode
            #Encode individual input parameters
            $EncodeDhcpScopeId = [System.Web.HttpUtility]::UrlEncode($DhcpScopeId)
            $EncodeDhcpScopeDescript = [System.Web.HttpUtility]::UrlEncode($DhcpScopeDescript)
            #Define sub URL
            $SubUrl = "dhcpscope_id=$EncodeDhcpScopeId&dhcpscope_class_parameters=description=$EncodeDhcpScopeDescript"

            #Combine URL
            $ServiceUrl = "$IPAMURL/rest/dhcp_scope_add?$SubUrl"
            Write-Verbose "ServiceURL: $ServiceUrl"
        }
        #If GroupName was not set search all
        else {
            $ServiceUrl = "$IPAMURL/rest/dhcp_scope_add/"
        }

        #Set header object type
        $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        #Set Username and Password Headers
        $Headers.Add("X-IPM-Username", "$IPAMUserName")
        $Headers.Add("X-IPM-Password", "$IPAMPassword")
        #Invoke Rest and capture
        $Response = Invoke-RestMethod "$ServiceUrl" -Headers $Headers -Method Put
        #Return response
        return $Response
    }
}