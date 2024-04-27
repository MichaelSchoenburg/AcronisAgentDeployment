<#
.SYNOPSIS
    Acronis Agent Deployment

.DESCRIPTION
    This PowerShell script is intended to be used in a RMM solution (e. g. Solarwinds N-able RMM or Riversuit Riverbird). The installation files are supposed to be hosted on a secure FTP server.

.INPUTS
    No parameters. Variables are supposed to be set by the rmm solution this script is used in.

.OUTPUTS
    None

.LINK
    https://github.com/MichaelSchoenburg/AcronisAgentDeployment

.LINK
    https://developer.acronis.com/doc/account-management/v2/reference/index.html#docs/summary/summary

.NOTES
    Author: Michael Schönburg
    Version: v1.0
    
    This projects code loosely follows the PowerShell Practice and Style guide, as well as Microsofts PowerShell scripting performance considerations.
    Style guide: https://poshcode.gitbook.io/powershell-practice-and-style/
    Performance Considerations: https://docs.microsoft.com/en-us/powershell/scripting/dev-cross-plat/performance/script-authoring-considerations?view=powershell-7.1
#>

#region FUNCTIONS
<# 
    Declare Functions
#>

function Write-ConsoleLog {
    <#
        .SYNOPSIS
        Logs an event to the console.
        
        .DESCRIPTION
        Writes text to the console with the current date (US format) in front of it.
        
        .PARAMETER Text
        Event/text to be outputted to the console.
        
        .EXAMPLE
        Write-ConsoleLog -Text 'Subscript XYZ called.'
        
        Long form

        .EXAMPLE
        Log 'Subscript XYZ called.
        
        Short form
    #>

    [alias('Log')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
        Position = 0)]
        [string]
        $Text
    )

    # Save current VerbosePreference
    $VerbosePreferenceBefore = $VerbosePreference

    # Enable verbose output
    $VerbosePreference = 'Continue'

    # Write verbose output
    Write-Output "$( Get-Date -Format 'MM/dd/yyyy HH:mm:ss' ) - $( $Text )"

    # Restore current VerbosePreference
    $VerbosePreference = $VerbosePreferenceBefore
}

function Get-Token {
    <#
        .SYNOPSIS
        Returns an API token.
        
        .DESCRIPTION
        Authorize this API client (PowerShell) against the Acronis Account Management API receiving a token. The token is then used to authenticate further API calls.
        
        .PARAMETER Url
        URL for your Acronis portal.
        
        .PARAMETER ApiClientId
        Client ID for the Acronis Account Management API. This can be generated the Acronis management portal.

        .PARAMETER ApiClientSecret
        Client secret for the Acronis Account Management API. This too can be generated in the Acronis management portal.

        .EXAMPLE
        Get-Token -Url 'https://portal.ajani.info' -ApiClientId '02baa9be-f1a2-4524-a8cb-0cd75c9acb61' -ApiClientSecret 'mzrop4shdxil3ud4lvvdcn5l4acqtafufi4juudqabfhxga756pm'

        .OUTPUTS
        Outputs an array (System.Object) with two variables. First the access token. Secondly the scope.

        .NOTES
        If you want to use this script for all your clients, you can generate an API client from you partner account which has access to all you clients tenants. 
        Check the related link for a guid from the manufacturer on how the Acronis Account Management API works and where you can create your API Client ID and secret.

        .LINK
        https://www.acronis.com/en-us/blog/posts/how-to-automate-acronis-agent-installations/
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Url,

        [Parameter(Mandatory)]
        [string]
        [ValidatePattern('^[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+$')]
        $ApiClientId,

        [Parameter(Mandatory)]
        [string]
        [ValidateLength(52,52)]
        $ApiClientSecret
    )

    # Manually construct Basic Authentication Header
    $pair = "${ApiClientId}:${ApiClientSecret}"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $basicAuthValue = "Basic $base64"
    $headers = @{ "Authorization" = $basicAuthValue }

    # Use param to tell type of credentials we request
    $postParams = @{ grant_type = "client_credentials" }

    # Add the request content type to the headers
    $headers.Add("Content-Type", "application/x-www-form-urlencoded")
    $headers.Add("User-Agent", "ACP 3.0/Acronis Cyber Platform PowerShell Examples")
    $token = Invoke-RestMethod -Method Post -Uri "${Url}api/2/idp/token" -Headers $headers -Body $postParams

    # Return access token
    return $token
}

#endregion FUNCTIONS
#region INITIALIZATION
<# 
    Libraries, Modules, ...
#>

# Nothing to initialize this time...

#endregion INITIALIZATION
#region DECLARATIONS
<#
    Declare local variables and global variables
#>

# The following variables should be set through your rmm solution. 
# Here some examples of possible declarations with explanations for each variable.
# Tip: PowerShell variables are not case sensitive.

<# 

$CustomerUserName = 'User'
$CustomerTenantName = "Customer"
$FtpServerFqdn = 'contoso.org' # FQDN or IP address of your FTP server
$FtpUsername = 'user' # Username of your FTP user
$FtpPassword = 'lkj fa8efjalALKJ38uu!"'ÄÖ' # Password for your FTP user
$FtpAgentDir = '\home\BackupAgentInstallFiles\' # Directory in which you've stored the agent installation files
$Dest = 'C:\Installer\Acronis' # Destination where the agent installer should be downloaded/saved to (used to start installation)
$AgentType can be either win, sql, hyperv or ad. If left empty it will auto detect one of the before mentioned.
$Lang = 'de' # Which language should the agent UI use?
$Url = 'https://portal.ajani.info/' # The full URL for your Acronis tenant (plugging Ajani right here)
$ApiClientId = '02baa9be-f1a2-4524-a8cb-0cd75c9acb61' # API client ID
$ApiClientSecret = 'mzrop4shdxil3ud4lvvdcn5l4acqtafufi4juudqabfhxga756pm' # API client secret

#>

try {
    # The following variables can be adjusted if you have different file names. Names are used to identify the files on the FTP server, as well as to save the downloaded file locally.
    $AgentWindows = 'AcronisCyberProtect_AgentForWindows_web.exe' # Full name of the agent installer for windows clients and server
    $AgentMsSql = 'AcronisCyberProtect_AgentForSQL_web.exe' # Full name of the agent installer for Microsoft SQL server
    $AgentHyperV = 'AcronisCyberProtect_AgentForHyperV_web.exe' # Full name of the agent installer for Microsoft Hyper-V
    $AgentAd = 'AcronisCyberProtect_AgentForAD_web.exe' # Full name of the agent installer for Microsoft Active Directory

    # Making sure there is a tailing slash in the path
    if ( -not ( $Dest.EndsWith('\') ) ){ $Dest = $Dest + '\' }
    if ( $FtpAgentDir.Contains('\') ) { $FtpAgentDir = $FtpAgentDir.Replace('\','/') }
    if ( -not ( $FtpAgentDir.EndsWith('/') ) ){ $FtpAgentDir = $FtpAgentDir + '/' }

    # Default language = German
    if (-not $Lang) {
        $Lang = 'de'
    }

    # Agent types
    # This doesn't account for a case where multiple of the three roles are installed since I found it to be unlikely
    switch ($AgentType) {
        win { $AgentName = $AgentWindows }
        sql { $AgentName = $AgentMsSql }
        hyperv { $AgentName = $AgentHyperV }
        ad { $AgentName = $AgentAd }
        Default { $DetectAgentType = $true }
    }

    if ($DetectAgentType) {
        try {
            if ( (Get-WindowsFeature AD-Domain-Services).Installed ) { Log 'Detected Active Directory.'; $AgentName = $AgentAd }
            elseif ( (Get-WindowsFeature Hyper-V).Installed ) { Log 'Detected Hyper-V.'; $AgentName = $AgentHyperV }
        } catch {
            
        }

        if (-not ($AgentName)) {
            if ( Test-Path 'HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL' ) { Log 'Detected Microsoft SQL Server.'; $AgentName = $AgentMsSql }
            else { Log 'Detected normal Windows.'; $AgentName = $AgentWindows } # If none of the three roles is active, the normal Windows agent will be installed.
        }
    }

    # The following variables can be adjusted if you want a different path/naming
    $LogDir = $Dest + 'Log\'
    $InstallFile = $Dest + $AgentName
    $Source = $FtpAgentDir + $AgentName

    #endregion DECLARATIONS
    #region EXECUTION
    <# 
        Script entry point
    #>

    # Check if the agent is already installed. If it is, skip the entire script. If not, proceed with installation.
    Log 'Checking if Acronis Cyber Protect Agent is installed already...'

    if ((Get-WmiObject -Class Win32_Product -Filter "Name='Cyber Protect'")) {
        Log 'Acronis Cyber Protect Agent is installed already. Skipping.'
    } else {
        Log 'Acronis Cyber Protect Agent is not installed. Proceeding...'

        <# 
            Get installation token from API
        #>

        # Issue token to access API
        $ApiToken = Get-Token -Url $Url -ApiClientId $ApiClientId -ApiClientSecret $ApiClientSecret
        $ApiAccessToken = $ApiToken.access_token

        # Manually construct Bearer
        $bearerAuthValue = "Bearer $ApiAccessToken"
        $headers = @{ "Authorization" = $bearerAuthValue }

        # The request contains body with JSON
        $headers.Add("Content-Type", "application/json")
        $headers.Add("User-Agent", "ACP 3.0/Acronis Cyber Platform PowerShell Examples")

        # Get own tenant ID
        $apiClientInfo = Invoke-RestMethod -Uri "$($Url)api/2/clients/$($ApiClientId)" -Headers $headers
        $tenantId = $apiClientInfo.tenant_id

        # Get customer tenant ID
        $pagingParams = @{tenant = $tenantId; text = $customerTenantName}
        $searchResult = Invoke-RestMethod -Uri "$($Url)api/2/search" -Headers $headers -Body $pagingParams

        if ($searchResult.items.Count -eq 0) {
            Log "No acronis tenant of the kind 'customer' with the name '$($customerTenantName)' was found. Aborting script!"
            Exit 1
        }

        $customerTenant = $searchResult.items.Where{($_.obj_type -eq 'tenant') -and ($_.kind -eq 'customer')}
        $customerTenantId = $customerTenant.id

        Log "Found tenant '$($customerTenant.name)' at path '$($customerTenant.path)' with ID '$($customerTenantId)'."

        # Get customer user ID
        if ($CustomerUserName) {
            # Search for a user with a specific name inside the customers tenant
            $pagingParams = @{tenant = $customerTenantId; text = $CustomerUserName}
            $searchResult = Invoke-RestMethod -Uri "$($Url)api/2/search" -Headers $headers -Body $pagingParams
            
            # take the first search result
            $customerUserId = $searchResult.items[0].id

            # Also get full user (details) since not all are included in the search result
            $pagingParams = @{uuids = $customerUserId}
            $result = Invoke-RestMethod -Uri "$($Url)api/2/users" -Headers $headers -Body $pagingParams
            $customerUser = $result.items[0]
        } else {
            # Get all users that exists inside the customer tenant
            $customerUserIds = Invoke-RestMethod -Uri "$($Url)api/2/tenants/$($customerTenantId)/users" -Headers $headers
            
            # Take the first user
            $customerUserId = $customerUserIds.items[0]

            # Also get full user (details) instead of just the user ID
            $pagingParams = @{uuids = $customerUserId}
            $result = Invoke-RestMethod -Uri "$($Url)api/2/users" -Headers $headers -Body $pagingParams
            $customerUser = $result.items[0]
        }

        Log "Found user with login '$($customerUser.login)' with ID '$($customerUser.id)' and personal tenant ID '$($customerUser.personal_tenant_id)' in tenant '$($customerUser.tenant_id)'."

        if ($customerUser.enabled) {
            Log 'This user is enabled.'
        } else {
            Log "This user isn't enabled. Aborting script!"
            Exit 1
        }

        if ($customerUser.activated) {
            Log 'This user is activated.'
        } else {
            Log "This user isn't activated. Aborting script!"
            Exit 1
        }

        # Get personal tenant ID of the customers user
        $pagingParams = @{uuids = $customerUserId}
        $user = Invoke-RestMethod -Uri "$($Url)api/2/users" -Headers $headers -Body $pagingParams
        $personalTenantId = $user.items.personal_tenant_id

        # Issue a token
        $bearerAuthValue = "Bearer $ApiAccessToken"
        $headers = @{ "Authorization" = $bearerAuthValue }
        $headers.Add("Content-Type", "application/json")
        $headers.Add("User-Agent", "ACP 3.0/Acronis Cyber Platform PowerShell Examples")
        $json = @{
            'expires_in' = 3600
            'scopes' = @( "urn:acronis.com:tenant-id:$($personalTenantId):backup_agent_admin" )
        }
        $json = $json | ConvertTo-Json
        $ClientRegistration = Invoke-RestMethod -Method Post -Uri "$($Url)api/2/tenants/$($customerTenantId)/registration_tokens" -Headers $headers -Body $json

        <# 
            Create directory for installation file
        #>

        if (-not (Test-Path -Path $Dest)) {
            New-Item -Path $Dest -ItemType Directory -Force
        }

        <# 
            Connect to FTP server to receive installation file
        #>

        # Check if PowerShell module for SFTP is installed already
        if (Get-Module -Name Posh-SSH) {
            Log 'Module "Posh-SSH" already imported'
        } elseif (Get-Module -Name Posh-SSH -ListAvailable) {
            Log 'Module installed already.'

            Log 'Importing Module "Posh-SSH"...'
            Import-Module -Name Posh-SSH
        } else {
            if (-not (Get-PackageProvider -Name NuGet) ) {
                Log 'Installing NuGet...'
                Install-PackageProvider -Name NuGet -Force
            }

            Log 'Installing Module "Posh-SSH"...'
            Install-Module -Name Posh-SSH -Force

            Log 'Importing Module "Posh-SSH"...'
            Import-Module -Name Posh-SSH
        }

        # Build credentials for FTP server
        $SecureString = ConvertTo-SecureString -AsPlainText $FtpPassword -Force
        $Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $FtpUsername,$SecureString 

        try {
            # Connect to FTP server
            $s = New-SFTPSession -ComputerName $FtpServerFqdn -Credential $Creds -Port 22 -AcceptKey:$true

            # Download installation file
            Get-SFTPItem -SFTPSession $s -Path $Source -Destination $Dest -Force # One can only specify a directory as destination. The file will always keep its name.
        } finally {
            # Disconnect from FTP server
            Remove-SFTPSession -SFTPSession $s
        }

        <# 
            Install
        #>

        # Execute installation file with arguments
        # I decided not to wait for the process.
        # If I waited I might run into a timeout with the RMM script runner.
        & $InstallFile --quiet --language=$Lang --reg-token=$( $ClientRegistration.token ) --log-dir=$LogDir --reg-address=$Url
    }
} catch {
    Log "An error occurred. Will exit with exit code 1. Error Details:"
    Log "Exception Message: $($PSItem.Exception.Message)"
    Log "Inner Exception Message: $($PSItem.Exception.InnerException)"
    $PSItem.InvocationInfo | Format-List *
    Exit 1
}

#endregion EXECUTION
