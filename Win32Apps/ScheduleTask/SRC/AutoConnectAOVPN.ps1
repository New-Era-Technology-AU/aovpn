##############################################
#                 Config
##############################################

$VPNProfiles = @(
    @{
        ProfileName = "St Peters VPN"
        DNSSuffix   = "stpeterss.school.nz"
        RemediateAutoConnect = $true
        DoNotDial   = $true
    },
    @{
        ProfileName = "St Peters VPN Device Tunnel"
        DNSSuffix   = "stpeterss.school.nz"
    }
)

##############################################
#                 Functions
##############################################

function start-AOVPNconnection {
    [CmdletBinding()]
    Param (
        [string]$ConnectionName
    )

    Write-Verbose "Dialing Connection: $ConnectionName"
    $ConnectionStatus = & rasdial $ConnectionName

    If ($ConnectionStatus -like "*error*") {
        Write-Verbose "Dialing Connection: $ConnectionName - Failed"
        $ConnectionStatus
        Continue
    }

    Write-Verbose "Dialing Connection: $ConnectionName - Connected"
}

function get-OnNetworkStatus {
    [CmdLetBinding()]
    Param(
        [string]$DNSSuffix
    )
    #Check Interfaces if DNS Suffix is on domain
    $interfaces = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }

    
    foreach ($interface in $interfaces) {
        if ($interface.DNSDomain -eq $DNSSuffix) {
            Write-Verbose "Device connected to domain - No Action required"
            Return $true
        }
        else {
            Write-Verbose "Interface: $($interface.Description) - DNS suffix does not match"
        }
    }

}

function reset-AutoConnect {
    [CmdletBinding()]
    Param (
        [string]$ProfileName = 'Always On VPN',
        [switch]$AllUserConnection
    )

    # Search AutoTriggerDisabledProfilesList for VPN profile
    $Path = 'HKLM:\System\CurrentControlSet\Services\RasMan\Config\'
    $Name = 'AutoTriggerDisabledProfilesList'

    Write-Verbose "Searching $Name in $Path for VPN profile `"$ProfileName`"..."

    Try {

        # Get the current registry values as an array of strings
        [string[]]$DisabledProfiles = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop

    }

    Catch {

        Write-Verbose "$Name does not exist in $Path. No action required."
        Return

    }

    If ($DisabledProfiles) {

        # Create ordered hashtable
        $List = [Ordered]@{}
        $DisabledProfiles | ForEach-Object { $List.Add("$($_.ToLower())", $_) }

        # Search hashtable for matching VPN profile and remove if present
        If ($List.Contains($ProfileName)) {
            Write-Verbose 'Profile found. Removing entry...'
            $List.Remove($ProfileName)
            Write-Verbose 'Updating the registry...'
            Set-ItemProperty -Path $Path -Name $Name -Value $List.Values
        }
    }

    Else {

        Write-Verbose "No profiles found matching `"$ProfileName`"."
        Return

    }

    # Add user SID to registry
    If ($AllUserConnection) {

        $SID = 'S-1-1-0'
        Write-Verbose "Adding SYSTEM SID $SID to registry..."

    }

    Else {

        Try {

            $SID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            Write-Verbose "Adding user SID $SID to registry..."

        }

        Catch {

            Write-Warning $_.Exception.Message
            Return

        }

    }

    $Parameters = @{

        Path         = 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Config\'
        Name         = 'UserSID'
        PropertyType = 'String'
        Value        = $SID

    }

    New-ItemProperty @Parameters -Force | Out-Null

    # Add VPN profile name to registry
    $Parameters = @{

        Path         = 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Config\'
        Name         = 'AutoTriggerProfileEntryName'
        PropertyType = 'String'
        Value        = $ProfileName

    }

    New-ItemProperty @Parameters | Out-Null

    # Add VPN profile GUID to registry
    Write-Verbose "Adding VPN GUID $GUID to registry..."
    $GuidString = Get-VpnConnection -Name $ProfileName -AllUserConnection:$AllUserConnection | Select-Object GUID
    $Guid = [guid]::Parse($GuidString.GUID)
    $Binary = $Guid.ToByteArray()

    $Parameters = @{

        Path         = 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Config\'
        Name         = 'AutoTriggerProfileGUID'
        PropertyType = 'Binary'
        Value        = $Binary

    }

    New-ItemProperty @Parameters | Out-Null

    # Add phonebook path to registry
    If ($AllUserConnection) {

        $Path = Join-Path -Path $env:programdata -ChildPath Microsoft\Network\Connections\Pbk\rasphone.pbk
        Write-Verbose "RAS phonebook path is $Path."

    }

    Else {

        $Path = Join-Path -Path $env:userprofile -ChildPath AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk
        Write-Verbose "RAS phonebook path is $Path."

    }

    $Parameters = @{

        Path         = 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Config\'
        Name         = 'AutoTriggerProfilePhonebookPath'
        PropertyType = 'String'
        Value        = $Path

    }

    New-ItemProperty @Parameters | Out-Null
}

##############################################
#               Script Start
##############################################

#------- Clear Autoconnect RegKey, restart services ------#
foreach ($Profile in $VPNProfiles) {
    if($Profile.RemediateAutoConnect){
        Write-Verbose "Remediating Auto Connect for: $($Profile.ProfileName)"
        reset-AutoConnect -ProfileName $Profile.ProfileName -Verbose -AllUserConnection
    }
}

Start-Sleep -Seconds 10

#------- Connect if offnetwork --------#
$CurrentConnections = & "rasdial.exe"

foreach ($Profile in $VPNProfiles) {
    if (!($CurrentConnections -like "$($Profile.ProfileName)")) {
        # Test if is on the network
        if (!(get-OnNetworkStatus -DNSSuffix $Profile.DNSSuffix -Verbose) -and !($Profile.DoNotDial)) {
            start-AOVPNconnection -ConnectionName $Profile.ProfileName -Verbose
        }   
    }
}