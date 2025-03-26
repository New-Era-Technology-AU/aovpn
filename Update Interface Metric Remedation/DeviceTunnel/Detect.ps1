$RasphonePath = "C:\ProgramData\Microsoft\Network\Connections\Pbk\rasphone.pbk"
$metric = 6
$ProfileName = "St Peters VPN Device Tunnel"


Function Check-RASPhoneBook {

    [CmdletBinding(SupportsShouldProcess)]

    Param (
        [string]$Path,
        [string]$ProfileName,
        [int]$desiredMetric
    )

    $pattern = "(\[.*\])"
    $c = Get-Content $path -Raw
    $p = [System.Text.RegularExpressions.Regex]::Split($c, $pattern, "IgnoreCase") | Where-Object { $_ }

    # // Create a hashtable of VPN profiles
    Write-Verbose "Initializing a hashtable for VPN profiles from $path..."
    $profHash = [ordered]@{}

    For ($i = 0; $i -lt $p.count; $i += 2) {

        Write-Verbose "Adding $($p[$i]) to VPN profile hashtable..."
        $profhash.Add($p[$i], $p[$i + 1])

    }

    # // An array to hold changed values for -Passthru
    $pass = @()

    Write-Verbose "Found the following VPN profiles: $($profhash.keys -join ',')."

    $compare = "[$Profilename]"

    Write-Verbose "Searching for VPN profile $compare..."
    # // Need to make sure to get the exact profile
    $SelectedProfile = $profHash.GetEnumerator() | Where-Object { $_.name -eq $compare }

    If ($SelectedProfile) {
        $IPv4_MetrixString = "IpInterfaceMetric=$desiredMetric"
        $IPv6_MetrixString = "Ipv6InterfaceMetric=$desiredMetric"

        Write-Verbose "Checking $($SelectedProfile.key) interface Metric"
        if(!($SelectedProfile.value -match $IPv4_MetrixString)){
            Write-Output "IPv4 Metrix is wrong  - Moving to remediation"
            Exit 1
        }
        if(!($SelectedProfile.value -match $IPv6_MetrixString)){
            Write-Output "IPv6 Metrix is wrong - Moving to remediation"
            Exit 1
        }
        Write-Output "Interface metrixs are correct - No Further Action Required"
        Exit 0   
    } #If found
    Else {
        Write-Warning "VPN Profile [$profilename] not found. - No Further Action Required"
        Exit 0
    }
}


#Check if path exists
if(Test-Path $RasphonePath){
    #Check if Interface Metric is correct
    Check-RASPhoneBook -Path $RasphonePath -ProfileName $ProfileName -desiredMetric $metric
}

Write-Output "VPN Connection does not exist - No action required"
Exit 0