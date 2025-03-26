$metric = 6
$ProfileName = "St Peters VPN Device Tunnel"

function updated-vpnConnection {

    [CmdletBinding(SupportsShouldProcess)]
    Param (

        [Parameter(Mandatory, HelpMessage = 'Enter the name of the VPN profile to update.')]    
        [string]$ProfileName,
        [string]$RasphonePath,
        [ValidateSet('IKEv2', 'IKEv2Only', 'SSTP', 'SSTPOnly', 'Automatic')]
        [string]$SetPreferredProtocol,
        [string]$InterfaceMetric,
        [ValidateSet('True', 'False')]
        [string]$DisableIkeMobility,
        [ValidateSet('60', '120', '300', '600', '1200', '1800')]
        [string]$NetworkOutageTime,
        [ValidateSet('True', 'False')]
        [string]$UseRasCredentials,
        [ValidateSet('True', 'False')]
        [string]$UseWinlogonCredential,
        [ValidateSet('True', 'False')]
        [string]$DisableClassBasedDefaultRoute,
        [ValidateSet('True', 'False')]
        [string]$DisableCredentialCaching,
        [ValidateSet('True', 'False')]
        [string]$RegisterDNS,
        [Alias("DeviceTunnel")]
        [switch]$AllUserConnection

    )

    # // Exit script if options to disable IKE mobility and define a network outage time are both enabled
    If ($DisableIkeMobility -And $NetworkOutageTime) {

        Write-Warning 'The option to disable IKE mobility and set a network outage time are mutually exclusive. Please choose one and run this command again.'
        Exit  

    }

    # // Define rasphone.pbk file path
    If (-Not $RasphonePath -and $AllUserConnection) {

        $RasphonePath = 'C:\ProgramData\Microsoft\Network\Connections\Pbk\rasphone.pbk'
        $RasphoneBackupPath = Join-Path 'C:\ProgramData\Microsoft\Network\Connections\Pbk\' -ChildPath "rasphone_$(Get-Date -Format FileDateTime).bak"

    }

    ElseIf (-Not $RasphonePath) {

        $RasphonePath = "$env:appdata\Microsoft\Network\Connections\Pbk\rasphone.pbk"
        $RasphoneBackupPath = Join-Path "$env:appdata\Microsoft\Network\Connections\Pbk\" -ChildPath "rasphone_$(Get-Date -Format FileDateTime).bak"

    }

    # // Ensure that rasphone.pbk exists
    If (!(Test-Path $RasphonePath)) {

        Write-Warning "The file $RasphonePath does not exist. Exiting script."
        Exit

    }

    # // Create backup of rasphone.pbk
    #Write-Verbose "Backing up existing rasphone.pbk file to $RasphoneBackupPath..."
    #Copy-Item $RasphonePath $RasphoneBackupPath

    # // Create empty VPN profile settings hashtable
    $Settings = @{ }

    # // Set preferred VPN protocol
    If ($SetPreferredProtocol) {

        Switch ($SetPreferredProtocol) {

            IKEv2 { $Value = '14' }
            IKEv2Only { $Value = '7' }
            SSTP { $Value = '6' }
            SSTPOnly { $Value = '5' }
            Automatic { $Value = '0' }

        }
    
        $Settings.Add('VpnStrategy', $Value)

    }

    # // Set IPv4 and IPv6 interface metrics
    If ($InterfaceMetric) {

        $Settings.Add('IpInterfaceMetric', $InterfaceMetric)
        $Settings.Add('Ipv6InterfaceMetric', $InterfaceMetric)
    }

    # // Disable IKE mobility
    If ($DisableIkeMobility) {

        Switch ($DisableIkeMobility) {

            True { $Value = '1' }
            False { $Value = '0' }

        }

        $Settings.Add('DisableMobility', $Value)
        $Settings.Add('NetworkOutageTime', '0')

    }

    # // If IKE mobility is enabled, define network outage time
    If ($NetworkOutageTime) {

        $Settings.Add('DisableMobility', '0')
        $Settings.Add('NetworkOutageTime', $NetworkOutageTime)

    }

    # // Define use of VPN credentials for SSO to on-premises resources (helpful for non-domain joined clients)
    If ($UseRasCredentials) {

        Switch ($UseRasCredentials) {

            True { $Value = '1' }
            False { $Value = '0' }

        }

        $Settings.Add('UseRasCredentials', $Value)

    }

    # // Define use of logged on user's Windows credentials for automatic VPN logon (helpful when MS-CHAP v2 authentication is configured)
    If ($UseWinlogonCredential) {

        Switch ($UseWinlogonCredential) {

            True { $Value = '1' }
            False { $Value = '0' }

        }

        $Settings.Add('AutoLogon', $Value)

    }

    # // Enable or disable the class-based default route
    If ($DisableClassBasedDefaultRoute) {

        Switch ($DisableClassBasedDefaultRoute) {

            True { $Value = '1' }
            False { $Value = '0' }

        }

        $Settings.Add('DisableClassBasedDefaultRoute', $Value)

    }

    # // Enable or disable credential caching
    If ($DisableCredentialCaching) {

        Switch ($DisableCredentialCaching) {

            True { $Value = '0' }
            False { $Value = '1' }

        }

        $Settings.Add('CacheCredentials', $Value)

    }

    # // Enable or disable VPN adapter DNS registration
    If ($RegisterDNS) {

        Switch ($RegisterDNS) {

            True { $Value = '1' }
            False { $Value = '0' }

        }

        $Settings.Add('IpDnsFlags', $Value)

    }

    # // Function to update rasphone.pbk
    Function Update-RASPhoneBook {

        [CmdletBinding(SupportsShouldProcess)]

        Param (

            [string]$Path,
            [string]$ProfileName,
            [hashtable]$Settings

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

            Write-Verbose "Updating $($SelectedProfile.key)"
            $pass += $SelectedProfile.key

            $Settings.GetEnumerator() | ForEach-Object {

                $SettingName = $_.name
                Write-Verbose "Searching for setting $Settingname..."
                $Value = $_.Value
                $thisName = "$SettingName=.*\s?`n"
                $thatName = "$SettingName=$value`n"
                If ($SelectedProfile.Value -match $thisName) {

                    Write-Verbose "Setting $SettingName = $Value."
                    $SelectedProfile.value = $SelectedProfile.value -replace $thisName, $thatName
                    $pass += ($ThatName).TrimEnd()
                    # // Set a flag indicating the file should be updated
                    $ChangeMade = $True

                }

                Else {

                    Write-Warning "Could not find an entry for $SettingName under [$($SelectedProfile.key)]."

                }

            } #ForEach setting

            If ($ChangeMade) {

                # // Update the VPN profile hashtable
                $profhash[$Selectedprofile.key] = $Selectedprofile.value

            }

        } #If found

        Else {

            Write-Warning "VPN Profile [$profilename] not found."

        }

        # // Only update the file if changes were made
        If (($ChangeMade) -AND ($pscmdlet.ShouldProcess($path, "Update RAS PhoneBook"))) {

            Write-Verbose "Updating $Path"
            $output = $profHash.Keys | ForEach-Object { $_ ; ($profhash[$_] | Out-String).trim(); "`n" }
            $output | Out-File -FilePath $Path -Encoding ascii

        } #Whatif

    } #close function

    Update-RasphoneBook -Path $RasphonePath -ProfileName $ProfileName -Settings $Settings
}

Write-Verbose "Updating Connect Metrics"
updated-vpnConnection -ProfileName $ProfileName -InterfaceMetric "6" -AllUserConnection

#Restart Connections 
Write-Verbose "Checking Connections"

$Connections = & "rasdial.exe"

if($Connections -like "*$ProfileName*"){
    Write-Output "Device Tunnel Active - Restarting"
    & rasdial.exe $ProfileName /Disconnect
    & rasdial.exe $ProfileName
}

Write-Output "Interface Metrixs Updated"
Exit 0