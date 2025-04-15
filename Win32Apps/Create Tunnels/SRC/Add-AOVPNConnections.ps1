##############################################
#                   Config
##############################################
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, HelpMessage = 'Enter the path to the ProfileXML file.')]
    [ValidateNotNullOrEmpty()]
    [string]$UserTunnelXmlFilePath,
    [string]$DeviceTunnelXmlFilePath,
    [string]$UserTunnelConnectionName,
    [string]$DeviceTunnelConnectionName,
    [int]$Version,
    [string]$VersionKey,
    [int]$UserTunnelInterfaceMetric,
    [int]$DeviceTunnelInterfaceMetric,
    [switch]$replace
)

##############################################
#                   Functions
##############################################

function Add-Connection {
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Enter the path to the ProfileXML file.')]
        [ValidateNotNullOrEmpty()]
        [string]$xmlFilePath,
        [Parameter(HelpMessage = 'Enter a name for the VPN profile.')]
        [Alias("Name", "ConnectionName")]
        [string]$ProfileName,
        [switch]$DeviceTunnel,
        [switch]$AllUserConnection

    )

    # // Set default profile name
    If ($ProfileName -eq '') {

        If ($DeviceTunnel) {

            $ProfileName = 'Always On VPN Device Tunnel'

        }

        Else {

            $ProfileName = 'Always On VPN'

        }

    }

    # // Check for existing connection. Exit if exists.
    If ($AllUserConnection -or $DeviceTunnel) {

        # // Script must be running in the context of the SYSTEM account to extract ProfileXML from a device tunnel connection. Validate user, exit if not running as SYSTEM.
        $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

        If ($CurrentPrincipal.Identities.IsSystem -ne $True) {

            Write-Warning 'This script is not running in the SYSTEM context, as required.'
            Return

        }

        # // Check for existing connection. Exit if exists.
        If (Get-VpnConnection -Name $ProfileName -AllUserConnection -ErrorAction SilentlyContinue) {

            Write-Warning "The VPN profile ""$ProfileName"" already exists."
            Return

        }

    }

    Else {

        If (Get-VpnConnection -Name $ProfileName -ErrorAction SilentlyContinue) {

            Write-Warning "The VPN profile ""$ProfileName"" already exists."
            Return

        }

    }

    # // Validate XML for user or device tunnel connections
    [xml]$Xml = Get-Content $xmlFilePath

    If ($DeviceTunnel) {

        If (($Xml.VPNProfile.DeviceTunnel -eq 'False') -or ($Null -eq $Xml.VPNProfile.DeviceTunnel)) {

            Write-Warning 'ProfileXML is not configured for a device tunnel.'
            Return

        }

    }

    If (!$DeviceTunnel) {

        If ($Xml.VPNProfile.DeviceTunnel -eq 'True') {

            Write-Warning 'ProfileXML is not configured for a user tunnel.'
            Return

        }

    }

    # // Import ProfileXML
    $ProfileXML = Get-Content $xmlFilePath

    # // Escape spaces in profile name
    $ProfileNameEscaped = $ProfileName -Replace ' ', '%20'
    $ProfileXML = $ProfileXML -Replace '<', '&lt;'
    $ProfileXML = $ProfileXML -Replace '>', '&gt;'
    $ProfileXML = $ProfileXML -Replace '"', '&quot;'

    # // OMA URI information
    $NodeCSPURI = './Vendor/MSFT/VPNv2'
    $NamespaceName = 'root\cimv2\mdm\dmmap'
    $ClassName = 'MDM_VPNv2_01'

    # // Registry clean-up
    Write-Verbose "Cleaning up registry artifacts for VPN connection ""$ProfileName""..."

    # // Remove registry artifacts from ERM\Tracked
    Write-Verbose "Searching for profile $ProfileNameEscaped..."

    $BasePath = "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked"
    $Tracked = Get-ChildItem -Path $BasePath

    ForEach ($Item in $Tracked) {

        Write-Verbose "Processing $(Convert-Path $Item.PsPath)..."
        $Key = Get-ChildItem $Item.PsPath -Recurse | Where-Object { $_ | Get-ItemProperty -Include "Path*" }
        $PathCount = ($Key.Property -Match "Path\d+").Count
        Write-Verbose "Found a total of $PathCount Path* entries."

        # // There may be more than 1 matching key
        ForEach ($K in $Key) {

            $Path = $K.Property | Where-Object { $_ -Match "Path\d+" }
            $Count = $Path.Count
            Write-Verbose "Found $Count Path* entries under $($K.Name)."

            ForEach ($P in $Path) {

                Write-Verbose "Testing $P..."
                $Value = $K.GetValue($P)

                If ($Value -Match "$($ProfileNameEscaped)$") {

                    Write-Verbose "Removing $Value under $($K.Name)..."
                    $K | Remove-ItemProperty -Name $P

                    # // Decrement count
                    $Count--

                }

            } # // ForEach $P in $Path

            #  // Update count
            Write-Verbose "Setting count to $Count..."
            $K | Set-ItemProperty -Name Count -Value $Count

        } # // ForEach $K in $Key

    } # // ForEach $Item in $Tracked

    # // Remove registry artifacts from NetworkList\Profiles
    $Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\'
    Write-Verbose "Searching $Path for VPN profile ""$ProfileName""..."
    $Key = Get-Childitem -Path $Path | Where-Object { (Get-ItemPropertyValue $_.PsPath -Name Description) -eq $ProfileName }

    If ($Key) {

        Write-Verbose "Removing $($Key.Name)..."
        $Key | Remove-Item

    }

    Else {

        Write-Verbose "No profiles found matching ""$ProfileName"" in the network list."

    }

    # // Remove registry artifacts from RasMan\Config
    $Path = 'HKLM:\System\CurrentControlSet\Services\RasMan\Config\'
    $Name = 'AutoTriggerDisabledProfilesList'

    Write-Verbose "Searching $Name under $Path for VPN profile called ""$ProfileName""..."

    Try {

        # // Get the current registry values as an array of strings
        [string[]]$Current = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop

    }

    Catch {

        Write-Verbose "$Name does not exist under $Path. No action required."

    }

    If ($Current) {

        #// Create ordered hashtable
        $List = [Ordered]@{}
        $Current | ForEach-Object { $List.Add("$($_.ToLower())", $_) }

        # //Search hashtable for matching VPN profile and remove if present
        If ($List.Contains($ProfileName)) {

            Write-Verbose "Profile found. Removing entry..."
            $List.Remove($ProfileName)
            Write-Verbose "Updating the registry..."
            Set-ItemProperty -Path $Path -Name $Name -Value $List.Values

        }

    }

    Else {

        Write-Verbose "No profiles found matching ""$ProfileName""."

    }

    # // Create the VPN connection

    If (!$AllUserConnection -and !$DeviceTunnel) {

        Try {

            # // Identify current user
            $Sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            Write-Verbose "User SID is $Sid."

        }

        Catch {

            Write-Warning $_.Exception.Message
            Return

        }

    }

    $Session = New-CimSession

    Try {

        $NewInstance = New-Object Microsoft.Management.Infrastructure.CimInstance $ClassName, $NamespaceName
        $Property = [Microsoft.Management.Infrastructure.CimProperty]::Create('ParentID', "$NodeCSPURI", 'String', 'Key')
        $NewInstance.CimInstanceProperties.Add($Property)
        $Property = [Microsoft.Management.Infrastructure.CimProperty]::Create('InstanceID', "$ProfileNameEscaped", 'String', 'Key')
        $NewInstance.CimInstanceProperties.Add($Property)
        $Property = [Microsoft.Management.Infrastructure.CimProperty]::Create('ProfileXML', "$ProfileXML", 'String', 'Property')
        $NewInstance.CimInstanceProperties.Add($Property)

        If (!$AllUserConnection -and !$DeviceTunnel) {

            $Options = New-Object Microsoft.Management.Infrastructure.Options.CimOperationOptions
            $Options.SetCustomOption('PolicyPlatformContext_PrincipalContext_Type', 'PolicyPlatform_UserContext', $False)
            $Options.SetCustomOption('PolicyPlatformContext_PrincipalContext_Id', "$Sid", $False)
            $Session.CreateInstance($NamespaceName, $NewInstance, $Options)

        }

        Else {

            $Session.CreateInstance($NamespaceName, $NewInstance)

        }

        Write-Output "Always On VPN profile ""$ProfileName"" created successfully."

    }

    Catch {

        Write-Output "Unable to create ""$ProfileName"" profile: $_"
        Return

    }
}

function Set-InterfaceMetric {
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

function Remove-AOVPNConnection {
    Param (

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, HelpMessage = 'Enter the name of the VPN profile to remove.')]
        [ValidateNotNullOrEmpty()]
        [Alias('Name', 'ConnectionName')]
        [string]$ProfileName,
        [switch]$DeviceTunnel,
        [switch]$AllUserConnection,
        [switch]$CleanUpOnly

    )

    Process {

        # Validate running under the SYSTEM context for device tunnel or all user connection configuration
        If ($DeviceTunnel -or $AllUserConnection) {

            # Script must be running in the context of the SYSTEM account to extract ProfileXML from a device tunnel connection. Validate user, exit if not running as SYSTEM
            $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

            If ($CurrentPrincipal.Identities.IsSystem -ne $True) {

                Write-Warning 'This script is not running in the SYSTEM context, as required.'
                Return

            }

            # Validate VPN connection
            $Vpn = Get-VpnConnection -AllUserConnection -Name $ProfileName -ErrorAction SilentlyContinue

        }

        Else {

            # Validate VPN connection
            $Vpn = Get-VpnConnection -Name $ProfileName -ErrorAction SilentlyContinue

        }

        If (($Null -eq $Vpn) -and (!($CleanUpOnly))) {

            Write-Warning "The VPN connection ""$ProfileName"" does not exist."
            Return

        }

        # Escape spaces in profile name
        $ProfileNameEscaped = $ProfileName -Replace ' ', '%20'

        # OMA URI information
        $NamespaceName = 'root\cimv2\mdm\dmmap'
        $ClassName = 'MDM_VPNv2_01'

        If (!$CleanUpOnly) {

            # Search for and remove matching VPN profile
            Try {

                $Session = New-CimSession

                If (!$AllUserConnection -and ($CurrentPrincipal.Identities.IsSystem -eq $True)) {

                    $Sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                    Write-Verbose "User SID is $Sid."

                    $Options = New-Object Microsoft.Management.Infrastructure.Options.CimOperationOptions
                    $Options.SetCustomOption('PolicyPlatformContext_PrincipalContext_Type', 'PolicyPlatform_UserContext', $False)
                    $Options.SetCustomOption('PolicyPlatformContext_PrincipalContext_Id', "$Sid", $False)

                    $DeleteInstances = $Session.EnumerateInstances($NamespaceName, $ClassName, $Options)

                }

                Else {

                    $DeleteInstances = $Session.EnumerateInstances($NamespaceName, $ClassName)

                }

                Write-Verbose "Searching for VPN profile ""$ProfileName""..."

                ForEach ($DeleteInstance in $DeleteInstances) {

                    $InstanceId = $DeleteInstance.InstanceID

                    If ("$InstanceId" -eq "$ProfileNameEscaped") {

                        Write-Verbose "Removing VPN connection ""$ProfileName""..."
                        $Session.DeleteInstance($NamespaceName, $DeleteInstance, $Options)
                        $ProfileRemoved = $True

                    }

                    Else {

                        Write-Verbose "Ignoring existing VPN profile ""$InstanceId""..."

                    }

                }

            }

            Catch {

                Write-Warning $_.Exception.Message
                Write-Warning "Unable to remove VPN profile ""$ProfileName""."
                Return

            }

        }

        If ($ProfileRemoved -or $CleanUpOnly) {

            # Registry clean-up
            Write-Verbose "Cleaning up registry artifacts for VPN connection ""$ProfileName""..."

            # Remove registry artifacts from ERM\Tracked
            Write-Verbose "Searching ERM\Tracked for profile ""$ProfileNameEscaped""..."

            $BasePath = "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked"
            $Tracked = Get-ChildItem -Path $BasePath

            ForEach ($Item in $Tracked) {

                Write-Verbose "Processing $(Convert-Path $Item.PsPath)..."
                $Key = Get-ChildItem $Item.PsPath -Recurse | Where-Object { $_ | Get-ItemProperty -Include "Path*" }
                $PathCount = ($Key.Property -Match "Path\d+").Count
                Write-Verbose "Found a total of $PathCount ERM\Tracked entries."

                # There may be more than 1 matching key
                ForEach ($K in $Key) {

                    $Path = $K.Property | Where-Object { $_ -Match "Path\d+" }
                    $Count = $Path.Count
                    Write-Verbose "Found $Count entries under $($K.Name)."

                    ForEach ($P in $Path) {

                        Write-Verbose "Testing $P..."
                        $Value = $K.GetValue($P)

                        If ($Value -Match "$($ProfileNameEscaped)$") {

                            Write-Verbose "Removing $Value under $($K.Name)..."
                            $K | Remove-ItemProperty -Name $P

                            # Decrement count
                            $Count--

                        }

                    } # ForEach $P in $Path

                    #  // Update count
                    Write-Verbose "Setting count to $Count..."
                    $K | Set-ItemProperty -Name Count -Value $Count

                } # ForEach $K in $Key

            } # ForEach $Item in $Tracked

            # Remove registry artifacts from NetworkList\Profiles
            $Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\'
            Write-Verbose "Searching $Path for VPN profile ""$ProfileName""..."
            $Key = Get-Childitem -Path $Path | Where-Object { (Get-ItemPropertyValue $_.PsPath -Name Description) -eq $ProfileName }

            If ($Key) {

                Write-Verbose "Removing $($Key.Name)..."
                $Key | Remove-Item

            }

            Else {

                Write-Verbose "No profiles found matching ""$ProfileName"" in the network list."

            }

            # Remove registry artifacts from RasMan\Config
            $Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Config\'
            $Name = 'AutoTriggerDisabledProfilesList'

            Write-Verbose "Searching $Name under $Path for VPN profile ""$ProfileName""..."

            Try {

                # Get the current registry values as an array of strings
                [string[]]$Current = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop

            }

            Catch {

                Write-Verbose "$Name does not exist under $Path. No action required."

            }

            If ($Current) {

                # Create ordered hashtable
                $List = [Ordered]@{}
                $Current | ForEach-Object { $List.Add("$($_.ToLower())", $_) }

                # Search hashtable for matching VPN profile and remove if present
                If ($List.Contains($ProfileName)) {

                    Write-Verbose "Profile found in AutoTriggerDisabledProfilesList. Removing entry..."
                    $List.Remove($ProfileName)
                    Write-Verbose "Updating the registry..."
                    Set-ItemProperty -Path $Path -Name $Name -Value $List.Values

                }

            }

            Else {

                Write-Verbose "No profiles found matching ""$ProfileName"" in the AutoTriggerDisabledProfilesList registry key."

            }

            # Remove registry artifacts from RasMan\DeviceTunnel
            If ($DeviceTunnel) {

                Write-Verbose 'Searching for entries in RasMan\DeviceTunnel...'
                $Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\DeviceTunnel\'

                If (Test-Path -Path $Path) {

                    Write-Verbose 'RasMan\DeviceTunnel found. Removing registry key...'
                    $Path = Get-Item -Path $Path
                    Remove-Item -Path $Path.PsPath -Recurse -Force

                }

                Else {

                    Write-Verbose 'RasMan\DeviceTunnel not found. No action required.'

                }

            }

        }

        Else {

            Write-Verbose "VPN profile ""$ProfileName"" not found."

        }

    }
}

function Set-VersionRegKey {
    param (
        [int]$Version,
        [string]$VersionKey
    )

    # Define the registry path and key
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Config"
    $property = $VersionKey


    # Check if the registry key exists
    if (-Not (Test-Path $registryPath)) {
        # Create the registry key if it doesn't exist
        New-Item -Path $registryPath -Force
    }

    # Check if the property exists
    if (-Not (Get-ItemProperty -Path $registryPath -Name $property -ErrorAction SilentlyContinue)) {
        # Create the property and set it to the integer value
        New-ItemProperty -Path $registryPath -Name $property -Value $Version -PropertyType DWord
    }
    else {
        # Set the property to the integer value if it already exists
        Set-ItemProperty -Path $registryPath -Name $property -Value $Version
    }
}

##############################################
#                Script Start
##############################################

#Order Is Important, The User Tunnel must be added first followed by the Device Tunnel

if ($Replace) {
    Write-Verbose "Replace set to true: Removing VPN Connections if it exists"
    
    #User Tunnel
    & rasdial.exe $UserTunnelConnectionName /disconnect
    Remove-AOVPNConnection -ProfileName $UserTunnelConnectionName -AllUserConnection

    #Device Tunnel
    & rasdial.exe $DeviceTunnelConnectionName /disconnect
    Remove-AOVPNConnection -ProfileName $DeviceTunnelConnectionName -DeviceTunnel
}

Write-Verbose "Adding User Tunnel VPN: $UserTunnelConnectionName"
Add-Connection -Name $UserTunnelConnectionName -AllUserConnection -xmlFilePath $UserTunnelXmlFilePath
Start-Sleep -Seconds 3

Write-Verbose "Adding Device Tunnel VPN: $DeviceTunnelConnectionName"
Add-Connection -Name $DeviceTunnelConnectionName -DeviceTunnel -xmlFilePath $DeviceTunnelXmlFilePath
Start-Sleep -Seconds 3

Write-Verbose "Setting VPN Interface Metric and disabling Ras Credentials for: $UserTunnelConnectionName"
Set-InterfaceMetric -ProfileName $UserTunnelConnectionName -InterfaceMetric $UserTunnelInterfaceMetric -AllUserConnection -UseRasCredentials:False

Write-Verbose "Setting VPN Interface Metric: $DeviceTunnelConnectionName"
Set-InterfaceMetric -ProfileName $DeviceTunnelConnectionName -InterfaceMetric $DeviceTunnelInterfaceMetric -AllUserConnection

Write-Verbose "VPN Deployed and Metric Set - Setting Version Reg Key for version Tracking"
Set-VersionRegKey -Version $Version -VersionKey $VersionKey