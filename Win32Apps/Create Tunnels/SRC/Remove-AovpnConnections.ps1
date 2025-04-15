##############################################
#                   Config
##############################################
param(
    [ValidateNotNullOrEmpty()]
    [string]$UserTunnelConnectionName,
    [string]$DeviceTunnelConnectionName
)

##############################################
#                   Functions
##############################################
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

##############################################
#                Script Start
##############################################

Write-Verbose "Removing Tunnels"
    
#User Tunnel
& rasdial.exe $UserTunnelConnectionName /disconnect
Remove-AOVPNConnection -ProfileName $UserTunnelConnectionName -AllUserConnection

#Device Tunnel
& rasdial.exe $DeviceTunnelConnectionName /disconnect
Remove-AOVPNConnection -ProfileName $DeviceTunnelConnectionName -DeviceTunnel