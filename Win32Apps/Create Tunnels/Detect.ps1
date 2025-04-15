##############################################
#                   Config
##############################################

$VersionKey = "TunnelVersion"
$DesiredVersion = "3"

$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Config"
$property = $VersionKey

$UserTunnelConnectionName = "St Peters VPN"
$DeviceTunnelConnectionName = "St Peters VPN Device Tunnel"


##############################################
#                Script Start
##############################################

#Check if the VPN Tunnel Exists
$UserTunnelConnection = Get-VpnConnection -Name $UserTunnelConnectionName -AllUserConnection -ErrorAction SilentlyContinue
$DeviceTunnelConnection = Get-VpnConnection -Name $DeviceTunnelConnectionName -AllUserConnection -ErrorAction SilentlyContinue

if($UserTunnelConnection -and $DeviceTunnelConnection){
    #Check Version
    try {
        $key = Get-ItemProperty -Path $registryPath -Name $property -ErrorAction SilentlyContinue
        if($key.$VersionKey -eq $DesiredVersion){
            Write-Output "Tunnels Exist and Version Matches - No further action required"
            Exit 0
        }
        Write-Output "Tunnels Exist but Version is Incorect - Moving to Installation"
        Exit 1
    }
    catch {
        Write-Output "Error: $_ - Moving to Installation"
        Exit 1
    }
    
}

Write-Output "User or Device Tunnel Does Not Exist - Moving to Installation"
Exit 1