# Define the registry path and key
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Config"
$property = "AutoTriggerDisabledProfilesList"
$vpnName = "St Peters VPN"

# Check if vpn is added to the key

if (Test-Path -Path $registryPath) {
    try {
        $connections = Get-ItemProperty -Path $registryPath -Name $property
        if ($connections.$property -like "*$vpnName*") {
            Write-Output "VPN Connection: $vpnName detected - Proceeding to removal"
            Exit 1
        }
        else {
            Write-Output "VPN Connection: $vpnName not added - No further actions required"
            Exit 0
        }
    }
    catch {
        Write-Output "Error Occured getting the value. Exiting - No Action"
        Exit 0
    }
}

Write-Output "Key Does Not Exist - No Action Required"