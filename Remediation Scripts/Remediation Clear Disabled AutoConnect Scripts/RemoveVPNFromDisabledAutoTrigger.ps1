# Define the registry path and key
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Config"
$property = "AutoTriggerDisabledProfilesList"
$vpnName = "St Peters VPN"


$key = Get-ItemProperty -Path $registryPath
$key.$property = ($key.$property -replace $vpnName) | Where-Object {$_.trim() -ne ""}
Set-ItemProperty -Path $registryPath -Name $property -Value $key.$property