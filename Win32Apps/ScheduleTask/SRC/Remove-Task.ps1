##############################################
#                 Config
##############################################

$TaskName = "AOVPN AutoConnect"
$ScriptLocation = "C:\Scheduled Commands"
$ScriptName = "AutoConnectAOVPN.ps1"


##############################################
#               Script Start
##############################################

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false

Remove-Item -Path "$ScriptLocation\$ScriptName" -Force