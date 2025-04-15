##############################################
#                 Config
##############################################

$TaskName = "AOVPN AutoConnect"
$ScriptLocation = "C:\Scheduled Commands"
$ScriptToCopy = "AutoConnectAOVPN.ps1"
$Version = "1.0"

##############################################
#               Script Start
##############################################

# Ensure the script location exists
if (-Not (Test-Path -Path $ScriptLocation)) {
    New-Item -ItemType Directory -Path $ScriptLocation
}

# Copy the script to the desired location
Copy-Item -Path "$ScriptToCopy" -Destination "$ScriptLocation\$ScriptToCopy"



# # Define the action to run the script
$action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-ex bypass -File '$ScriptLocation\$ScriptToCopy'"

# # Define the triggers
$trigger1 = New-ScheduledTaskTrigger -AtLogOn
$trigger2 = New-ScheduledTaskTrigger -AtStartup

# Define Custom Trigger for wake from sleep/hybernation
$class = cimclass MSFT_TaskEventTrigger root/Microsoft/Windows/TaskScheduler
$trigger3 = $class | New-CimInstance -ClientOnly
$trigger3.Enabled = $true
$trigger3.Subscription = '<QueryList><Query Id="0" Path="System"><Select Path="System">*[System[Provider[@Name=''Microsoft-Windows-Kernel-Power''] and EventID=107]]</Select></Query></QueryList>'

# # Define the principal to run as SYSTEM
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
# # Define the settings
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

# # Register the scheduled task
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger1, $trigger2, $trigger3 -Principal $principal -Settings $settings -Force -Description $Version