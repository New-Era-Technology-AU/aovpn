##############################################
#                 Config
##############################################

$TaskName = "AOVPN AutoConnect"
$ScriptLocation = "C:\Scheduled Commands"
$Script = "AutoConnectAOVPN.ps1"
$Version = "1.0"

##############################################
#               Script Start
##############################################

# Check if the scheduled task exists, check version and check for existance of script
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

if ($null -ne $task) {
    # Get the task description
    $taskDescription = $task.Description

    # Check if the description contains the version
    if ($taskDescription -match $Version) {
        # Check if the script file exists
        $scriptPath = Join-Path -Path $ScriptLocation -ChildPath $Script
        if (Test-Path -Path $scriptPath) {
            Write-Output "Script file exists at $scriptPath and Version matches - No Action Requred"
            Exit 0
        } else {
            Write-Output "Script file does not exist at $scriptPath - Moving to Remediation"
            Exit 1
        }
    } else {
        Write-Output "Task version does not match desired version: $Version - Moving to Remediation"
        Exit 1
    }
} else {
    Write-Output "Scheduled task '$TaskName' does not exist - Moving to Remediation"
}
