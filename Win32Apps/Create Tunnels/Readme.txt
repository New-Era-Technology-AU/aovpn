### ReadMe


Install: powershell.exe -ex bypass -file Add-AOVPNConnections.ps1 -UserTunnelXmlFilePath STP_ProfileXML_User_EAP.xml -DeviceTunnelXmlFilePath STP_ProfileXML_Device.xml -UserTunnelConnectionName "St Peters VPN" -DeviceTunnelConnectionName "St Peters VPN Device Tunnel" -Version 1 -VersionKey TunnelVersion -UserTunnelInterfaceMetric 3 -DeviceTunnelInterfaceMetric 6 -replace
Remove: powershell.exe -ex bypass -file Remove-AovpnConnections.ps1 -UserTunnelConnectionName "St Peters VPN" -DeviceTunnelConnectionName "St Peters VPN Device Tunnel"