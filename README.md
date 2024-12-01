# aovpn

This repository includes PowerShell scripts and sample ProfileXML configuration files used for creating Windows Always On VPN connections.


#### Intune Guide for Importing the XML Profile:

Create Profile in Intune
1. In the navigation pane click Device Configuration.
2. Click Profiles.
3. Click Create Profile.
4. Enter a descriptive name for the new VPN profile.
5. Select Windows 10 and later from the Platform drop-down list.
6. Select Custom from the Profile type drop-down list.

Custom OMA-URI Settings
1. In the Custom OMA-URI Settings blade click Add.
2. Enter a descriptive name in the Name field (this name will appear in the Windows UI on the client).
3. Enter _./User/Vendor/MSFT/VPNv2/Example%20Profile%Name/ProfileXML_ or _./Device/Vendor/MSFT/VPNv2/Example%20Profile%Name/ProfileXML_ (Device Tunnel)
in the OMA-URI field. If it includes spaces they must be escaped using %20, as shown here. Also, don’t forget to include the leading “.“.
4. Select String (XML file) from the Data type drop-down list.
5. Click the folder next to the Select a file field and select your ProfileXML file.
6. Click Ok.
