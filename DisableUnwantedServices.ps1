$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"

Function DisableUnwantedServices
{
	$services = @(
		"diagnosticshub.standardcollector.service"	# Microsoft® Diagnostics Hub Standard Collector Service
		"DiagTrack"					# Diagnostics Tracking Service
		"dmwappushservice"				# WAP Push Message Routing Service (see known issues)
		"HomeGroupListener"				# HomeGroup Listener
		"HomeGroupProvider"				# HomeGroup Provider
		"lfsvc"						# Geolocation Service
		"MapsBroker"					# Downloaded Maps Manager
		"ndu"						# Windows Network Data Usage Monitor
		"NetTcpPortSharing"				# Net.Tcp Port Sharing Service
		"RemoteAccess"					# Routing and Remote Access
		"RemoteRegistry"				# Remote Registry
		"SharedAccess"					# Internet Connection Sharing (ICS)
		"SysMain"					# Superfetch's name on 1903+
		"TrkWks"					# Distributed Link Tracking Client
		"WbioSrvc"					# Windows Biometric Service (required for Fingerprint reader / facial detection)
		#"WlanSvc"					# WLAN AutoConfig (WiFi Networks)
		"WMPNetworkSvc"					# Windows Media Player Network Sharing Service
		"wscsvc"					# Windows Security Center Service
		#"WSearch"					# Windows Search
		"XblAuthManager"				# Xbox Live Auth Manager
		"XblGameSave"					# Xbox Live Game Save Service
		"XboxNetApiSvc"					# Xbox Live Networking Service
	)
	Foreach ($service in $services) {
		Get-Service -Name $service | Stop-Service -WarningAction SilentlyContinue
		Get-Service -Name $service | Set-Service -StartupType Disabled
	}
}