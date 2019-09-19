$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"

Function DisableUnwantedServices
{
	$services = @(
		"diagnosticshub.standardcollector.service"	# Microsoft® Diagnostics Hub Standard Collector Service
		# "diagsvc"
		"DiagTrack"					# Diagnostics Tracking Service
		"dmwappushservice"				# WAP Push Message Routing Service
		"HomeGroupListener"				# HomeGroup Listener
		"HomeGroupProvider"				# HomeGroup Provider
		"lfsvc"						# Geolocation Service
		"MapsBroker"					# Downloaded Maps Manager
		"MessagingService"
		"ndu"						# Windows Network Data Usage Monitor
		"NetTcpPortSharing"				# Net.Tcp Port Sharing Service
		"OneSyncSvc"
		"PushToInstall"
		# "PcaSvc"					# Program compatibility assistant
		"RemoteAccess"					# Routing and Remote Access
		"RemoteRegistry"				# Remote Registry
		"RetailDemo"
		"SessionEnv"
		"SharedAccess"					# Internet Connection Sharing (ICS)
		# "shpamsvc"
		"SysMain"					# Superfetch's name on 1903+
		"TermService"
		"TrkWks"					# Distributed Link Tracking Client
		"TroubleshootingSvc"
		# "UmRdpService"
		"WbioSrvc"					# Windows Biometric Service (required for Fingerprint reader / facial detection)
		"wercplsupport"					# Problem report
		"WerSvc"					# Windows report
		# "WlanSvc"					# WLAN AutoConfig (WiFi Networks)
		"WMPNetworkSvc"					# Windows Media Player Network Sharing Service
		"wisvc"						# Windows Insider service
		"wscsvc"					# Windows Security Center Service
		# "WSearch"					# Windows Search
		"XblAuthManager"				# Xbox Live Auth Manager
		"XblGameSave"					# Xbox Live Game Save Service
		"XboxNetApiSvc"					# Xbox Live Networking Service
	)
	ForEach ($service in $services) {
		Stop-Service $service -WarningAction SilentlyContinue
		Set-Service $service -StartupType Disabled
	}
}