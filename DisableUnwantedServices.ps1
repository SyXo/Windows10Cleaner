$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"

Function DisableUnwantedServices
{
	$services = @(
		"diagnosticshub.standardcollector.service"	# Microsoft® Diagnostics Hub Standard Collector Service
		# "diagsvc"
		"DiagTrack"					# Diagnostics Tracking Service
		"diagsvc"
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
		"diagsvc"
		# "shpamsvc"
		"SessionEnv"
		"SysMain"					# Superfetch's name on 1903+
		"TermService"
		"TrkWks"					# Distributed Link Tracking Client
		"TroubleshootingSvc"
		"UmRdpService"
		# "UmRdpService"
		"WbioSrvc"					# Windows Biometric Service (required for Fingerprint reader / facial detection)
		"wercplsupport"					# Problem report
		"WerSvc"					# Windows report
		# "WlanSvc"					# WLAN AutoConfig (WiFi Networks)
		"WMPNetworkSvc"					# Windows Media Player Network Sharing Service
		"wlidsvc"
		"wisvc"						# Windows Insider service
		"wscsvc"					# Windows Security Center Service
		# "WSearch"					# Windows Search
		"XblAuthManager"				# Xbox Live Auth Manager
		"XblGameSave"					# Xbox Live Game Save Service
		"XboxGipSvc"
		"XboxNetApiSvc"					# Xbox Live Networking Service
	)
	ForEach ($service in $services) {
		Stop-Service $service -WarningAction SilentlyContinue
		Set-Service $service -StartupType Disabled
	}
}

Function FurtherDeleting
{
	for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "wscsvc" ^| find /i "wscsvc"') do (reg delete %I /f)
	for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "OneSyncSvc" ^| find /i "OneSyncSvc"') do (reg delete %I /f)
	for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "MessagingService" ^| find /i "MessagingService"') do (reg delete %I /f)
	for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "PimIndexMaintenanceSvc" ^| find /i "PimIndexMaintenanceSvc"') do (reg delete %I /f)
	for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UserDataSvc" ^| find /i "UserDataSvc"') do (reg delete %I /f)
	for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UnistoreSvc" ^| find /i "UnistoreSvc"') do (reg delete %I /f)
	for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "BcastDVRUserService" ^| find /i "BcastDVRUserService"') do (reg delete %I /f)
	for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "Sgrmbroker" ^| find /i "Sgrmbroker"') do (reg delete %I /f)
	sc delete diagnosticshub.standardcollector.service
	reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
	reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
	reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
	reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
	reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
	reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f
	reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f
	reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
	reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
	regini .\TakeKeyOwnership
}

DisableUnwantedServices
FurtherDeleting