$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"

Function DisableUnwantedServices
{
	$services = @(
		"AJRouter"					# AllJoyn Router Service
		"AppXSvc"					# AppX Deployment Service
		"ALG"						# Application Layer Gateway Service
		"AppMgmt"					# Application Management
		"AppReadiness"					# Disabling App Readiness
		"AssignedAccessManagerSvc"			# AssignedAccessManager
		"BcastDVRUserService"
		"BDESVC"					# BitLocker Drive Encryption Service
		"BITS"						# Background Intelligent Transfer Service
		#"BTAGService"					# Bluetooth Audio Gateway Service
		#"bthserv"					# Bluetooth Support Service
		#"BthHFSrv"					# Bluetooth Handsfree Service
		"CDPSvc"					# Connected Devices Platform Service
		"CertPropSvc"					# Certificate Propagation
		"ClipSVC"					# Client License Service (ClipSVC)
		"diagnosticshub.standardcollector.service"	# Microsoft® Diagnostics Hub Standard Collector Service
		"diagsvc"					# Diagnostic Execution Service
		"DiagTrack"					# Diagnostics Tracking Service
		"DisplayEnhancementService"
		"dmwappushservice"				# WAP Push Message Routing Service
		"DoSvc"						# Delivery Optimisation
		"DPS"						# Diagnostic Policy Service
		"DusmSvc"					# Data Usage
		"EntAppSvc"					# Enterprise App Management Service
		"EFS"						# Encrypting File System
		"fdPHost"					# Function Discovery Provider Host
		"fhsvc"						# File History Service
		"FDResPub"					# Function Discovery Resource Publication
		"GraphicsPerfSvc"				# GraphicsPerfSvc
		"hns"						# Host Network Service
		"HomeGroupListener"				# HomeGroup Listener
		"HomeGroupProvider"				# HomeGroup Provider
		"HvHost"					# HV Host Service
		"KeyIso"					# CNG Key Isolation
		"lfsvc"						# Geolocation Service
		"MapsBroker"					# Downloaded Maps Manager
		"MessagingService"
		"MSDTC"						# Distributed Transaction Coordinator
		"ndu"						# Windows Network Data Usage Monitor
		"NetTcpPortSharing"				# Net.Tcp Port Sharing Service
		"OneSyncSvc"
		"PeerDistSvc"					# BranchCache
		"PimIndexMaintenanceSvc"
		"PushToInstall"
		# "PcaSvc"					# Program compatibility assistant
		"RemoteAccess"					# Routing and Remote Access
		"RemoteRegistry"				# Remote Registry
		"RetailDemo"
		"SessionEnv"
		"Sgrmbroker"
		"SharedAccess"					# Internet Connection Sharing (ICS)
		"SessionEnv"
		# "shpamsvc"
		"Superfetch"					# Versions older than 1903
		"SysMain"					# Superfetch's name on 1903+
		"TermService"
		"TrkWks"					# Distributed Link Tracking Client
		"TroubleshootingSvc"
		"tzautoupdate"					# Auto Time Zone Updater
		"UmRdpService"
		"UnistoreSvc"
		"UserDataSvc"
		"VaultSvc"					# Credential Manager
		"vmickvpexchange"				# Hyper-V Data Exchange Service
		"vmicguestinterface"				# Hyper-V Guest Service Interface
		"vmicshutdown"					# Hyper-V Guest Shutdown Service
		"wbengine"					# Block Level Backup Engine Service
		"WbioSrvc"					# Windows Biometric Service (required for Fingerprint reader / facial detection)
		"WdiServiceHost"				# Diagnostic Service Host
		"WdiSystemHost"					# Diagnostic System Host
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
	# regini .\TakeKeyOwnership
}

DisableUnwantedServices
FurtherDeleting