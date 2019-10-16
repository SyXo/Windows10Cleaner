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
		"AppVClient"					# Microsoft App-V Client
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
		"CscService"					# Offline Files
		"defragsvc"					# Optimise drives
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
		"IEEtwCollectorService"				# Internet Explorer ETW Collector Service
		"iphlpsvc"					# IP Helper
		"IpxlatCfgSvc"					# IP Translation Configuration Service
		"InstallService"				# Microsoft Store Install Service
		"irmon"						# Infrared monitor service
		"KeyIso"					# CNG Key Isolation
		"lfsvc"						# Geolocation Service
		"lltdsvc"					# Link-Layer Topology Discovery Mapper
		"MapsBroker"					# Downloaded Maps Manager
		"MessagingService"
		"MSDTC"						# Distributed Transaction Coordinator
		"MSiSCSI"					# Microsoft iSCSI Initiator Service
		"NaturalAuthentication"				# Natural Authentification
		"NcaSvc"					# Network Connectivity Assistant
		"NcbService"					# Network Connection Broker
		"NcdAutoSetup"					# Network Connected Devices Auto-Setup
		"ndu"						# Windows Network Data Usage Monitor
		"Netlogon"					# Netlogon
		"NetTcpPortSharing"				# Net.Tcp Port Sharing Service
		"NgcSvc"					# Microsoft Passport
		"NgcCtnrSvc"					# Microsoft Passport Container
		"OneSyncSvc"
		"p2pimsvc"					#Peer Networking Identity Manager
		"p2psvc"					# Peer Networking Grouping
		"PeerDistSvc"					# BranchCache
		"PcaSvc"					# Program Compatibility Assistant Service
		"PhoneSvc"					# Phone Service
		"PimIndexMaintenanceSvc"
		"pla"						# Performance Logs & Alerts
		"PNRPsvc"					# Peer Name Resolution Protocol
		"PolicyAgent"					# IPsec Policy Agent
		"PrintNotify"					# Printer Extensions and Notifications
		"PushToInstall"
		# "PcaSvc"					# Program compatibility assistant
		"QWAVE"						# Quality Windows Audio Video Experience
		"RasAuto"					# Remote Access Auto Connection Manager
		"RasMan"					# Remote Access Connection Manager
		"RemoteAccess"					# Routing and Remote Access
		"RemoteRegistry"				# Remote Registry
		"RetailDemo"
		"SEMgrSvc"					# Payments and NFC/SE Manager
		"SessionEnv"
		"Sgrmbroker"
		"SharedAccess"					# Internet Connection Sharing (ICS)
		"SessionEnv"					# Remote Desktop Configuration
		# "shpamsvc"
		"smphost"					# Microsoft Storage Spaces SMP
		"SmsRouter"					# Microsoft Windows SMS Router Service
		"Spooler"					# Print Spooler
		"Superfetch"					# Versions older than 1903
		"swprv"						# Microsoft Software Shadow Copy Provider
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
		"vmicheartbeat"					# Hyper-V Heartbeat Service
		"vmicrdv"					# Hyper-V Remote Desktop Virtualization Service
		"vmicshutdown"					# Hyper-V Guest Shutdown Service
		"vmictimesync"					# Hyper-V Time Synchronization Service
		"vmicvmsession"					# Hyper-V PowerShell Direct Service
		"vmicvss"					# Hyper-V Volume Shadow Copy Requestor
		"wbengine"					# Block Level Backup Engine Service
		"WbioSrvc"					# Windows Biometric Service (required for Fingerprint reader / facial detection)
		"WdiServiceHost"				# Diagnostic Service Host
		"WdiSystemHost"					# Diagnostic System Host
		"wercplsupport"					# Problem report
		"WerSvc"					# Windows report
		# "WlanSvc"					# WLAN AutoConfig (WiFi Networks)
		"WMPNetworkSvc"					# Windows Media Player Network Sharing Service
		"wisvc"						# Windows Insider service
		"wlidsvc"					# Microsoft Account Sign-in Assistant
		"WpcMonSvc"					# WpcMonSvc
		"WPDBusEnum"					# Portable Device Enumerator Service
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