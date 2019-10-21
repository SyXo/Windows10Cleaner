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
		#"BluetoothUserService"
		#"BTAGService"					# Bluetooth Audio Gateway Service
		#"bthserv"					# Bluetooth Support Service
		#"BthHFSrv"					# Bluetooth Handsfree Service
		"CaptureService"
		"CDPSvc"					# Connected Devices Platform Service
		"CDPUserSvc"
		"CertPropSvc"					# Certificate Propagation
		"ClipSVC"					# Client License Service (ClipSVC)
		"ConsentUxUserSvc"
		"CscService"					# Offline Files
		"defragsvc"					# Optimise drives
		"DevicesFlowUserSvc"				# Allows ConnectUX and PC Settings to Connect and Pair with WiFi displays and Bluetooth devices
		"DevicePickerUserSvc"
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
		"FontCache"					# Windows Font Cache Service
		"FontCache3.0.0.0"				# Windows Presentation Foundation Font Cache 3.0.0.0
		"FrameServer"					# Windows Camera Framer Server
		"GraphicsPerfSvc"				# GraphicsPerfSvc
		"hns"						# Host Network Service
		"HomeGroupListener"				# HomeGroup Listener
		"HomeGroupProvider"				# HomeGroup Provider
		"HvHost"					# HV Host Service
		"icssvc"					# Windows Mobile Hotspot Service
		"IEEtwCollectorService"				# Internet Explorer ETW Collector Service
		"iphlpsvc"					# IP Helper
		"IpxlatCfgSvc"					# IP Translation Configuration Service
		"InstallService"				# Microsoft Store Install Service
		"irmon"						# Infrared monitor service
		"KeyIso"					# CNG Key Isolation
		"LanmanServer"					# File, print, and named-pipe sharing over the network
		"LanmanWorkstation"				# Creates and maintains client network connections to remote servers using the SMB protocol
		"lfsvc"						# Geolocation Service
		"LicenseManager"				# License Manager Service
		"lltdsvc"					# Link-Layer Topology Discovery Mapper
		"lmhosts"					# TCP/IP NetBIOS Helper
		"MapsBroker"					# Downloaded Maps Manager
		"MessagingService"
		"MSDTC"						# Distributed Transaction Coordinator
		"MSiSCSI"					# Microsoft iSCSI Initiator Service
		"NaturalAuthentication"				# Natural Authentification
		#"NcaSvc"					# Network Connectivity Assistant
		#"NcbService"					# Network Connection Broker
		#"NcdAutoSetup"					# Network Connected Devices Auto-Setup
		"ndu"						# Windows Network Data Usage Monitor
		#"Netlogon"					# Netlogon
		"NetTcpPortSharing"				# Net.Tcp Port Sharing Service
		"NgcSvc"					# Microsoft Passport
		"NgcCtnrSvc"					# Microsoft Passport Container
		"OneSyncSvc"
		"p2pimsvc"					# Peer Networking Identity Manager
		"p2psvc"					# Peer Networking Grouping
		"PcaSvc"					# Program Compatibility Assistant Service
		"PeerDistSvc"					# BranchCache
		"perceptionsimulation"				# Windows Perception Simulation Service
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
		"RetailDemo"					# Retail Demo Service
		"RmSvc"						# Radio Management Service
		"RpcLocator"					# Remote Procedure Call (RPC) Locator
		"SamSs"						# Security Accounts Manager
		"SCardSvr"					# Smart Card
		"ScDeviceEnum"					# Smart Card Device Enumeration Service
		"SCPolicySvc"					# Smart Card Removal Policy
		"SDRSVC"					# Windows backup
		"seclogon"					# Secondary Logon
		"SecurityHealthService"				# Windows Defender Security Center Service
		"SEMgrSvc"					# Payments and NFC/SE Manager
		"Sense"						# Senses
		"SensorDataService"				# Sensor Data Service
		"SensorService"					# Sensor Service
		"SensrSvc"					# Sensor Monitoring Service
		"SessionEnv"					# Remote Desktop Configuration
		"smphost"					# Microsoft Storage Spaces SMP
		"SgrmBroker"					# System Guard Runtime Monitor Broker
		"SharedAccess"					# Internet Connection Sharing (ICS)
		"SharedRealitySvc"				# Spatial Data Service
		"ShellHWDetection"				# Shell Hardware Detection
		"shpamsvc"					# Shared PC Account Manager
		"SmsRouter"					# Microsoft Windows SMS Router Service
		"SNMPTRAP"					# SNMP Trap
		"Spectrum"					# Windows Perception Service
		"Spooler"					# Print Spooler
		"StiSvc"					# Windows Image Acquisition
		"StorSvc"					# Storage Service
		"Superfetch"					# Versions older than 1903
		"swprv"						# Microsoft Software Shadow Copy Provider
		"SysMain"					# Superfetch's name on 1903+
		"TabletInputService"				# Touch Keyboard and Handwriting Panel Service
		"TapiSrv"					# Telephony
		"TermService"					# Remote Desktop Services
		"TieringEngineService"				# Storage Tiers Management
		"tiledatamodelsvc"				# Tile Data model server
		"TokenBroker"					# Web Account Manager
		"Themes"					# Themes
		"TrkWks"					# Distributed Link Tracking Client
		"TroubleshootingSvc"
		"tzautoupdate"					# Auto Time Zone Updater
		"UevAgentService"				# User Experience Virtualization Service
		"UmRdpService"					# Remote Desktop Services UserMode Port Redirector
		"UnistoreSvc"					# User Data Storage
		"UserDataSvc"					# Provides apps access to structured user data, including contact info, calendars, messages, and other content
		"UsoSvc"					# Update Orchestrator Service
		"VaultSvc"					# Credential Manager
		"vmickvpexchange"				# Hyper-V Data Exchange Service
		"vmicguestinterface"				# Hyper-V Guest Service Interface
		"vmicheartbeat"					# Hyper-V Heartbeat Service
		"vmicrdv"					# Hyper-V Remote Desktop Virtualization Service
		"vmicshutdown"					# Hyper-V Guest Shutdown Service
		"vmictimesync"					# Hyper-V Time Synchronization Service
		"vmicvmsession"					# Hyper-V PowerShell Direct Service
		"vmicvss"					# Hyper-V Volume Shadow Copy Requestor
		"VSS"						# Volume Shadow Copy
		"W32Time"					# Windows Time
		"WalletService"					# Wallet Service
		"WaaSMedicSVC"					# Windows Update Medic Service
		"wbengine"					# Block Level Backup Engine Service
		"WbioSrvc"					# Windows Biometric Service (required for Fingerprint reader / facial detection)
		"wcncsvc"					# Windows Connect Now - Config Registrar
		"WdNisSvc"					# Windows Defender Antivirus Network Inspection Service
		"WdiServiceHost"				# Diagnostic Service Host
		"WdiSystemHost"					# Diagnostic System Host
		"WebClient"					# Web client
		"Wecsvc"					# Windows Event Collector
		"WEPHOSTSVC"					# Windows Encryption Provider Host Service
		"wercplsupport"					# Problem report
		"WerSvc"					# Windows report
		# "WFDSConMgrSvc"				# Wi-Fi Direct Services Connection Manager Service
		# "WlanSvc"					# WLAN AutoConfig (WiFi Networks)
		"wisvc"						# Windows Insider service
		"WinDefend"					# Windows Defender Antivirus Service
		"WinRM"						# Windows Remote Management
		"wlidsvc"					# Microsoft Account Sign-in Assistant
		"wmiApSrv"					# WMI Performance Adapter
		"WMPNetworkSvc"					# Windows Media Player Network Sharing Service
		"WpcMonSvc"					# WpcMonSvc
		"WPDBusEnum"					# Portable Device Enumerator Service
		"WpnService"
		"WpnService"					# Windows Push Notifications System Service
		"wscsvc"					# Windows Security Center Service
		"WSearch"					# Windows Search
		"wuauserv"					# Windows Update
		"WwanSvc"					# WWAN AutoConfig
		"WSearch"					# Windows Search
		"xbgm"						# Xbox Game Monitoring
		"XblAuthManager"				# Xbox Live Auth Manager
		"XblGameSave"					# Xbox Live Game Save Service
		"XboxGipSvc"					# Xbox Accessory Management Service
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
	reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" /v Start /t REG_DWORD /d 00000004 /f

	# regini .\TakeKeyOwnership
}

DisableUnwantedServices
FurtherDeleting