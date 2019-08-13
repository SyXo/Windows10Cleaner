$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"

Function DisableUnwantedScheduledTasks
{
	schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /disable
	schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable
	schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
	schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
	schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable
	schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
	schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
	schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
	schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
	schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
	schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
	schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
	schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable
	schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
	schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /disable
	schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /disable
	schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
	schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
	schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /disable
	schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /disable
	schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
	schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable
	schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /disable
	schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /disable
	schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /disable
	schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
	schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /disable
	schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /disable
	schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
	schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /disable
	schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /disable
	schtasks /Change /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" /disable
	schtasks /Change /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" /disable
	schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /disable
	schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /disable
	schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
	schtasks /Change /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /disable
	schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /disable
}

Function DisableAutoWindowsUpdate
{
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" NoAutoUpdate -Value 1
}

Function DisableWindowsUpgrade
{
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsUpdate" DisableOSUpgrade -Value 1
	if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade"
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade" AllowOSUpgrade -Value 0
}

DisableUnwantedScheduledTasks
DisableAutoWindowsUpdate
DisableWindowsUpgrade