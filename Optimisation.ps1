$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"

Function DetectRamQuantity
{
    $PhysicalRAM = (Get-WMIObject -class Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.sum / 1GB), 2)})

    return ($PhysicalRAM)
}

Function DisableBackgroundApps
{
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" GlobalUserDisabled -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" BackgroundAppGlobalToggle -Value 0
}

Function DisableDefender
{
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
}

Function DisableDefenderCloud
{
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2
}

Function DisableEdgeBackground
{
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge" -Force | Out-Null
	}
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Force | Out-Null
	}
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" AllowPrelaunch -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" AllowTabPreloading -Value 0
}

Function DisableFirewall
{
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" EnableFirewall -Value 0
}

Function DisableHPET
{
	bcdedit /deletevalue useplatformclock
	bcdedit /set disabledynamictick Yes
}

Function DisableNdu
{
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Ndu" Start -Value 4
}

Function DisablePrefetch
{
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" EnablePrefetcher -Value 0
}

Function DisableUpdateMSRT
{
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 1
}

Function DisableWindowsFunctionalities
{
	$toRemove = 'MediaPlayback|FaxServicesClientPackage|Containers'
	Get-WindowsOptionalFeature -Online | Where-Object { $_.State -Match "Enabled" -And $_.FeatureName -Match $toRemove } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue
}

Function DisableXboxFunctionnalities
{
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" GameDVR_Enabled -Value 0
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" AllowGameDVR -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" AppCaptureEnabled -Value 0
}

Function ExploitRamQuantity
{
	$ram = DetectRamQuantity
	$path = "HKLM:\SYSTEM\ControlSet001\Control"

	$result = switch ($ram) {
		{$_ -lt 6} { 4194304 }
		{$_ -ge 6 -and $_ -lt 8} { 6291456 }
		{$_ -ge 8 -and $_ -lt 12} { 8388608 }
		{$_ -ge 12 -and $_ -lt 16} { 12582912 }
		{$_ -ge 16 -and $_ -lt 24} { 16777216 }
		{$_ -ge 24 -and $_ -lt 32} { 25165824 }
		{$_ -ge 32 -and $_ -lt 64} { 33554432 }
		{$_ -ge 64} { 67108864 }
		default { 380000 }
	}
	$result = [convert]::toint64($result, 16)
	Set-ItemProperty -Path $path SvcHostSplitThresholdInKB -Value $result
}

Function ImproveResponsiveness
{
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" SystemResponsiveness -Value 0
}

Function RemoveTempFiles
{
	Remove-Item "C:\Windows\Temp\*" -Recurse -Force
	Remove-Item "C:\Windows\Prefetch\*" -Recurse -Force
	Remove-Item "C:\Documents and Settings\*\Local Settings\temp\*" -Recurse -Force
	Remove-Item "C:\Users\*\Appdata\Local\Temp\*" -Recurse -Force
}

Function RemoveXboxRelatedExe
{
	takeown /f "C:\Windows\System32\GamePanel.exe"
	icacls "C:\Windows\System32\GamePanel.exe" /grant administrateurs:f
	Remove-Item -Path "C:\Windows\System32\GamePanel.exe" -Force

	takeown /f "C:\Windows\System32\GameBarPresenceWriter.exe"
	icacls "C:\Windows\System32\GameBarPresenceWriter.exe" /grant administrateurs:f
	Remove-Item -Path "C:\Windows\System32\GameBarPresenceWriter.exe" -Force
}

DetectRamQuantity
DisableBackgroundApps
DisableDefender
DisableDefenderCloud
DisableEdgeBackground
DisableFirewall
DisableHPET
DisableNdu
DisablePrefetch
DisableUpdateMSRT
DisableWindowsFunctionalities
DisableXboxFunctionnalities
ExploitRamQuantity
ImproveResponsiveness
RemoveXboxRelatedExe
RemoveTempFiles