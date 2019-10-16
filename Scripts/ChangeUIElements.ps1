$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"

Function DisableActionCenter
{
	if (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "SOFTWARE\Policies\Microsoft\Windows\Explorer" DisableNotificationCenter -Value 1
}

Function DisableStickyKeys
{
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" Flags -Value "506"
}

Function DisableThumbsDB
{
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" DisableThumbnailCache -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" DisableThumbsDBOnNetworkFolders -Value 1
}

Function DisableTips
{
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" DisableSoftLanding -Value 1
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" DisableWindowsSpotlightFeatures -Value 1
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" DisableWindowsConsumerFeatures -Value 1
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" DoNotShowFeedbackNotifications -Value 1
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace" AllowSuggestedAppsInWindowsInkWorkspace -Value 0
}

Function DisableTransparency
{
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" EnableTransparency -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" DisableAcrylicBackgroundOnLogon -Value 1
}

Function EnableBlackTheme
{
	if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" AppsUseLightTheme -Value 0
	if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" AppsUseLightTheme -Value 0
}

Function EnableNumlockAtStartup
{
	if (!(Test-Path "HKU:")) {
		New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
	Add-Type -AssemblyName System.Windows.Forms
	if (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
}

Function Hide3DObjectsFromThisPC
{
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
}

Function HideRecentShortcuts
{
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" ShowRecent -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" ShowFrequent -Value 0
}

Function HideSyncNotifications
{
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0
}

Function HideTaskbarPeopleIcon
{
	if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" PeopleBand -Value 0
}

Function HideTaskbarSearch
{
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
}

Function HideTaskView
{
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
}

Function SetExplorerThisPC
{
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" LaunchTo -Value 1
}

Function SetVisualFXPerformance
{
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
}

Function ShowKnownExtensions
{
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" HideFileExt -Value 0
}

Function ShowTaskManagerDetails
{
	$taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
	do {
		Start-Sleep -Milliseconds 100
		$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
	} until ($preferences)
	Stop-Process $taskmgr
	$preferences.Preferences[28] = 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" Preferences -Value $preferences.Preferences
}

Function UnpinStartMenuIcons
{
	if ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 16299) {
		Get-ChildItem -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Include "*.group" -Recurse | ForEach-Object {
			$data = (Get-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data").Data -Join ","
			$data = $data.Substring(0, $data.IndexOf(",0,202,30") + 9) + ",0,202,80,0,0"
			Set-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data" -Type Binary -Value $data.Split(",")
		}
	} ElseIf ([System.Environment]::OSVersion.Version.Build -eq 17133) {
		$key = Get-ChildItem -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Recurse | Where-Object { $_ -like "*start.tilegrid`$windows.data.curatedtilecollection.tilecollection\Current" }
		$data = (Get-ItemProperty -Path $key.PSPath -Name "Data").Data[0..25] + ([byte[]](202,50,0,226,44,1,1,0,0))
		Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $data
	}
}

Function UnpinTaskbarIcons
{
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" Favorites -Value ([byte[]](255))
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesResolve" -ErrorAction SilentlyContinue
}

DisableActionCenter
DisableStickyKeys
DisableThumbsDB
DisableTips
DisableTransparency
EnableBlackTheme
EnableNumlockAtStartup
Hide3DObjectsFromThisPC
HideRecentShortcuts
HideSyncNotifications
HideTaskbarPeopleIcon
HideTaskbarSearch
HideTaskView
SetExplorerThisPC
SetVisualFXPerformance
ShowKnownExtensions
ShowTaskManagerDetails
UnpinStartMenuIcons
# UnpinTaskbarIcons