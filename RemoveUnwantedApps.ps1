$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"

Function DisableOneDrive
{
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" DisableFileSyncNGSC -Value 1
}

Function BackupOneDriveFiles
{
	if (Test-Path "$env:USERPROFILE\OneDrive\") {
		New-item -Path "$env:USERPROFILE\Desktop" -Name "OneDriveBackupFiles"-ItemType Directory -Force
		Move-Item -Path "$env:USERPROFILE\OneDrive\" -Destination "$env:USERPROFILE\Desktop\OneDriveBackupFiles" -Force
	} else {
		$OneDriveKey = 'HKLM:Software\Policies\Microsoft\Windows\OneDrive'
		if (!(Test-Path $OneDriveKey)) {
			Mkdir $OneDriveKey
			Set-ItemProperty $OneDriveKey -Name OneDrive -Value DisableFileSyncNGSC
		}
		Set-ItemProperty $OneDriveKey -Name OneDrive -Value DisableFileSyncNGSC
	}
}

Function UninstallOneDrive
{
	BackupOneDriveFiles
	Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	if (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
	Start-Sleep -s 2
	Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
	if (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
}

Function UninstallAllButWhitelisted
{
	$WhitelistedApps = 'Microsoft.WindowsCalculator|Microsoft.WindowsStore|Microsoft.Windows.Photos|Microsoft.MSPaint|Microsoft.WindowsCamera|.NET|Framework'
	$NonRemovable = '1527c705-839a-4832-9118-54d4Bd6a0c89|c5e2524a-ea46-4f67-841f-6a9465d9d515|E2A4F912-2574-4A75-9BB0-0D023378592B|F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE|InputApp|Microsoft.AAD.BrokerPlugin|Microsoft.AccountsControl|`
	Microsoft.BioEnrollment|Microsoft.CredDialogHost|Microsoft.ECApp|Microsoft.LockApp|Microsoft.MicrosoftEdgeDevToolsClient|Microsoft.MicrosoftEdge|Microsoft.PPIProjection|Microsoft.Win32WebViewHost|Microsoft.Windows.Apprep.ChxApp|`
	Microsoft.Windows.AssignedAccessLockApp|Microsoft.Windows.CapturePicker|Microsoft.Windows.CloudExperienceHost|Microsoft.Windows.ContentDeliveryManager|Microsoft.Windows.Cortana|Microsoft.Windows.NarratorQuickStart|`
	Microsoft.Windows.ParentalControls|Microsoft.Windows.PeopleExperienceHost|Microsoft.Windows.PinningConfirmationDialog|Microsoft.Windows.SecHealthUI|Microsoft.Windows.SecureAssessmentBrowser|Microsoft.Windows.ShellExperienceHost|`
	Microsoft.Windows.XGpuEjectDialog|Microsoft.XboxGameCallableUI|Windows.CBSPreview|windows.immersivecontrolpanel|Windows.PrintDialog|Microsoft.VCLibs.140.00|Microsoft.Services.Store.Engagement|Microsoft.UI.Xaml.2.0'

	Get-AppxPackage -AllUsers | Where-Object {$_.Name -NotMatch $WhitelistedApps -and $_.Name -NotMatch $NonRemovable} | Remove-AppxPackage | Out-Null
	Get-AppxPackage | Where-Object {$_.Name -NotMatch $WhitelistedApps -and $_.Name -NotMatch $NonRemovable} | Remove-AppxPackage | Out-Null
	Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -NotMatch $WhitelistedApps -and $_.PackageName -NotMatch $NonRemovable} | Remove-AppxProvisionedPackage -Online | Out-Null
}

Function UninstallMicrosoftIncludedApps
{
	$Apps = @(
		"Microsoft.3DBuilder"
		"Microsoft.AppConnector"
		"Microsoft.BingFinance"
		"Microsoft.BingNews"
		"Microsoft.BingSports"
		"Microsoft.BingTranslator"
		"Microsoft.BingWeather"
		"Microsoft.CloudExperienceHost"
		"Microsoft.CommsPhone"
		"Microsoft.ConnectivityStore"
		"Microsoft.GetHelp"
		"Microsoft.Getstarted"
		"Microsoft.HEIFImageExtension"
		"Microsoft.Messaging"
		"Microsoft.Microsoft3DViewer"
		"Microsoft.MicrosoftOfficeHub"
		"Microsoft.MicrosoftPowerBIForWindows"
		"Microsoft.MicrosoftSolitaireCollection"
		"Microsoft.MicrosoftStickyNotes"
		"Microsoft.MinecraftUWP"
		"Microsoft.MixedReality.Portal"
		# "Microsoft.MSPaint"
		"Microsoft.NetworkSpeedTest"
		"Microsoft.Office.Excel"
		"Microsoft.Office.OneNote"
		"Microsoft.Office.PowerPoint"
		"Microsoft.Office.Sway"
		"Microsoft.Office.Word"
		"Microsoft.OneConnect"
		"Microsoft.People"
		"Microsoft.Print3D"
		"Microsoft.RemoteDesktop"
		"Microsoft.Services.Store.Engagement"
		# "Microsoft.ScreenSketch"
		"Microsoft.SolitareCollection"
		"Microsoft.StickyNotes"
		"Microsoft.StorePurchaseApp"
		"Microsoft.SkypeApp"
		"Microsoft.VP9VideoExtensions"
		"Microsoft.Wallet"
		"Microsoft.WebMediaExtensions"
		"Microsoft.WebpImageExtension"
		# "Microsoft.WindowsAlarms"
		"Microsoft.WindowsCamera"
		# "Microsoft.WindowsCalculator"
		"Microsoft.Windows.ContactSupport"
		"Microsoft.Windows.Cortana"
		"Microsoft.Windows.HolographicFirstRun"
		"microsoft.windowscommunicationsapps"
		"Microsoft.WindowsFeedbackHub"
		"Microsoft.WindowsFeedback"
		"Microsoft.WindowsMaps"
		"Microsoft.Windows.ParentalControls"
		"Microsoft.Windows.PeopleExperienceHost"
		"Microsoft.WindowsPhone"
		# "Microsoft.Windows.Photos"
		"Microsoft.Windows.SecHealthUI"
		"Microsoft.WindowsSoundRecorder"
		# "Microsoft.WindowsStore"
		"Microsoft.Xbox.TCUI"
		"Microsoft.XboxApp"
		"Microsoft.XboxGameCallableUI"
		"Microsoft.XboxGameOverlay"
		"Microsoft.XboxGamingOverlay"
		"Microsoft.XboxIdentityProvider"
		"Microsoft.XboxSpeechToTextOverlay"
		"Microsoft.YourPhone"
		"Microsoft.ZuneMusic"
		"Microsoft.ZuneVideo"
	)
	ForEach ($App in $Apps) {
		Get-AppxPackage -AllUsers -Name $App | Remove-AppxPackage
		Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online
	}
}

Function UninstallInternetExplorer
{
	Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

Function UninstallWindowsStoreApps
{
	$Apps = @(
		"ACGMediaPlayer"
		"ActiproSoftwareLLC"
		"AdobePhotoshopExpress"
		"AutodeskSketchBook"
		"Asphalt8Airborne"
		"BubbleWitch3Saga"
		"CandyCrushSodaSaga"
		"CyberLinkMediaSuiteEssentials"
		"DisneyMagicKingdoms"
		"DolbyAccess"
		"Drawboard"
		"Duolingo-LearnLanguagesforFree"
		"EclipseManager"
		"Facebook"
		"FarmVille2CountryEscape"
		"HiddenCityMysteryofShadows"
		"Keeper"
		"LinkedInforWindows"
		"MarchofEmpires"
		"Netflix"
		"OneCalendar"
		"PandoraMediaInc"
		"Plex"
		"RoyalRevolt2"
		"SpotifyMusic"
		"Twitter"
		"Viber"
		"WinZipUniversal"
		"XING"
	)
	ForEach ($App in $Apps) {
		Get-AppxPackage -AllUsers -Name $App | Remove-AppxPackage
		Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online
	}
}

Function RemoveAssociatedRegitryKeys
{
	$Keys = @(
		# Remove Background Tasks
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"

		# Windows File
		"HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            
		# Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
		"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
		"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
		"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
		# Scheduled Tasks to delete
		"HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"

		# Windows Protocol Keys
		"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
		"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"

		# Windows Share Target
		"HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
	)
	ForEach ($Key in $Keys) {
		Remove-Item $Key -Recurse | Out-Null
	}
}

Function PreventAppsReinstallation
{
	$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
	$registryOEM = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"

	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore"
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate"
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" AutoDownload -Value 2
	If (!(Test-Path $registryPath)) { 
		New-Item $registryPath
	}
	Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1 
	If (!(Test-Path $registryOEM)) {
		New-Item $registryOEM
	}
	Set-ItemProperty $registryOEM ContentDeliveryAllowed -Value 0 
	Set-ItemProperty $registryOEM OemPreInstalledAppsEnabled -Value 0 
	Set-ItemProperty $registryOEM PreInstalledAppsEnabled -Value 0 
	Set-ItemProperty $registryOEM PreInstalledAppsEverEnabled -Value 0 
	Set-ItemProperty $registryOEM SilentInstalledAppsEnabled -Value 0 
	Set-ItemProperty $registryOEM SystemPaneSuggestionsEnabled -Value 0          
}

DisableOneDrive
#UninstallMicrosoftIncludedApps
#UninstallWindowsStoreApps
PreventAppsReinstallation
RemoveAssociatedRegitryKeys
UninstallAllButWhitelisted
UninstallInternetExplorer
UninstallOneDrive