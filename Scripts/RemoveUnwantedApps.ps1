$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"

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

Function DisableAppHost
{
	if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name EnableWebContentEvaluation -Value 0
}

Function DisableContentDeliveryManager
{
	if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SilentInstalledAppsEnabled -Value 0
}

Function Disable3DApps
{
	<# for /f "tokens=1* delims=" %I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Edit" ^| find /i "3D Edit" ') do (reg delete "%I" /f )
	for /f "tokens=1* delims=" %I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Print" ^| find /i "3D Print" ') do (reg delete "%I" /f ) #>
}

Function DisableEdge
{
	mv C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe_BAK
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdge.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
	Get-WindowsPackage -Online | Where PackageName -like *InternetExplorer* | Remove-WindowsPackage -Online -NoRestart
}

Function DisableOneDrive
{
	if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" DisableFileSyncNGSC -Value 1
}

Function DisablePushToInstall
{
	if (!(Test-Path "HKLM:\Software\Policies\Microsoft\PushToInstall")) {
		New-Item -Path "HKLM:\Software\Policies\Microsoft\PushToInstall" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\PushToInstall" -Name DisablePushToInstall -Value 1
}

Function DisableWindowsFunctionalities
{
	<#
	## $toRemove = 'MediaPlayback|FaxServicesClientPackage|Containers'
	## Get-WindowsOptionalFeature -Online | Where-Object { $_.State -Match "Enabled" -And $_.FeatureName -Match $toRemove } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue
	#>
	Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

Function DisableWindowsStore
{
	if (!(Test-Path "HKLM:\Software\Policies\Microsoft\WindowsStore")) {
		New-Item -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" -Name RemoveWindowsStore -Value 1
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" -Name DisableStoreApps -Value 1
}

Function PreventAppsReinstallation
{
	$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
	$registryOEM = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"

	Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1
	if (!(Test-Path $registryOEM)) {
		New-Item $registryOEM
	}
	Set-ItemProperty $registryOEM ContentDeliveryAllowed -Value 0
	Set-ItemProperty $registryOEM OemPreInstalledAppsEnabled -Value 0
	Set-ItemProperty $registryOEM PreInstalledAppsEnabled -Value 0
	Set-ItemProperty $registryOEM PreInstalledAppsEverEnabled -Value 0
	Set-ItemProperty $registryOEM SilentInstalledAppsEnabled -Value 0
	Set-ItemProperty $registryOEM SystemPaneSuggestionsEnabled -Value 0
}

Function RemoveFlash
{
	Remove-Item -LiteralPath "C:\Windows\SysWOW64\flashPlayerCPLApp.cpl" -Force
	Remove-Item -LiteralPath "C:\Windows\SysWOW64\flashPlayerApp.exe" -Force

	takeown /R /A /F "C:\Windows\System32\Macromed\"
	icacls "C:\Windows\System32\Macromed\" /grant Administrateurs:F /T /C
	Remove-Item -LiteralPath "C:\Windows\System32\Macromed\" -Force -Recurse

	takeown /R /A /F "C:\Windows\SysWOW64\Macromed\"
	icacls "C:\Windows\SysWOW64\Macromed\" /grant Administrateurs:F /T /C
	Remove-Item -LiteralPath "C:\Windows\SysWOW64\Macromed\" -Force -Recurse

	takeown /R /A /F "C:\Users\Rodolphe\AppData\Roaming\Adobe\"
	icacls "C:\Users\Rodolphe\AppData\Roaming\Adobe\" /grant Administrateurs:F /T /C
	Remove-Item -LiteralPath "C:\Users\Rodolphe\AppData\Roaming\Adobe\" -Force -Recurse

}

Function RemoveIncludedTools
{
	takeown /f "C:\Windows\helpPane.exe"
	icacls /f "C:\Windows\helpPane.exe"
	Remove-Item -LiteralPath "C:\Windows\System32\helpPane.exe" -Force

	takeown /f "C:\Windows\System32\backgroundTaskHost.exe"
	icacls "C:\Windows\System32\backgroundTaskHost.exe" /grant administrateurs:f
	Remove-Item -LiteralPath "C:\Windows\System32\backgroundTaskHost.exe" -Force

	takeown /f "C:\Windows\System32\gamebarpresencewriter.exe"
	icacls "C:\Windows\System32\gamebarpresencewriter.exe" /grant administrateurs:f
	Remove-Item -LiteralPath "C:\Windows\System32\gamebarpresencewriter.exe" -Force

	takeown /f "C:\Windows\System32\gamepanel.exe"
	icacls "C:\Windows\System32\gamepanel.exe" /grant administrateurs:f
	Remove-Item -LiteralPath "C:\Windows\System32\gamepanel.exe" -Force

	takeown /f "C:\Windows\System32\magnify.exe"
	icacls "C:\Windows\System32\magnify.exe" /grant administrateurs:f
	Remove-Item -LiteralPath "C:\Windows\System32\magnify.exe" -Force

	takeown /f "C:\Windows\System32\mblctr.exe"
	icacls "C:\Windows\System32\mblctr.exe" /grant administrateurs:f
	Remove-Item -LiteralPath "C:\Windows\System32\mblctr.exe" -Force

	takeown /f "C:\Windows\System32\mobsync.exe"
	icacls "C:\Windows\System32\mobsync.exe" /grant administrateurs:f
	Remove-Item -LiteralPath "C:\Windows\System32\mobsync.exe" -Force

	takeown /f "C:\Windows\System32\narrator.exe"
	icacls "C:\Windows\System32\narrator.exe" /grant administrateurs:f
	Remove-Item -LiteralPath "C:\Windows\System32\narrator.exe" -Force

	takeown /f "C:\Windows\System32\osk.exe"
	icacls "C:\Windows\System32\osk.exe" /grant administrateurs:f
	Remove-Item -LiteralPath "C:\Windows\System32\osk.exe" -Force

	takeown /f "C:\Windows\System32\smartscreen.exe"
	icacls "C:\Windows\System32\smartscreen.exe" /grant administrateurs:f
	Remove-Item -LiteralPath "C:\Windows\System32\smartscreen.exe" -Force

	takeown /f "C:\Windows\System32\WSClient.dll"
	icacls "C:\Windows\System32\WSClient.dll" /grant administrateurs:f
	Remove-Item -LiteralPath "C:\Windows\System32\WSClient.dll" -Force

	takeown /f "C:\Windows\System32\WSCollect.exe"
	icacls "C:\Windows\System32\WSCollect.exe" /grant administrateurs:f
	Remove-Item -LiteralPath "C:\Windows\System32\WSCollect.exe" -Force
}

Function RemoveSystemApps
{
        $whitelistedApps = 'ShellExperienceHost|LockApp'
        $folders = Get-ChildItem "C:\Windows\SystemApps\"

        ForEach ($folder in $folders) {
		taskkill /F /IM SearchUI.exe
		taskkill /F /IM StartMenuExperienceHost.exe
                $current = "C:\Windows\SystemApps\" + $folder.name
                takeown /R /A /F $current /D N
                icacls $current /grant Administrateurs:F /T /C
		if ($current -NotMatch $whitelistedApps) {
			Remove-Item -LiteralPath $current -Force -Recurse
		}
        }
}

Function RemoveWindowsApps
{
	$toDelete = 'Deleted|Deleted|Xaml|Mutable|Moved'
	$folders = Get-ChildItem "C:\Program Files\WindowsApps"

	ForEach ($folder in $folders) {
		$current = "C:\Program Files\WindowsApps\" + $folder.name
                takeown /R /A /F $current /D N
                icacls $current /grant Administrateurs:F /T /C
		if ($current -Match $toDelete) {
			Remove-Item -LiteralPath $current -Force -Recurse
		}
        }
}

Function ReinstallWindowsPhotoViewer
{
	reg import .\ReinstallPhotoViewer.reg
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

Function UninstallPreloadedSoft
{
	$apps = Get-WmiObject Win32_Product | Where-Object {
		$_.Name -NotLike "*intel*" -and
		$_.Name -NotLike "*synaptics*" -and
		$_.Name -NotLike "*workspace" -and
		$_.Name -NotLike "*audio*" -and
		$_.Name -NotLike "*network*" -and
		$_.Name -Notlike "*amd*" -and
		$_.Name -NotLike "*nvidia*"
	}
	$apps.uninstall()
}

Function UninstallOneDrive
{
	BackupOneDriveFiles
	DisableOneDrive
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

Function UninstallUnwantedUWP
{
	$WhitelistedApps = 'Microsoft.WindowsCalculator|Microsoft.MSPaint|.NET|Framework|Microsoft.ScreenSketch|Microsoft.WindowsAlarms'
	$NonRemovable = '1527c705-839a-4832-9118-54d4Bd6a0c89|c5e2524a-ea46-4f67-841f-6a9465d9d515|E2A4F912-2574-4A75-9BB0-0D023378592B|F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE|InputApp|Microsoft.AAD.BrokerPlugin|Microsoft.AccountsControl|`
	Microsoft.BioEnrollment|Microsoft.CredDialogHost|Microsoft.ECApp|Microsoft.LockApp|Microsoft.MicrosoftEdgeDevToolsClient|Microsoft.MicrosoftEdge|Microsoft.PPIProjection|Microsoft.Win32WebViewHost|Microsoft.Windows.Apprep.ChxApp|`
	Microsoft.Windows.AssignedAccessLockApp|Microsoft.Windows.CapturePicker|Microsoft.Windows.CloudExperienceHost|Microsoft.Windows.ContentDeliveryManager|Microsoft.Windows.Cortana|Microsoft.Windows.NarratorQuickStart|`
	Microsoft.Windows.ParentalControls|Microsoft.Windows.PeopleExperienceHost|Microsoft.Windows.PinningConfirmationDialog|Microsoft.Windows.SecHealthUI|Microsoft.Windows.SecureAssessmentBrowser|Microsoft.Windows.ShellExperienceHost|`
	Microsoft.Windows.XGpuEjectDialog|Microsoft.XboxGameCallableUI|Windows.CBSPreview|windows.immersivecontrolpanel|Windows.PrintDialog|Microsoft.VCLibs.140.00|Microsoft.Services.Store.Engagement|Microsoft.UI.Xaml.2.0'

	Get-AppxPackage -AllUsers | Where-Object { $_.Name -NotMatch $WhitelistedApps -and $_.Name -NotMatch $NonRemovable } | Remove-AppxPackage | Out-Null
	Get-AppxPackage | Where-Object { $_.Name -NotMatch $WhitelistedApps -and $_.Name -NotMatch $NonRemovable } | Remove-AppxPackage | Out-Null
	Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -NotMatch $WhitelistedApps -and $_.PackageName -NotMatch $NonRemovable } | Remove-AppxProvisionedPackage -Online | Out-Null
}

DisableAppHost
DisableContentDeliveryManager
DisableEdge
DisablePushToInstall
DisableWindowsStore
DisableWindowsFunctionalities
PreventAppsReinstallation
ReinstallWindowsPhotoViewer
RemoveAssociatedRegitryKeys
RemoveFlash
RemoveIncludedTools
RemoveSystemApps
RemoveWindowsApps
UninstallOneDrive
UninstallPreloadedSoft
UninstallUnwantedUWP