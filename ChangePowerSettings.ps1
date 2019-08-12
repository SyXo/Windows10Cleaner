$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"

Function ChangePowerPlan
{
	powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 # Ultimate performance
	powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61
	powercfg -CHANGE -disk-timeout-ac 0
	powercfg -CHANGE -disk-timeout-dc 0
	# powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c #High performance
}

Function ChangeSleepTimeout
{
	powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK 300
	powercfg /X monitor-timeout-ac 5
	powercfg /X monitor-timeout-dc 5
	powercfg /X standby-timeout-ac 0
	powercfg /X standby-timeout-dc 240
}

Function DisableFastBoot
{
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" HiberbootEnabled -Value 0
}

Function DisableHibernation
{
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" HibernateEnabled -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0
}

Function EnhanceBootSequence
{
	bcdedit /timeout 10
	bcdedit /set {current} quietboot No
}

ChangeSleepTimeout
ChangePowerPlan
DisableFastBoot
DisableHibernation
EnhanceBootSequence