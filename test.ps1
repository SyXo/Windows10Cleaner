$PCI = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\PCI"

ForEach ($element in $PCI) {
	$Key = $element.Name -replace "HKEY_LOCAL_MACHINE", "HKLM:"
	$Subkey = Get-ChildItem $Key
	$Subkey = $Subkey -replace "HKEY_LOCAL_MACHINE", "HKLM:"
	$value = Get-ItemProperty -Path $Subkey -Name "DeviceDesc"
	if ($value -match "amd" -or $value -match "nvidia" -or $value -match "audio") {
		$msi = $Subkey + "\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
		if (!(Test-Path $msi)) {
			New-Item -Path $msi | Out-Null
			New-ItemProperty -Path $msi -Name MSISupported
		}
		Set-ItemProperty -Path $msi MSISupported -Value 1
	}
}