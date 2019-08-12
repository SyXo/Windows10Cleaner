@echo off

set "params=%*"
cd /d "%~dp0" && ( if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs" ) && fsutil dirty query %systemdrive% 1>nul 2>nul || (  echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd ""%~sdp0"" && %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs" && "%temp%\getadmin.vbs" && exit /B )

set LOGFILE=%SystemDrive%\WindowsCleaner.log
echo. 2> %LOGFILE%

echo Changing power settings >> %LOGFILE%
start "" /b /wait powershell -executionpolicy bypass -file "ChangePowerSettings.ps1" >> %LOGFILE%

echo Getting privacy back >> %LOGFILE%
start "" /b /wait powershell -executionpolicy bypass -file "ChangePrivacySettings.ps1" >> %LOGFILE%

echo Tweaking UI elements >> %LOGFILE%
start "" /b /wait powershell -executionpolicy bypass -file "ChangeUIElements.ps1" >> %LOGFILE%

echo Disabling unwanted services >> %LOGFILE%
start "" /b /wait powershell -executionpolicy bypass -file "DisableUnwantedServices.ps1" >> %LOGFILE%

echo Disabling unwanted background tasks >> %LOGFILE%
start "" /b /wait powershell -executionpolicy bypass -file "DisableUnwantedTasks.ps1" >> %LOGFILE%

echo Speeding us the computer >> %LOGFILE%
start "" /b /wait powershell -executionpolicy bypass -file "Optimisation.ps1" >> %LOGFILE%

echo Removing unwanted bloatware >> %LOGFILE%
start "" /b /wait powershell -executionpolicy bypass -file "RemoveUnwantedApps.ps1" >> %LOGFILE%