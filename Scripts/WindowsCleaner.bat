@echo off

:: BatchGotAdmin
:-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------

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