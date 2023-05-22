@echo off
SETLOCAL ENABLEDELAYEDEXPANSION
SET SERVICE=netadmin_api_server
SET DESCRIPTION=Netadmin API Server

cd /d %~dp0
call :heading
if exist "%CD%\!SERVICE!.py" goto menu
	echo.
	echo "%CD%\!SERVICE!.py" does not exist
	pause >NUL
goto exit

:heading
cls
echo !DESCRIPTION!
echo -------------
goto :EOF

:menu
echo.
echo STATUS:
nssm status !SERVICE!
echo.
echo 1 - Install
echo 2 - Un-install
echo 3 - Start Service    [START]
echo 4 - Stop Service     [STOP]
echo 5 - Restart Service  [RESTART]
echo 6 - service status
echo x - Exit
echo.

choice /C 123456x /T 10 /D 6 /M Action? /CS /N
set ACTION=%ERRORLEVEL%
call :heading
echo.
if "!ACTION!"=="1" (
	echo INSTALLING...
	nssm install !SERVICE! "%CD%\venv\scripts\python.exe" "%CD%\!SERVICE!.py"
	echo Configuring...
	nssm set !SERVICE! AppDirectory "%CD%"
	nssm set !SERVICE! Description "!DESCRIPTION!"
	echo Done!
)
if "!ACTION!"=="2" (
	echo UNINSTALL...
	nssm remove !SERVICE! confirm
)
if "!ACTION!"=="3" (
	echo STARTING SERVICE
	nssm start !SERVICE!
)
if "!ACTION!"=="4" (
	echo STOPPING SERVICE
	nssm stop !SERVICE!
)
if "!ACTION!"=="5" (
	echo RESTARTING SERVICE
	nssm restart !SERVICE!
)
if "!ACTION!"=="7" goto :exit

goto :menu
:exit


