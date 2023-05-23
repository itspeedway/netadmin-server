@echo off
cd /d %~dp0

REM # GET CURRENT BUILD
for /f "delims=" %%a in (version.txt) do (
    set verhi=%%a
    set verlo=%%b
    set build=%%c
)
if "%verhi"=="" set verhi=0
if "%verhi"=="" set verhi=0
if "%verhi"=="" set verhi=0

REM # INCREMENT BUILD VERSION
set /i build=build+1
set version=%verhi%.%verlo%.%build%

REM # UPDATE BUILD
del v*.ver
echo %version%>version.txt
echo v%version%.ver:
echo v%version%>v%version%.ver

REM # TEST-RUN
venv\scripts\python netadmin_api_server.py %*

