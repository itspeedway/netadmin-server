@echo off
cd /d %~dp0

REM # GET CURRENT BUILD
for /f "delims=" %%a in (version.txt) do (
    set verhi=%%a
    set verlo=%%b
    set build=%%c
    set release=%%d
)
if "%verhi%"=="" set verhi=0
if "%verlo%"=="" set verlo=0
if "%build%"=="" set build=0
if "%release%"=="" set release=DEV

REM # INCREMENT BUILD VERSION
if "%1"=="-i" set /i build=build+1
set version=%verhi%.%verlo%.%build%.%release%

REM # UPDATE BUILD
del v*.ver
echo %version%>version.txt
echo v%version%>v%version%.ver

REM # TEST-RUN
venv\scripts\python netadmin_api_server.py %*

