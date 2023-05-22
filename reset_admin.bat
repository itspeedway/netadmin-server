@echo off
echo ADMIN ACCOUNT RESET
echo.

set /p username=Admin account ^(admin^): 
if "%username%"=="" set username=admin

:retry
set /p password=Password for %username%: 
set /p repeat=Retype password: 
if not "%password%"=="%repeat%" (
    echo ERROR: Password mismatch!
    echo.
    goto retry
)
venv\scripts\python netadmin_api_server.py --reset %username% %password%

