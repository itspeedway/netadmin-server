@echo off
cd /d %~dp0

venv\scripts\python netadmin_api_server.py %*

