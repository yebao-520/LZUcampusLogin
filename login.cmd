@echo off
chcp 65001 >nul
python "%~dp0campus_login.py"
if errorlevel 1 pause
