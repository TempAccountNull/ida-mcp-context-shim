@echo off
setlocal
cd /d "%~dp0"
py -3 ida_mcp_export.py %*
endlocal
