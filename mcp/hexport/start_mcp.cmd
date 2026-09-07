@echo off
setlocal
rem Launch a hexport HTTP MCP instance. No install needed.
rem Usage: start_mcp.cmd <db.i64|binary> [start_port]
rem   Multiple instances: each auto-bumps to the next free port from start_port
rem   (13337 -> 13338 -> 13339 ...), matching the ida-pro-mcp convention the exporter expects.

if "%~1"=="" (
  echo usage: start_mcp.cmd ^<db.i64^|binary^> [start_port]
  exit /b 1
)
set "DB=%~1"
set "PORT=%~2"
if "%PORT%"=="" set "PORT=13337"

rem hexport.exe needs IDA's runtime (ida.dll/idalib.dll) on PATH. Honor %IDADIR% if set;
rem otherwise, only if idalib.dll isn't already resolvable, fall back to the default install.
if defined IDADIR set "PATH=%IDADIR%;%PATH%"
where idalib.dll >nul 2>&1 || if exist "C:\Program Files\IDA Professional 9.4\idalib.dll" set "PATH=C:\Program Files\IDA Professional 9.4;%PATH%"

"%~dp0build\hexport.exe" --http --port %PORT% --open "%DB%"
