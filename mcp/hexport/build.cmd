@echo off
setlocal
cd /d "%~dp0"

REM Ensure the IDA SDK is fetched into src\dep and patched (idempotent) before building.
call "%~dp0setup_sdk.cmd"
if errorlevel 1 exit /b 1

REM hexport build via MSBuild (no CMake). Locates MSBuild with vswhere.
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo vswhere not found - is Visual Studio installed?
  exit /b 1
)
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do set "MSBUILD=%%i"
if not defined MSBUILD (
  echo MSBuild.exe not found.
  exit /b 1
)

"%MSBUILD%" hexport.vcxproj /p:Configuration=Release /p:Platform=x64 /m /nologo
if errorlevel 1 exit /b 1

echo.
echo Built: build\hexport.exe
echo Run it where IDA's DLLs are reachable, e.g.:
echo   set PATH=C:\Program Files\IDA Professional 9.4;%%PATH%%
