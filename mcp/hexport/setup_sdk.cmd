@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

REM Ensure the IDA SDK is present under src\dep and correctly patched, so the build is
REM self-contained. Idempotent: if the SDK is already there, we skip the pull and only
REM re-check the fixup. No absolute paths are hardcoded.

set "SDK=src\dep\ida-sdk"
set "SDK_URL=https://github.com/HexRaysSA/ida-sdk"

if exist "%SDK%\src\include\idalib.hpp" (
  echo [hexport] IDA SDK already present at %SDK% - skipping pull.
) else (
  echo [hexport] Pulling IDA SDK into %SDK% ...
  if not exist "src\dep" mkdir "src\dep"
  git clone --depth 1 --single-branch "%SDK_URL%" "%SDK%"
  if errorlevel 1 (
    echo [hexport] ERROR: git clone of %SDK_URL% failed.
    exit /b 1
  )
)

REM --- Required fixup ---------------------------------------------------------
REM The SDK ships some import libs only in the static-CRT (_s) lib dirs. The build
REM links the dynamic-CRT dirs, so copy the missing files across first or the link
REM fails with unresolved externals.
set "LIB=%SDK%\src\lib"

REM x64 fix: x64_win_64_s -> x64_win_64
call :copyone "%LIB%\x64_win_64_s" "%LIB%\x64_win_64" pro.lib

REM x86 fix: x86_win_32_s -> x64_win_32
for %%F in (compress.lib dumb.obj int128.lib pro.lib unicode.lib) do (
  call :copyone "%LIB%\x86_win_32_s" "%LIB%\x64_win_32" %%F
)

echo [hexport] SDK ready.
exit /b 0

:copyone
REM %1=src dir  %2=dst dir  %3=file  (copies only if missing at dst and present at src)
if not exist "%~2\%~3" (
  if exist "%~1\%~3" (
    copy /y "%~1\%~3" "%~2\%~3" >nul
    echo   fixup: %~2\%~3
  )
)
exit /b 0
