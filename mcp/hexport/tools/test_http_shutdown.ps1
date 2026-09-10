# Does --http have a clean exit?
#
# It used not to. run_http was `for ( ;; )`, so startup_close() in main() was unreachable and the
# only way to stop an HTTP server was a kill -- which leaves a packed .i64 unpacked and inconsistent
# on disk. That is this project's documented corruption mechanism, so it is worth an assertion.
#
# taskkill WITHOUT /F requests a close instead of terminating, which is what reaches the console
# control handler. A clean shutdown repacks the database and deletes its working files, so the
# residue count is the real check here. Nothing is ever force-killed, and it runs on a COPY.
#
#   pwsh -File tools\test_http_shutdown.ps1
param(
  [string]$Exe = "$PSScriptRoot\..\build\hexport.exe",
  [string]$Work = "$env:TEMP\hexport_http_shutdown_test",
  [string]$Pristine = 'D:\source\repos\test_research\crcrun2\db.i64',
  [int]$Port = 13700
)
$env:PATH = "C:\Program Files\IDA Professional 9.4;$env:PATH"
if (-not (Test-Path $Pristine)) { "SKIP: no fixture at $Pristine"; exit 0 }
Remove-Item $Work -Recurse -Force -ea 0
New-Item -ItemType Directory -Force $Work | Out-Null
Copy-Item $Pristine "$Work\db.i64" -Force
$db = "$Work\db.i64"
$before = (Get-FileHash $db -Algorithm SHA256).Hash

function residue { @(Get-ChildItem -Path "$Work\db.id0","$Work\db.id1","$Work\db.id2","$Work\db.nam","$Work\db.til" -ea 0) }

$errf = "$Work\srv.err"
$p = Start-Process -FilePath $Exe -ArgumentList @("--http","--port","$Port","--open",$db) `
     -PassThru -RedirectStandardError $errf -RedirectStandardOutput "$errf.out" -WindowStyle Hidden
$port = $null
for ($k=0; $k -lt 150; $k++) {
  Start-Sleep -Milliseconds 100
  if (Test-Path $errf) {
    $m = Select-String -Path $errf -Pattern 'listening on http://127\.0\.0\.1:(\d+)/mcp' | Select-Object -First 1
    if ($m) { $port = [int]$m.Matches[0].Groups[1].Value; break }
  }
}
"listening on      : $port"
"residue while open: $((residue).Count) file(s)   <- expected non-zero, the db is unpacked in use"

# Do real work first, so there is something to flush on the way out.
$f = "$Work\req.json"
[IO.File]::WriteAllText($f, '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"decompile","arguments":{"addr":"0x140001000"}}}')
$dc = & curl.exe -s --max-time 20 -X POST -H "Content-Type: application/json" `
       -H "Accept: application/json, text/event-stream" --data-binary "@$f" "http://127.0.0.1:$port/mcp"
"decompile works   : $([bool]($dc -match 'MessageBoxW'))"

# Ask it to close. Do not terminate it.
& taskkill.exe /PID $p.Id | Out-String | ForEach-Object { "taskkill          : $($_.Trim())" }
$exited = $p.WaitForExit(60000)
"exited            : $exited (code $(if($exited){$p.ExitCode}else{'still running'}))"

Start-Sleep -Milliseconds 500
$after = if (Test-Path $db) { (Get-FileHash $db -Algorithm SHA256).Hash } else { 'MISSING' }
$r = residue
"residue after     : $($r.Count) file(s) $(($r.Name) -join ', ')"
"db hash           : $(if($after -eq $before){'unchanged'}else{"CHANGED ($($after.Substring(0,16)))"})"
""
"--- server stderr ---"
Get-Content $errf -ea 0
""
# Exit code 0xC000013A (STATUS_CONTROL_C_EXIT) here means the process was killed by the control
# event before it finished closing. That was the first attempt at this fix, and it still left the
# four unpacked files behind, which is why the exit code is asserted and not just the residue.
if (-not $exited) {
  "RESULT: FAIL - no clean exit; process left running rather than force-killed"; exit 1
} elseif ($p.ExitCode -ne 0) {
  "RESULT: FAIL - exit code $($p.ExitCode); the close did not finish"; exit 1
} elseif ($r.Count -ne 0) {
  "RESULT: FAIL - exited but left $($r.Count) unpacked file(s)"; exit 1
} elseif ($after -ne $before) {
  "RESULT: FAIL - the database was rewritten; a read-only session must not change it"; exit 1
} else {
  "RESULT: PASS - clean exit, database repacked, no residue, bytes unchanged"; exit 0
}
