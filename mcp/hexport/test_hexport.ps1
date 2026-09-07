# hexport end-to-end test: drives the stdio MCP server and validates every tool + the
# database lifecycle + edge cases. Usage: powershell -File test_hexport.ps1
param(
  [string]$Exe = "$PSScriptRoot\build\hexport.exe",
  [string]$Idb = "D:\source\repos\test_research\crcrun2\db.i64",
  [string]$Idb2 = "D:\source\repos\test_research\crcrun\db.i64",
  [string]$IdbCopy = "D:\source\repos\test_research\hexrays\hexx64 - Copy.dll.i64"
)
$env:PATH = "C:\Program Files\IDA Professional 9.4;$env:PATH"
$script:pass = 0; $script:fail = 0
function ok($cond, $name) {
  if ($cond) { $script:pass++; "  [PASS] $name" }
  else       { $script:fail++; "  [FAIL] $name" }
}
function jesc($p) { $p.Replace('\','\\') }
# send an array of JSON-RPC lines to a fresh hexport, return a hashtable id -> parsed response
function run($exe, $cliArgs, $reqs, $errFile) {
  $joined = ($reqs -join "`n")
  if ($errFile) { $out = $joined | & $exe @cliArgs 2>$errFile } else { $out = $joined | & $exe @cliArgs 2>$null }
  $R = @{}
  $out -split "`n" | Where-Object { $_.Trim() } | ForEach-Object {
    try { $o = $_ | ConvertFrom-Json; if ($null -ne $o.id) { $R[[int]$o.id] = $o } } catch {}
  }
  return $R
}
function tv($resp) { $resp.result.structuredContent.result }   # tool value

"=== Phase 1: DB open at startup - read tools + edge cases ==="
$errFile = "$env:TEMP\hexport_test_stderr.txt"
$reqs = @(
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
 '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
 '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"server_health","arguments":{}}}'
 '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_funcs","arguments":{"queries":{"offset":0,"count":1}}}}'
 '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"list_funcs","arguments":{"queries":{"offset":0,"count":0}}}}'
 '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"list_funcs","arguments":{"queries":[{"offset":0,"count":2},{"offset":2,"count":2}]}}}'
 '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"entity_query","arguments":{"queries":{"kind":"functions","count":1}}}}'
 '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"disasm","arguments":{"addr":"0x140001000","max_instructions":2,"offset":0}}}'
 '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"disasm","arguments":{"addr":"0x140001000","max_instructions":2,"offset":2}}}'
 '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"decompile","arguments":{"addr":"0x140001000"}}}'
 '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"analyze_batch","arguments":{"queries":[{"addr":"0x140001000","include_disasm":true,"include_decompile":true},{"addr":"wWinMain","include_decompile":true}]}}}'
 '{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"lookup_funcs","arguments":{"queries":"wWinMain"}}}'
 '{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"lookup_funcs","arguments":{"queries":"0x140001000"}}}'
 '{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"force_recompile","arguments":{"items":[{"addr":"0x140001000"}]}}}'
 '{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"force_recompile","arguments":{}}}'
 '{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"nope_tool","arguments":{}}}'
 '{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"disasm","arguments":{"addr":"0xdeadbeef"}}}'
 '{"jsonrpc":"2.0","id":18,"method":"bogus/method","params":{}}'
)
$R = run $Exe @("--stdio", $Idb) $reqs $errFile
ok ($R[1].result.serverInfo.name -eq "hexport") "initialize -> serverInfo.name=hexport"
ok ($R[2].result.tools.Count -eq 11) "tools/list advertises 11 tools ($($R[2].result.tools.Count))"
ok ((($R[2].result.tools.name) -contains "disasm") -and (($R[2].result.tools.name) -contains "decompile") -and (($R[2].result.tools.name) -contains "lookup_funcs")) "tools/list includes required tools"
ok ((tv $R[3]).status -eq "ok" -and (tv $R[3]).functions -gt 0) "server_health ok, functions=$((tv $R[3]).functions)"
ok ((tv $R[4])[0].data.Count -eq 1 -and (tv $R[4])[0].next_offset -eq 1) "list_funcs count=1 -> 1 row, next_offset=1"
ok ((tv $R[5])[0].data.Count -eq (tv $R[3]).functions -and $null -eq (tv $R[5])[0].next_offset) "list_funcs count=0 -> all, next_offset=null"
ok ((tv $R[6]).Count -eq 2) "list_funcs array of 2 queries -> 2 pages"
ok ((tv $R[7])[0].total -eq (tv $R[3]).functions) "entity_query total=$((tv $R[7])[0].total)"
ok ((tv $R[8]).asm.lines.Count -eq 2 -and (tv $R[8]).cursor.done -eq $false -and (tv $R[8]).cursor.next -eq 2) "disasm paging: 2 lines, done=false, next=2"
ok ((tv $R[8]).asm.lines[0].addr -eq "140001000" -and (tv $R[8]).asm.lines[0].label -eq "wWinMain") "disasm first line addr+label correct"
ok ((tv $R[9]).asm.lines.Count -ge 1) "disasm offset=2 continues ($((tv $R[9]).asm.lines.Count) lines)"
ok ((tv $R[10]).code -match "wWinMain" -and (tv $R[10]).code -match "MessageBoxW") "decompile full pseudocode"
ok ((tv $R[11]).Count -eq 2 -and (tv $R[11])[0].name -eq "wWinMain" -and $null -ne (tv $R[11])[0].analysis.decompile) "analyze_batch 2 fns with analysis"
ok ((tv $R[11])[0].analysis.disasm.truncated -eq $false) "analyze_batch disasm truncated=false"
ok ((tv $R[11])[1].name -eq "wWinMain") "analyze_batch resolves 'wWinMain' by name"
ok ((tv $R[12])[0].fn.name -eq "wWinMain") "lookup_funcs by name"
ok ((tv $R[13])[0].fn.name -eq "wWinMain") "lookup_funcs by address"
ok ((tv $R[14]).summary.total -eq 1 -and (tv $R[14]).summary.ok -eq 1 -and (tv $R[14]).summary.all -eq $false) "force_recompile items -> summary"
ok ((tv $R[15]).summary.all -eq $true -and (tv $R[15]).summary.total -gt 0) "force_recompile all -> summary.all=true"
ok ($R[16].result.isError -eq $true) "unknown tool -> isError"
ok ($null -ne $R[17].result.structuredContent.result.error) "disasm bad addr -> error field"
ok ($null -ne $R[18].error -and $R[18].error.code -eq -32601) "unknown method -> JSON-RPC error -32601"

"=== live status on stderr ==="
$se = Get-Content $errFile -Raw
ok ($se -match "\[hexport\]" -and $se -match "decompile" -and $se -match "wWinMain") "stderr shows live per-function status"

"=== Phase 2: DB lifecycle (start closed -> open -> close) ==="
$reqs2 = @(
 '{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"server_health","arguments":{}}}'
 '{"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"list_databases","arguments":{}}}'
 ('{"jsonrpc":"2.0","id":32,"method":"tools/call","params":{"name":"open_database","arguments":{"file_path":"' + (jesc $Idb) + '"}}}')
 '{"jsonrpc":"2.0","id":33,"method":"tools/call","params":{"name":"server_health","arguments":{}}}'
 '{"jsonrpc":"2.0","id":34,"method":"tools/call","params":{"name":"list_databases","arguments":{}}}'
 ('{"jsonrpc":"2.0","id":35,"method":"tools/call","params":{"name":"open_database","arguments":{"file_path":"' + (jesc $Idb2) + '"}}}')
 '{"jsonrpc":"2.0","id":36,"method":"tools/call","params":{"name":"close_database","arguments":{}}}'
 '{"jsonrpc":"2.0","id":37,"method":"tools/call","params":{"name":"server_health","arguments":{}}}'
)
$R2 = run $Exe @("--stdio") $reqs2 $null
ok ((tv $R2[30]).status -eq "no_database" -and (tv $R2[30]).ready -eq $false) "start closed -> server_health no_database"
ok ((tv $R2[31]).Count -eq 0) "list_databases empty when closed"
ok ((tv $R2[32]).status -eq "ok" -and (tv $R2[32]).functions -gt 0) "open_database via tool -> ok, functions=$((tv $R2[32]).functions)"
ok ((tv $R2[33]).ready -eq $true) "server_health ready after open"
ok ((tv $R2[34]).Count -eq 1) "list_databases shows 1 open db"
ok ((tv $R2[35]).status -eq "ok") "re-open a different database (switch) works"
ok ((tv $R2[36]).status -eq "closed") "close_database -> closed"
ok ((tv $R2[37]).ready -eq $false) "server_health not ready after close"

"=== Phase 3: module-name normalization (' - Copy' stripping) ==="
if (Test-Path $IdbCopy) {
  $R3 = run $Exe @("--stdio", $IdbCopy) @('{"jsonrpc":"2.0","id":40,"method":"tools/call","params":{"name":"server_health","arguments":{}}}') $null
  ok ((tv $R3[40]).module -eq "hexx64.dll") "module 'hexx64 - Copy.dll' -> 'hexx64.dll' (got '$((tv $R3[40]).module)')"
} else { "  [SKIP] no ' - Copy' test idb present" }

"=== Phase 4: HTTP transport (M4) ==="
function http_inst($base) {
  $errf = "$env:TEMP\hexport_http_$base.err"
  $p = Start-Process -FilePath $Exe -ArgumentList @("--http","--port","$base","--open",$Idb) -PassThru -RedirectStandardError $errf -RedirectStandardOutput "$errf.out" -WindowStyle Hidden
  $port = $null
  for ($i=0; $i -lt 120; $i++) { Start-Sleep -Milliseconds 100
    if (Test-Path $errf) { $m = Select-String -Path $errf -Pattern 'listening on http://127\.0\.0\.1:(\d+)/mcp' | Select-Object -First 1; if ($m) { $port = [int]$m.Matches[0].Groups[1].Value; break } } }
  [pscustomobject]@{ proc=$p; port=$port }
}
function http_post($port,$obj) {
  $f = "$env:TEMP\hexport_http_req.json"; [IO.File]::WriteAllText($f, ($obj | ConvertTo-Json -Depth 8 -Compress))
  $raw = & curl.exe -s --max-time 20 -X POST -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" --data-binary "@$f" "http://127.0.0.1:$port/mcp"
  if ($raw) { $raw | ConvertFrom-Json } else { $null }
}
$H1 = http_inst 13500   # base away from any live ida-pro-mcp on 13337-13339
$H2 = http_inst 13500   # second instance must auto-bump off H1's port
try {
  ok ($null -ne $H1.port) "http instance A bound a port ($($H1.port))"
  $init = http_post $H1.port @{ jsonrpc="2.0"; id=1; method="initialize"; params=@{ protocolVersion="2024-11-05"; capabilities=@{}; clientInfo=@{ name="t"; version="1" } } }
  ok ($init.result.serverInfo.name -eq "hexport") "http initialize -> serverInfo.name=hexport"
  $hh = (http_post $H1.port @{ jsonrpc="2.0"; id=2; method="tools/call"; params=@{ name="server_health"; arguments=@{} } }).result.structuredContent.result
  ok ($hh.ready -eq $true -and $hh.functions -gt 0) "http server_health ready, functions=$($hh.functions)"
  $dc = (http_post $H1.port @{ jsonrpc="2.0"; id=3; method="tools/call"; params=@{ name="decompile"; arguments=@{ addr="0x140001000" } } }).result.structuredContent.result
  ok ($dc.code -match "MessageBoxW") "http decompile returns full pseudocode"
  $nt = http_post $H1.port @{ jsonrpc="2.0"; method="notifications/initialized" }
  ok ($null -eq $nt) "http notification -> no JSON-RPC response (202)"
  ok ($null -ne $H2.port -and $H2.port -ne $H1.port) "http instance B auto-bumped to a different port ($($H2.port))"
} finally {
  foreach ($x in @($H1,$H2)) { if ($x -and $x.proc -and -not $x.proc.HasExited) { Stop-Process -Id $x.proc.Id -Force -ea 0 } }
}

""
"================ RESULT: $script:pass passed, $script:fail failed ================"
if ($script:fail -gt 0) { exit 1 }
