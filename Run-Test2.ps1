# ----------------------------
# CONFIG
# ----------------------------
$serverExe = (Resolve-Path ".\target\release\server.exe").Path   # adjust if name differs
$exe       = (Resolve-Path ".\target\release\client_test2.exe").Path

$serverAddr   = "127.0.0.1:4000"
$clientIndex  = 1
$clientsRoot  = "clients"
$logsDir      = "logs\test2"

New-Item -ItemType Directory -Force $logsDir | Out-Null

# Client logs
$out = "$logsDir\test2.out.log"
$err = "$logsDir\test2.err.log"

# Server logs
$serverOut = "$logsDir\server.out.log"
$serverErr = "$logsDir\server.err.log"

Remove-Item $out,$err,$serverOut,$serverErr -ErrorAction SilentlyContinue

$i   = $clientIndex.ToString("00")
$cid = "c$i"
$dir = "$clientsRoot\$cid"

# ----------------------------
# START SERVER (background)
# ----------------------------
Write-Host "Starting server with logs..."
$serverProc = Start-Process -FilePath $serverExe `
  -ArgumentList @("--bind",$serverAddr) `
  -NoNewWindow `
  -RedirectStandardOutput $serverOut `
  -RedirectStandardError  $serverErr `
  -PassThru

Start-Sleep -Milliseconds 500

try {
  # ----------------------------
  # TEST 2 (client)
  # ----------------------------
  Write-Host "TEST2: client $cid running 50 iterations"

  powershell -NoProfile -Command `
    "& '$exe' --server $serverAddr --state-dir '$dir' 2>&1 | ForEach-Object { '[${cid}] ' + `$_ }" `
    1> $out `
    2> $err

  Write-Host "TEST2 complete."
  Write-Host "client stdout: $out"
  Write-Host "client stderr: $err"
  Write-Host "server stdout: $serverOut"
  Write-Host "server stderr: $serverErr"
}
finally {
  # ----------------------------
  # STOP SERVER
  # ----------------------------
  if ($serverProc -and -not $serverProc.HasExited) {
    Write-Host "Stopping server..."
    Stop-Process -Id $serverProc.Id -Force
  }
}
