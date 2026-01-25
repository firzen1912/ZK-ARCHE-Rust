# ----------------------------
# CONFIG
# ----------------------------
$serverExe = ".\target\release\server.exe"          # adjust if your server binary name differs
$clientExe = ".\target\release\client_test1.exe"

$serverAddr = "127.0.0.1:4000"
$clients     = 50
$clientsRoot = "clients"
$logsDir     = "logs\test1"

New-Item -ItemType Directory -Force $logsDir | Out-Null

# Client logs (combined, tagged)
$outLog = "$logsDir\test1.out.log"
$errLog = "$logsDir\test1.err.log"

# Server logs
$serverOut = "$logsDir\server.out.log"
$serverErr = "$logsDir\server.err.log"

Remove-Item $outLog,$errLog,$serverOut,$serverErr -ErrorAction SilentlyContinue

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

# Give server a moment to bind (simple + effective)
Start-Sleep -Milliseconds 500

try {
  # ----------------------------
  # TEST 1 (clients)
  # ----------------------------
  1..$clients | ForEach-Object {
    $i   = $_.ToString("00")
    $cid = "c$i"
    $dir = "$clientsRoot\$cid"

    Write-Host "TEST1: $cid"

    & $clientExe --server $serverAddr --state-dir $dir 2>&1 |
      ForEach-Object { "[${cid}] $_" } |
      Tee-Object -FilePath $outLog -Append |
      Out-File -FilePath $errLog -Append
  }

  Write-Host "TEST1 complete."
  Write-Host "Client logs: $outLog (and $errLog)"
  Write-Host "Server logs: $serverOut (and $serverErr)"
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
