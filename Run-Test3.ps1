# Run-Test3.ps1

# ---- CLIENT EXE ----
$exeRel = ".\target\release\client_test3.exe"
$exe    = (Resolve-Path $exeRel).Path   # absolute path fixes Start-Job context issues

# ---- SERVER EXE (adjust name if needed) ----
$serverExeRel = ".\target\release\server.exe"
$serverExe    = (Resolve-Path $serverExeRel).Path

$serverAddr  = "127.0.0.1:4000"

$clients     = 50
$clientsRoot = "clients"
$logsDir     = "logs\test3"

New-Item -ItemType Directory -Force $logsDir | Out-Null

# Client merged logs
$outLog = Join-Path $logsDir "test3.out.log"
$errLog = Join-Path $logsDir "test3.err.log"

# Server logs
$serverOut = Join-Path $logsDir "server.out.log"
$serverErr = Join-Path $logsDir "server.err.log"

Remove-Item $outLog,$errLog,$serverOut,$serverErr -ErrorAction SilentlyContinue

$tmpDir = Join-Path $logsDir "tmp"
New-Item -ItemType Directory -Force $tmpDir | Out-Null
Remove-Item (Join-Path $tmpDir "*.log") -ErrorAction SilentlyContinue

# Capture the caller's working directory and reuse it inside jobs
$cwd = (Get-Location).Path

# ---- START SERVER ----
Write-Host "Starting server with logs..."
$serverProc = Start-Process -FilePath $serverExe `
  -ArgumentList @("--bind",$serverAddr) `
  -NoNewWindow `
  -RedirectStandardOutput $serverOut `
  -RedirectStandardError  $serverErr `
  -PassThru

Start-Sleep -Milliseconds 500

try {
  $jobs = @()

  1..$clients | ForEach-Object {
    $i   = $_.ToString("00")
    $cid = "c$i"
    $dir = Join-Path $cwd (Join-Path $clientsRoot $cid)  # make state-dir absolute too
    $tmp = Join-Path $tmpDir "$cid.log"

    Write-Host "TEST3: starting $cid"

    $jobs += Start-Job -ScriptBlock {
      param($exe,$dir,$cid,$tmp,$cwd,$serverAddr)

      Set-Location $cwd

      try {
        & $exe --server $serverAddr --state-dir $dir 2>&1 |
          ForEach-Object { "[${cid}] $_" } |
          Out-File -FilePath $tmp -Append -Encoding utf8
      }
      catch {
        "[${cid}] JOB ERROR: $($_.Exception.Message)" |
          Out-File -FilePath $tmp -Append -Encoding utf8
      }

    } -ArgumentList $exe,$dir,$cid,$tmp,$cwd,$serverAddr
  }

  # Wait for completion
  $jobs | Wait-Job | Out-Null

  # Drain job output streams (usually empty because we write to tmp files)
  $jobs | Receive-Job -Keep | Out-Null
  $jobs | Remove-Job

  # Merge deterministically (like Test 1)
  1..$clients | ForEach-Object {
    $i   = $_.ToString("00")
    $cid = "c$i"
    $tmp = Join-Path $tmpDir "$cid.log"

    if (Test-Path $tmp) {
      Get-Content $tmp | Tee-Object -FilePath $outLog -Append
    } else {
      "[${cid}] (no output - tmp log missing)" | Tee-Object -FilePath $outLog -Append
    }
  }

  Copy-Item $outLog $errLog -Force

  Write-Host "TEST3 complete."
  Write-Host "Client logs: $outLog"
  Write-Host "Server logs: $serverOut (and $serverErr)"
}
finally {
  # ---- STOP SERVER ----
  if ($serverProc -and -not $serverProc.HasExited) {
    Write-Host "Stopping server..."
    Stop-Process -Id $serverProc.Id -Force
  }
}
