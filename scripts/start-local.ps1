$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$cacheDirectory = Join-Path $projectRoot ".cache"
$logDirectory = Join-Path $cacheDirectory "logs"
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null

function Test-Service([string]$Uri) {
  try {
    $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 2
    return $response.StatusCode -eq 200
  } catch {
    return $false
  }
}

function Wait-Service([string]$Name, [string]$Uri, [int]$Seconds = 40) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $deadline) {
    if (Test-Service $Uri) { return }
    Start-Sleep -Milliseconds 500
  }
  throw "$Name did not become ready. See $logDirectory for details."
}

$npm = (Get-Command npm.cmd -ErrorAction SilentlyContinue).Source
if (-not $npm) { throw "Node.js/npm was not found. Install Node.js 22.13 or newer." }

if (-not (Test-Path -LiteralPath (Join-Path $projectRoot "node_modules\vinext"))) {
  Write-Host "[LogSleuth] Installing frontend dependencies..." -ForegroundColor Cyan
  Push-Location $projectRoot
  try { & $npm install; if ($LASTEXITCODE -ne 0) { throw "npm install failed." } }
  finally { Pop-Location }
}

$goUri = "http://127.0.0.1:8787/api/v1/health"
if (-not (Test-Service $goUri)) {
  Write-Host "[LogSleuth] Starting Go investigation engine..." -ForegroundColor Cyan
  $goOut = Join-Path $logDirectory "go-engine.out.log"
  $goError = Join-Path $logDirectory "go-engine.error.log"
  Start-Process powershell.exe -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$(Join-Path $PSScriptRoot 'dev-go.ps1')`"") -WorkingDirectory $projectRoot -WindowStyle Hidden -RedirectStandardOutput $goOut -RedirectStandardError $goError | Out-Null
  Wait-Service "Go engine" $goUri
}

$frontendUri = "http://localhost:3000/"
if (-not (Test-Service $frontendUri)) {
  Write-Host "[LogSleuth] Starting investigation console..." -ForegroundColor Cyan
  $frontOut = Join-Path $logDirectory "frontend.out.log"
  $frontError = Join-Path $logDirectory "frontend.error.log"
  Start-Process $npm -ArgumentList @("run", "dev") -WorkingDirectory $projectRoot -WindowStyle Hidden -RedirectStandardOutput $frontOut -RedirectStandardError $frontError | Out-Null
  Wait-Service "Frontend" $frontendUri
}

Write-Host "[LogSleuth] Go engine and frontend are ready." -ForegroundColor Green
Start-Process $frontendUri
