$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$goExecutable = (Get-Command go -ErrorAction SilentlyContinue).Source
if (-not $goExecutable) {
  $localPrograms = Join-Path ([Environment]::GetFolderPath("LocalApplicationData")) "Programs"
  $userGo = Join-Path $localPrograms "Go\bin\go.exe"
  $projectGo = Join-Path $projectRoot ".tools\go\bin\go.exe"
  if (Test-Path -LiteralPath $userGo) { $goExecutable = $userGo }
  elseif (Test-Path -LiteralPath $projectGo) { $goExecutable = $projectGo }
  else { throw "Go was not found. Install Go 1.26 or newer from https://go.dev/dl/." }
}
$env:GOCACHE = Join-Path $projectRoot ".cache\go-build"
$env:GOPATH = Join-Path $projectRoot ".cache\gopath"
Set-Location (Join-Path $projectRoot "backend-go")
& $goExecutable run .
