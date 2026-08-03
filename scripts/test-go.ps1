$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$goExecutable = (Get-Command go -ErrorAction SilentlyContinue).Source
if (-not $goExecutable) {
  $localPrograms = Join-Path ([Environment]::GetFolderPath("LocalApplicationData")) "Programs"
  $goExecutable = Join-Path $localPrograms "Go\bin\go.exe"
}
if (-not (Test-Path -LiteralPath $goExecutable)) { throw "Go was not found." }
$env:GOCACHE = Join-Path $projectRoot ".cache\go-build"
$env:GOPATH = Join-Path $projectRoot ".cache\gopath"
Set-Location (Join-Path $projectRoot "backend-go")
& $goExecutable test ./...
