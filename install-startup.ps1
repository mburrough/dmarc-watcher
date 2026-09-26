# Creates a Startup shortcut so the monitor launches at sign-in.
# Uses pythonw.exe so no console window appears.
# Remove it by deleting the shortcut from shell:startup.

$ErrorActionPreference = "Stop"

$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonw = Join-Path (Split-Path -Parent (Get-Command py).Source) "pythonw.exe"

if (-not (Test-Path $pythonw)) {
    $pythonw = (Get-Command pythonw -ErrorAction SilentlyContinue).Source
}
if (-not $pythonw -or -not (Test-Path $pythonw)) {
    throw "Could not locate pythonw.exe. Pass its path manually."
}

$startup = [Environment]::GetFolderPath("Startup")
$linkPath = Join-Path $startup "DMARC Watcher.lnk"

$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut($linkPath)
$link.TargetPath = $pythonw
$link.Arguments = "-m dmarc_watcher"
$link.WorkingDirectory = $projectDir
$link.Description = "DMARC aggregate report monitor"
$link.Save()

Write-Host "Created: $linkPath"
Write-Host "  target: $pythonw -m dmarc_watcher"
Write-Host "  workdir: $projectDir"
