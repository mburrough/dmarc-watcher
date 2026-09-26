<#
.SYNOPSIS
    Removes DMARC Watcher's traces from this machine.

.DESCRIPTION
    Stops any running instance, removes the Startup shortcut, and deletes the
    stored Bridge password from Windows Credential Manager.

    Your report database is KEPT by default. Reporters never re-send an
    aggregate report, so a deleted database is history you cannot rebuild --
    deleting it has to be asked for explicitly with -RemoveData.

    This script does not delete the project folder itself. Remove that by hand
    once you are happy with the result.

.PARAMETER RemoveData
    Also delete %APPDATA%\dmarc-watcher (report database, log, details file).

.PARAMETER Force
    Skip the confirmation prompt for -RemoveData. Intended for scripted use.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File uninstall.ps1
    Removes the shortcut and password, keeps every report.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File uninstall.ps1 -RemoveData
    Also deletes the report database, after confirming.
#>

[CmdletBinding()]
param(
    [switch]$RemoveData,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$dataDir    = Join-Path $env:APPDATA "dmarc-watcher"
$startup    = [Environment]::GetFolderPath("Startup")
$shortcut   = Join-Path $startup "DMARC Watcher.lnk"

Write-Host "DMARC Watcher uninstaller" -ForegroundColor Cyan
Write-Host "-------------------------"

# --- 1. Stop any running instance ------------------------------------------
$procs = @(Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" |
           Where-Object { $_.CommandLine -and $_.CommandLine -match 'dmarc_watcher' })
if ($procs.Count -gt 0) {
    foreach ($p in $procs) {
        try {
            Stop-Process -Id $p.ProcessId -Force -Confirm:$false
            Write-Host "  stopped running instance (PID $($p.ProcessId))"
        } catch {
            Write-Warning "  could not stop PID $($p.ProcessId): $($_.Exception.Message)"
        }
    }
} else {
    Write-Host "  no running instance"
}

# --- 2. Startup shortcut ----------------------------------------------------
if (Test-Path $shortcut) {
    Remove-Item $shortcut -Force -Confirm:$false
    Write-Host "  removed Startup shortcut"
} else {
    Write-Host "  no Startup shortcut"
}

# --- 3. Stored Bridge password ---------------------------------------------
# The keyring entry is keyed by the address in config.toml, so read it from
# there rather than guessing.
$cfg = Join-Path $projectDir "config.toml"
$py  = (Get-Command py -ErrorAction SilentlyContinue)
if (-not $py) { $py = Get-Command python -ErrorAction SilentlyContinue }

if ($py -and (Test-Path $cfg)) {
    $snippet = @'
import codecs, sys, tomllib, pathlib
try:
    import keyring
except ImportError:
    print("  keyring not installed; skipping stored password"); sys.exit(0)
cfg = pathlib.Path(sys.argv[1])
user = ""
try:
    data = cfg.read_bytes()
    if data.startswith(codecs.BOM_UTF8):
        data = data[len(codecs.BOM_UTF8):]
    user = tomllib.loads(data.decode("utf-8")).get("imap", {}).get("user", "")
except Exception as exc:
    print(f"  could not read config.toml ({exc}); skipping stored password"); sys.exit(0)
if not user:
    print("  no imap.user in config.toml; skipping stored password"); sys.exit(0)
removed = False
for service in ("dmarc-watcher",):
    try:
        if keyring.get_password(service, user):
            keyring.delete_password(service, user)
            print(f"  removed stored password ({service} / {user})")
            removed = True
    except Exception:
        pass
if not removed:
    print("  no stored password found")
'@
    $tmp = Join-Path $env:TEMP "dmarc-watcher-uninstall-keyring.py"
    Set-Content -Path $tmp -Value $snippet -Encoding utf8
    try { & $py.Source -3 $tmp $cfg } catch { Write-Warning "  keyring cleanup failed: $($_.Exception.Message)" }
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
} else {
    Write-Host "  skipping stored password (no Python, or no config.toml)"
}

# --- 4. Report database -----------------------------------------------------
if (Test-Path $dataDir) {
    $db = Join-Path $dataDir "reports.db"
    $count = "unknown"
    if ($py -and (Test-Path $db)) {
        try {
            $count = & $py.Source -3 -c "import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute('SELECT COUNT(*) FROM reports').fetchone()[0])" $db
        } catch { $count = "unknown" }
    }

    if ($RemoveData) {
        $go = $Force
        if (-not $go) {
            Write-Host ""
            Write-Warning "About to delete $dataDir (holding $count report(s))."
            Write-Warning "Reporters never re-send reports. This history cannot be rebuilt."
            $answer = Read-Host "Type DELETE to confirm"
            $go = ($answer -ceq "DELETE")
        }
        if ($go) {
            Remove-Item $dataDir -Recurse -Force -Confirm:$false
            Write-Host "  deleted $dataDir"
        } else {
            Write-Host "  kept $dataDir (not confirmed)"
        }
    } else {
        Write-Host "  kept report data: $dataDir ($count report(s))"
        Write-Host "    re-run with -RemoveData to delete it"
    }
} else {
    Write-Host "  no data directory"
}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "The project folder was left in place: $projectDir"
Write-Host "Delete it yourself when you are ready (it also holds your config.toml)."
